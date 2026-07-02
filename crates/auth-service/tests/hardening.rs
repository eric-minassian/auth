//! Server-hardening batch: revoke secret validation, POST /oauth/authorize,
//! expired-id_token_hint logout, login rate limiting, and the account
//! deletion tombstone.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use auth_service::crypto::{random_b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use auth_service::domain::user::AccountStatus;
use auth_service::jwt::Signer;
use auth_service::jwt::claims::IdTokenClaims;
use axum::http::StatusCode;
use harness::TestApp;
use harness::flows::{new_authenticator, signup_with_passkey};
use url::Url;
use uuid::Uuid;

const RP_CALLBACK: &str = "http://rp.example.com/callback";

fn rp_client() -> OidcClient {
    OidcClient {
        client_id: "rp".to_string(),
        client_name: "Test RP".to_string(),
        redirect_uris: vec![RP_CALLBACK.to_string()],
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        allowed_origins: vec![],
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "offline_access".to_string(),
        ],
        require_dpop: false,
    }
}

async fn code_flow_tokens(app: &TestApp, scope: &str) -> serde_json::Value {
    let verifier = random_b64u(32);
    let challenge = sha256_b64u(&verifier);
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", scope)
        .add_query_param("code_challenge", &challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    let url = Url::parse(res.header("location").to_str().expect("loc")).expect("url");
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("code");
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", RP_CALLBACK),
            ("client_id", "rp"),
            ("code_verifier", verifier.as_str()),
        ])
        .await;
    res.assert_status(StatusCode::OK);
    res.json()
}

async fn refresh_status(app: &TestApp, token: &str) -> StatusCode {
    app.server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", "rp"),
        ])
        .await
        .status_code()
}

#[tokio::test]
async fn revoke_requires_the_current_secret() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authn = new_authenticator();
    signup_with_passkey(&mut app, "revoke-secret", &mut authn).await;

    let tokens = code_flow_tokens(&app, "openid offline_access").await;
    let rt0 = tokens["refresh_token"].as_str().expect("rt0").to_string();

    // Rotate: rt0 is now stale, rt1 is live.
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt0.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::OK);
    let rt1 = res.json::<serde_json::Value>()["refresh_token"]
        .as_str()
        .expect("rt1")
        .to_string();

    // Revoking with the STALE token must be a no-op (200, no oracle): a
    // family id from an old token or a log line must not kill a live grant.
    app.server
        .post("/oauth/revoke")
        .form(&[("token", rt0.as_str())])
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(
        refresh_status(&app, &rt1).await,
        StatusCode::OK,
        "stale-secret revocation must not kill the live family"
    );
    let rt2 = {
        // the refresh above rotated again
        let sessions = app.server.get("/api/session").await;
        sessions.assert_status(StatusCode::OK);
        // re-run a flow to get the current token: simplest is another code flow
        let tokens = code_flow_tokens(&app, "openid offline_access").await;
        tokens["refresh_token"].as_str().expect("rt2").to_string()
    };

    // Revoking with the CURRENT token kills its family.
    app.server
        .post("/oauth/revoke")
        .form(&[("token", rt2.as_str())])
        .await
        .assert_status(StatusCode::OK);
    assert_eq!(refresh_status(&app, &rt2).await, StatusCode::BAD_REQUEST);

    // Garbage is still 200 (no oracle).
    app.server
        .post("/oauth/revoke")
        .form(&[("token", "rt_bogus.bogus")])
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn post_authorize_behaves_like_get() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;

    let verifier = random_b64u(32);
    let challenge = sha256_b64u(&verifier);
    let params = [
        ("response_type", "code"),
        ("client_id", "rp"),
        ("redirect_uri", RP_CALLBACK),
        ("scope", "openid"),
        ("state", "xyz"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];

    // Signed out: POST must bounce to sign-in with the request re-serialized
    // into return_to, so the round-trip resumes the same authorization.
    let res = app.server.post("/oauth/authorize").form(&params).await;
    res.assert_status(StatusCode::SEE_OTHER);
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(location.contains("/sign-in?return_to="), "{location}");
    let return_to = urlencoding_decode(
        location
            .split("return_to=")
            .nth(1)
            .expect("return_to param"),
    );
    assert!(return_to.starts_with("/oauth/authorize?"), "{return_to}");
    assert!(return_to.contains("client_id=rp"), "{return_to}");
    assert!(return_to.contains("state=xyz"), "{return_to}");

    // Signed in: POST issues a code exactly like GET.
    let mut authn = new_authenticator();
    signup_with_passkey(&mut app, "post-authz", &mut authn).await;
    let res = app.server.post("/oauth/authorize").form(&params).await;
    res.assert_status(StatusCode::SEE_OTHER);
    let url = Url::parse(res.header("location").to_str().expect("loc")).expect("url");
    assert!(url.as_str().starts_with(RP_CALLBACK));
    assert!(url.query_pairs().any(|(k, _)| k == "code"));
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "iss" && v == harness::ISSUER)
    );
}

fn urlencoding_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={s}").as_bytes())
        .find(|(k, _)| k == "x")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

#[tokio::test]
async fn expired_id_token_hint_still_identifies_the_session_but_access_tokens_do_not() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authn = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "hint", &mut authn).await;

    // An id_token that expired an hour ago, signed by the real signer.
    let ts = auth_service::store::now();
    let claims = IdTokenClaims {
        iss: harness::ISSUER.to_string(),
        sub: user_id.clone(),
        aud: "rp".to_string(),
        iat: ts - 7200,
        exp: ts - 3600,
        auth_time: ts - 7200,
        sid: "whatever".to_string(),
        amr: vec!["webauthn".to_string()],
        acr: "phr".to_string(),
        nonce: None,
        nickname: None,
        updated_at: None,
    };
    let signer = Signer::Local(app.signer.clone());
    let expired_hint = signer.sign("JWT", &claims).await.expect("sign hint");

    // The expired hint still authorizes RP-initiated logout for the matching
    // browser session (OIDC RP-Initiated Logout: expired hints acceptable).
    let res = app
        .server
        .get("/oauth/logout")
        .add_query_param("id_token_hint", &expired_hint)
        .await;
    res.assert_status(StatusCode::SEE_OTHER);
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A (live) ACCESS token must never work as an id_token_hint: wrong typ.
    app.login_as(Uuid::parse_str(&user_id).expect("uuid")).await;
    let tokens = code_flow_tokens(&app, "openid").await;
    let access_token = tokens["access_token"].as_str().expect("at").to_string();
    let res = app
        .server
        .get("/oauth/logout")
        .add_query_param("id_token_hint", &access_token)
        .await;
    // Falls to the confirmation page, nothing revoked.
    let location = res.header("location").to_str().expect("loc").to_string();
    assert_eq!(location, format!("{}/logout", harness::ISSUER));
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn login_endpoints_share_a_real_rate_limit() {
    let app = TestApp::spawn().await;

    // Exhaust the login budget from one IP; the limiter must actually block
    // (it previously counted failures but never consulted the budget).
    let mut limited = false;
    for _ in 0..130 {
        let res = app
            .post("/api/webauthn/login/start", &serde_json::json!({}))
            .await;
        if res.status_code() == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
        res.assert_status(StatusCode::OK);
    }
    assert!(limited, "login_start never rate-limited after 130 calls");

    // finish shares the same budget → immediately limited too.
    let res = app
        .server
        .post("/api/webauthn/login/finish")
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .json(&serde_json::json!({ "ceremony_id": "bogus", "credential": {
            "id": "AA", "rawId": "AA", "type": "public-key",
            "response": { "authenticatorData": "AA", "clientDataJSON": "AA", "signature": "AA" },
            "extensions": {}
        }}))
        .await;
    res.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn tombstoned_account_cannot_authorize() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authn = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "tombstone", &mut authn).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");

    // Tombstone as delete_account now does first. Even with a live session
    // cookie, authorize must refuse to issue a code (fails safe if the
    // deletion cascade was interrupted right after this point).
    app.store
        .set_user_status(user_id, AccountStatus::Deleting)
        .await
        .expect("tombstone");

    let verifier = random_b64u(32);
    let challenge = sha256_b64u(&verifier);
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(
        location.contains("/sign-in?return_to="),
        "tombstoned account must not be issued a code: {location}"
    );
}
