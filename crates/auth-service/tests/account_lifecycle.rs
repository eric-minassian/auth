//! Post-recovery credential review, nickname editing, sign-out-everywhere,
//! and the unknown-credential login signal.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use auth_service::crypto::{random_b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use auth_service::domain::session::SessionLevel;
use axum::http::StatusCode;
use harness::TestApp;
use harness::flows::{new_authenticator, origin, signup_with_passkey};
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

const RP_CALLBACK: &str = "http://rp.example.com/callback";

fn rp_client() -> OidcClient {
    OidcClient {
        client_id: "rp".to_string(),
        client_name: "Test RP".to_string(),
        redirect_uris: vec![RP_CALLBACK.to_string()],
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        allowed_origins: vec![],
        scopes: vec!["openid".to_string(), "profile".to_string()],
        require_dpop: false,
    }
}

fn authorize_req(app: &TestApp, extra: &[(&str, &str)]) -> axum_test::TestRequest {
    let mut req = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", sha256_b64u(random_b64u(32)))
        .add_query_param("code_challenge_method", "S256");
    for (k, v) in extra {
        req = req.add_query_param(k, v);
    }
    req
}

#[tokio::test]
async fn recovery_leaves_a_credential_review_that_blocks_authorize() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "review", &mut authenticator).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");

    // Mint recovery codes on the fresh (stepped-up) login session.
    let res = app.post("/api/account/recovery-codes", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let code = res.json::<serde_json::Value>()["codes"][0]
        .as_str()
        .expect("code")
        .to_string();

    // Redeem: the original passkey survives, so review becomes pending.
    app.post("/api/recovery/redeem", &json!({ "code": code }))
        .await
        .assert_status(StatusCode::OK);
    let user = app
        .store
        .get_user(user_id)
        .await
        .expect("get")
        .expect("user");
    assert!(user.pending_credential_review);

    // Register the replacement passkey on the enroll session, then log in.
    let mut replacement = new_authenticator();
    let res = app.post("/api/webauthn/register/start", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"].as_str().expect("id").to_string();
    let options: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("options");
    let credential = replacement
        .do_registration(origin(), options)
        .expect("registration");
    app.post(
        "/api/webauthn/register/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "Replacement" }),
    )
    .await
    .assert_status(StatusCode::OK);
    app.login_as(user_id).await;

    // The pending review blocks authorization…
    let res = authorize_req(&app, &[]).await;
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(
        location.contains("/review-passkeys?return_to="),
        "authorize must route to the review screen: {location}"
    );
    // …and prompt=none reports interaction_required to the RP.
    let res = authorize_req(&app, &[("prompt", "none"), ("state", "s")]).await;
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(location.starts_with(RP_CALLBACK));
    assert!(
        location.contains("error=interaction_required"),
        "{location}"
    );

    // /api/session surfaces the flag for the SPA.
    let res = app.server.get("/api/session").await;
    res.assert_status(StatusCode::OK);
    assert_eq!(
        res.json::<serde_json::Value>()["user"]["pending_credential_review"],
        true
    );

    // Completing the review unblocks authorization.
    app.post("/api/account/credential-review/complete", &json!({}))
        .await
        .assert_status(StatusCode::OK);
    let res = authorize_req(&app, &[]).await;
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(location.starts_with(RP_CALLBACK), "{location}");
    assert!(location.contains("code="), "{location}");
}

#[tokio::test]
async fn nickname_can_be_edited_and_bumps_updated_at() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "old-name", &mut authenticator).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");
    let before = app
        .store
        .get_user(user_id)
        .await
        .expect("get")
        .expect("user");

    let res = app
        .server
        .patch("/api/account")
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .json(&json!({ "nickname": "  New Name  " }))
        .await;
    res.assert_status(StatusCode::OK);

    let after = app
        .store
        .get_user(user_id)
        .await
        .expect("get")
        .expect("user");
    assert_eq!(after.nickname, "New Name");
    assert!(after.updated_at >= before.updated_at);
    let res = app.server.get("/api/session").await;
    assert_eq!(
        res.json::<serde_json::Value>()["user"]["nickname"],
        "New Name"
    );

    // Blank nicknames are rejected.
    app.server
        .patch("/api/account")
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .json(&json!({ "nickname": "   " }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoke_others_kills_everything_but_the_current_session() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "everywhere", &mut authenticator).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");

    // Two "other device" sessions, one with a refresh family.
    let (_, other_a) = app
        .store
        .create_session(
            user_id,
            SessionLevel::Full,
            vec!["webauthn".into()],
            None,
            None,
            None,
        )
        .await
        .expect("session a");
    let (_, other_b) = app
        .store
        .create_session(
            user_id,
            SessionLevel::Full,
            vec!["webauthn".into()],
            None,
            None,
            None,
        )
        .await
        .expect("session b");
    let rt = app
        .store
        .create_refresh_family(
            &random_b64u(16),
            user_id,
            "rp",
            &other_a.sid_hash,
            "openid",
            None,
        )
        .await
        .expect("family");

    let res = app
        .post("/api/account/sessions/revoke-others", &json!({}))
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    // The enroll session from signup may or may not still be live; at least
    // the two full sessions above must be gone.
    assert!(body["revoked"].as_u64().expect("revoked") >= 2);

    assert!(
        app.store
            .get_session_by_hash(&other_a.sid_hash)
            .await
            .expect("lookup")
            .is_none()
    );
    assert!(
        app.store
            .get_session_by_hash(&other_b.sid_hash)
            .await
            .expect("lookup")
            .is_none()
    );
    // The family died with its session.
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
    // The caller's session survives.
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn unknown_credential_login_is_distinguishable_for_the_signal_api() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    signup_with_passkey(&mut app, "ghost", &mut authenticator).await;

    let res = app.post("/api/webauthn/login/start", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let ceremony_id = res.json::<serde_json::Value>()["ceremony_id"]
        .as_str()
        .expect("id")
        .to_string();

    // An assertion for a credential id this server has never seen (e.g. the
    // passkey was deleted on another device). The lookup precedes signature
    // verification, so a syntactically valid envelope suffices.
    let res = app
        .post(
            "/api/webauthn/login/finish",
            &json!({
                "ceremony_id": ceremony_id,
                "credential": {
                    "id": random_b64u(16),
                    "rawId": random_b64u(16),
                    "type": "public-key",
                    "response": {
                        "authenticatorData": random_b64u(37),
                        "clientDataJSON": random_b64u(64),
                        "signature": random_b64u(64),
                        "userHandle": null
                    },
                    "extensions": {}
                }
            }),
        )
        .await;
    res.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.json::<serde_json::Value>()["error"],
        "unknown_credential"
    );
}
