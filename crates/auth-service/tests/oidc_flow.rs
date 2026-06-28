//! Full OIDC authorization-code + PKCE flow, acting as a relying party.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use auth_service::crypto::{random_b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use axum::http::StatusCode;
use harness::TestApp;
use harness::flows;
use url::Url;

const RP_ORIGIN: &str = "http://rp.example.com";
const RP_CALLBACK: &str = "http://rp.example.com/callback";

fn rp_client() -> OidcClient {
    OidcClient {
        client_id: "rp".to_string(),
        client_name: "Test RP".to_string(),
        redirect_uris: vec![RP_CALLBACK.to_string()],
        post_logout_redirect_uris: vec![format!("{RP_ORIGIN}/")],
        backchannel_logout_uri: None,
        allowed_origins: vec![RP_ORIGIN.to_string()],
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "offline_access".to_string(),
        ],
        require_dpop: false,
    }
}

struct Pkce {
    verifier: String,
    challenge: String,
}

fn pkce() -> Pkce {
    let verifier = random_b64u(32); // 43 url-safe chars
    let challenge = sha256_b64u(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

/// Drives /oauth/authorize with an authenticated session; returns the code.
async fn get_code(app: &TestApp, pkce: &Pkce, state_param: &str, nonce: &str) -> String {
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid profile offline_access")
        .add_query_param("state", state_param)
        .add_query_param("nonce", nonce)
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    res.assert_status(StatusCode::SEE_OTHER);
    let location = res.header("location");
    let url = Url::parse(location.to_str().expect("location header")).expect("redirect url");
    assert!(url.as_str().starts_with(RP_CALLBACK), "redirects to the RP");
    let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
    assert_eq!(query.get("state").map(AsRef::as_ref), Some(state_param));
    // RFC 9207: every authorization response carries the issuer.
    assert_eq!(query.get("iss").map(AsRef::as_ref), Some(harness::ISSUER));
    query.get("code").expect("code param").to_string()
}

#[tokio::test]
async fn discovery_and_jwks_are_served() {
    let app = TestApp::spawn().await;

    let res = app.server.get("/.well-known/openid-configuration").await;
    res.assert_status(StatusCode::OK);
    let doc: serde_json::Value = res.json();
    assert_eq!(doc["issuer"], harness::ISSUER);
    assert_eq!(
        doc["authorization_endpoint"],
        format!("{}/oauth/authorize", harness::ISSUER)
    );
    assert_eq!(doc["code_challenge_methods_supported"][0], "S256");
    assert_eq!(doc["frontchannel_logout_supported"], false);
    assert_eq!(doc["authorization_response_iss_parameter_supported"], true);
    assert_eq!(doc["revocation_endpoint_auth_methods_supported"][0], "none");
    assert_eq!(doc["dpop_signing_alg_values_supported"][0], "ES256");
    assert!(
        doc["prompt_values_supported"]
            .as_array()
            .is_some_and(|v| v.iter().any(|p| p == "create")),
        "prompt=create advertised"
    );
    // RFC 9470 step-up: the phishing-resistant acr values are advertised.
    assert!(
        doc["acr_values_supported"]
            .as_array()
            .is_some_and(|v| v.iter().any(|a| a == "phr-stepup") && v.iter().any(|a| a == "phr")),
        "acr_values_supported advertises phr and phr-stepup: {:?}",
        doc["acr_values_supported"]
    );
    assert!(
        doc["claims_supported"]
            .as_array()
            .is_some_and(|v| v.iter().any(|c| c == "acr")),
        "acr is an advertised claim"
    );

    let res = app.server.get("/.well-known/jwks.json").await;
    res.assert_status(StatusCode::OK);
    let jwks: serde_json::Value = res.json();
    assert_eq!(jwks["keys"][0]["kty"], "EC");
    assert_eq!(jwks["keys"][0]["alg"], "ES256");
    assert!(jwks["keys"][0]["kid"].is_string());
}

#[tokio::test]
async fn security_txt_is_served() {
    let app = TestApp::spawn().await;
    let res = app.server.get("/.well-known/security.txt").await;
    res.assert_status(StatusCode::OK);
    let body = res.text();
    // RFC 9116 requires Contact + Expires; Canonical points back at the issuer.
    assert!(body.contains("Contact:"), "missing Contact: {body}");
    assert!(body.contains("Expires:"), "missing Expires: {body}");
    assert!(
        body.contains(&format!("{}/.well-known/security.txt", harness::ISSUER)),
        "missing Canonical: {body}"
    );
}

#[tokio::test]
async fn full_code_pkce_flow_issues_verifiable_tokens() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "oidc@example.com", &mut authenticator).await;

    let pkce = pkce();
    let code = get_code(&app, &pkce, "xyzstate", "noncevalue").await;

    // Exchange the code.
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", RP_CALLBACK),
            ("client_id", "rp"),
            ("code_verifier", &pkce.verifier),
        ])
        .await;
    res.assert_status(StatusCode::OK);
    let tokens: serde_json::Value = res.json();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 600);
    let access_token = tokens["access_token"].as_str().expect("access token");
    let id_token = tokens["id_token"].as_str().expect("id token");
    assert!(
        tokens["refresh_token"]
            .as_str()
            .is_some_and(|t| t.starts_with("rt_"))
    );

    // Verify the ID token like an RP would: against the JWKS, with audience
    // and nonce checks.
    let jwks_res = app.server.get("/.well-known/jwks.json").await;
    let jwks: serde_json::Value = jwks_res.json();
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwks["keys"][0].clone()).expect("jwk");
    let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).expect("decoding key");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[harness::ISSUER]);
    validation.set_audience(&["rp"]);
    let id_claims = jsonwebtoken::decode::<serde_json::Value>(id_token, &key, &validation)
        .expect("id token verifies")
        .claims;
    assert_eq!(id_claims["nonce"], "noncevalue");
    assert_eq!(id_claims["nickname"], "oidc@example.com");
    // A passkey login is phishing-resistant: the baseline acr is `phr`.
    assert_eq!(
        id_claims["acr"], "phr",
        "id_token carries the phishing-resistant acr"
    );
    // The access token carries acr/amr too, so an RP resource server can gate on
    // assurance (RFC 9068 §2.2) without a userinfo round-trip.
    let at_claims = jsonwebtoken::decode::<serde_json::Value>(access_token, &key, &validation)
        .expect("access token verifies")
        .claims;
    assert_eq!(at_claims["acr"], "phr", "access token carries acr");
    assert!(
        at_claims["amr"]
            .as_array()
            .is_some_and(|a| a.iter().any(|m| m == "webauthn")),
        "access token carries amr"
    );
    assert!(
        id_claims.get("email").is_none(),
        "no email claim is ever issued"
    );
    // signup_with_passkey ends with a real passkey login, so the session — and
    // the token minted from it — carries amr=["webauthn"].
    assert!(
        id_claims["amr"]
            .as_array()
            .is_some_and(|a| a.iter().any(|m| m == "webauthn")),
        "passkey login must yield webauthn amr: {:?}",
        id_claims["amr"]
    );
    let kid = jsonwebtoken::decode_header(id_token).expect("header").kid;
    assert_eq!(kid.as_deref(), jwks["keys"][0]["kid"].as_str());

    // userinfo with the access token.
    let res = app
        .server
        .get("/oauth/userinfo")
        .add_header("authorization", format!("Bearer {access_token}"))
        .await;
    res.assert_status(StatusCode::OK);
    let userinfo: serde_json::Value = res.json();
    assert_eq!(userinfo["nickname"], "oidc@example.com");
    assert_eq!(userinfo["sub"], id_claims["sub"]);

    // Second authorize (silent SSO): no UI, straight back with a code.
    let pkce2 = pkce_2();
    let code2 = get_code(&app, &pkce2, "state2", "nonce2").await;
    assert_ne!(code, code2);
}

fn pkce_2() -> Pkce {
    pkce()
}

#[tokio::test]
async fn authorize_without_session_redirects_to_sign_in() {
    let app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let pkce = pkce();

    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    res.assert_status(StatusCode::SEE_OTHER);
    let location = res
        .header("location")
        .to_str()
        .expect("location")
        .to_string();
    assert!(
        location.starts_with(&format!("{}/sign-in?return_to=", harness::ISSUER)),
        "should land on the sign-in page: {location}"
    );
    // return_to round-trips to the exact authorize URL.
    let url = Url::parse(&location).expect("url");
    let return_to = url
        .query_pairs()
        .find(|(k, _)| k == "return_to")
        .map(|(_, v)| v.to_string())
        .expect("return_to");
    assert!(return_to.starts_with("/oauth/authorize?"));

    // prompt=none: error goes straight back to the RP.
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .add_query_param("prompt", "none")
        .add_query_param("state", "st")
        .await;
    let location = res
        .header("location")
        .to_str()
        .expect("location")
        .to_string();
    assert!(location.starts_with(RP_CALLBACK));
    assert!(location.contains("error=login_required"));
    assert!(location.contains("state=st"));
}

#[tokio::test]
async fn prompt_create_routes_to_signup_and_8414_alias_serves_metadata() {
    let app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let pkce = pkce();

    // prompt=create sends an unauthenticated browser to the signup entry.
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .add_query_param("prompt", "create")
        .await;
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(
        location.starts_with(&format!("{}/sign-up?return_to=", harness::ISSUER)),
        "prompt=create should land on signup: {location}"
    );

    // prompt=none combined with another value is invalid_request (to the RP).
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .add_query_param("prompt", "none login")
        .add_query_param("state", "s")
        .await;
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(location.starts_with(RP_CALLBACK) && location.contains("error=invalid_request"));

    // RFC 8414 alias serves the same document as the OIDC discovery path.
    let res = app
        .server
        .get("/.well-known/oauth-authorization-server")
        .await;
    res.assert_status(StatusCode::OK);
    let doc: serde_json::Value = res.json();
    assert_eq!(doc["issuer"], harness::ISSUER);
}

#[tokio::test]
async fn fresh_login_satisfies_prompt_login_and_max_age_zero() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "fresh@example.com", &mut authenticator).await;

    // A just-completed login is fresh enough for the strictest controls, so
    // authorize issues a code rather than looping back to sign-in (the grace
    // floor absorbs the redirect round-trip).
    for (key, value) in [("prompt", "login"), ("max_age", "0")] {
        let pkce = pkce();
        let res = app
            .server
            .get("/oauth/authorize")
            .add_query_param("response_type", "code")
            .add_query_param("client_id", "rp")
            .add_query_param("redirect_uri", RP_CALLBACK)
            .add_query_param("scope", "openid")
            .add_query_param("code_challenge", &pkce.challenge)
            .add_query_param("code_challenge_method", "S256")
            .add_query_param(key, value)
            .await;
        res.assert_status(StatusCode::SEE_OTHER);
        let location = res.header("location").to_str().expect("loc").to_string();
        assert!(
            location.starts_with(RP_CALLBACK) && location.contains("code="),
            "{key}={value} should issue a code to a freshly-logged-in user: {location}"
        );
    }
}

#[tokio::test]
async fn acr_stepup_is_satisfied_by_a_fresh_login_and_drops_to_baseline_on_refresh() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "acr@example.com", &mut authenticator).await;

    // A just-completed login satisfies the stepped-up acr (fresh reauth_at +
    // grace floor), so authorize issues a code rather than looping to sign-in.
    let pkce = pkce();
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid offline_access")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .add_query_param("acr_values", "phr-stepup")
        .await;
    res.assert_status(StatusCode::SEE_OTHER);
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(
        location.starts_with(RP_CALLBACK) && location.contains("code="),
        "stepped-up code issued to a fresh session: {location}"
    );
    let url = Url::parse(&location).expect("url");
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
            ("code", &code),
            ("redirect_uri", RP_CALLBACK),
            ("client_id", "rp"),
            ("code_verifier", &pkce.verifier),
        ])
        .await;
    res.assert_status(StatusCode::OK);
    let tokens: serde_json::Value = res.json();

    let jwks: serde_json::Value = app.server.get("/.well-known/jwks.json").await.json();
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwks["keys"][0].clone()).expect("jwk");
    let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).expect("key");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[harness::ISSUER]);
    validation.set_audience(&["rp"]);
    let decode = |token: &str| {
        jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
            .expect("token verifies")
            .claims
    };

    let id_token = tokens["id_token"].as_str().expect("id token");
    assert_eq!(
        decode(id_token)["acr"],
        "phr-stepup",
        "a fresh login satisfies and stamps the stepped-up acr"
    );

    // A refresh deliberately drops back to the phishing-resistant baseline:
    // step-up is point-in-time at the authorize event, not a sticky property.
    let refresh_token = tokens["refresh_token"].as_str().expect("rt");
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::OK);
    let refreshed: serde_json::Value = res.json();
    let refreshed_id = refreshed["id_token"].as_str().expect("id token");
    assert_eq!(
        decode(refreshed_id)["acr"],
        "phr",
        "a refresh carries the baseline acr, never the stepped-up one"
    );
}

#[tokio::test]
async fn authorize_rejects_bad_clients_and_redirect_uris_without_rp_redirect() {
    let app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let pkce = pkce();

    // Unknown client: no RP redirect, lands on /error.
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "ghost")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    let location = res
        .header("location")
        .to_str()
        .expect("location")
        .to_string();
    assert!(location.starts_with(&format!("{}/error", harness::ISSUER)));

    // Unregistered redirect_uri: also /error, never the attacker URI.
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", "http://evil.example.com/cb")
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    let location = res
        .header("location")
        .to_str()
        .expect("location")
        .to_string();
    assert!(location.starts_with(&format!("{}/error", harness::ISSUER)));

    // plain method refused (S256 only) — error to the RP (uri is valid).
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &pkce.challenge)
        .add_query_param("code_challenge_method", "plain")
        .await;
    let location = res
        .header("location")
        .to_str()
        .expect("location")
        .to_string();
    assert!(location.starts_with(RP_CALLBACK) && location.contains("error=invalid_request"));
}

#[tokio::test]
async fn code_is_single_use_and_replay_revokes_the_family() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "replay@example.com", &mut authenticator).await;

    let pkce = pkce();
    let code = get_code(&app, &pkce, "s", "n").await;

    let exchange = |code: String, verifier: String| {
        app.server.post("/oauth/token").form(&[
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("redirect_uri", RP_CALLBACK.to_string()),
            ("client_id", "rp".to_string()),
            ("code_verifier", verifier),
        ])
    };

    let res = exchange(code.clone(), pkce.verifier.clone()).await;
    res.assert_status(StatusCode::OK);
    let tokens: serde_json::Value = res.json();
    let refresh_token = tokens["refresh_token"].as_str().expect("rt").to_string();

    // Replay the code: invalid_grant…
    let res = exchange(code, pkce.verifier.clone()).await;
    res.assert_status(StatusCode::BAD_REQUEST);
    let err: serde_json::Value = res.json();
    assert_eq!(err["error"], "invalid_grant");

    // …and the refresh family from the first exchange is dead (RFC 9700).
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_pkce_verifier_is_rejected() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "pkce@example.com", &mut authenticator).await;

    let p = pkce();
    let code = get_code(&app, &p, "s", "n").await;
    let wrong = random_b64u(32);
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", RP_CALLBACK),
            ("client_id", "rp"),
            ("code_verifier", wrong.as_str()),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
    let err: serde_json::Value = res.json();
    assert_eq!(err["error"], "invalid_grant");
}

#[tokio::test]
async fn cors_reflects_only_registered_origins() {
    let app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;

    let res = app
        .server
        .method(axum::http::Method::OPTIONS, "/oauth/token")
        .add_header("origin", RP_ORIGIN)
        .add_header("access-control-request-method", "POST")
        .await;
    res.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        res.header("access-control-allow-origin").to_str().ok(),
        Some(RP_ORIGIN)
    );

    let res = app
        .server
        .method(axum::http::Method::OPTIONS, "/oauth/token")
        .add_header("origin", "http://evil.example.com")
        .add_header("access-control-request-method", "POST")
        .await;
    assert!(res.maybe_header("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn metadata_endpoints_allow_any_origin() {
    // Discovery + JWKS are public metadata, fetched cross-origin by RP SPAs
    // before they are known to us, so any origin may read them.
    let app = TestApp::spawn().await;

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
    ] {
        let res = app
            .server
            .get(path)
            .add_header("origin", "http://unregistered.example.com")
            .await;
        res.assert_status(StatusCode::OK);
        assert_eq!(
            res.header("access-control-allow-origin").to_str().ok(),
            Some("*"),
            "{path} should be readable from any origin"
        );

        let preflight = app
            .server
            .method(axum::http::Method::OPTIONS, path)
            .add_header("origin", "http://unregistered.example.com")
            .add_header("access-control-request-method", "GET")
            .await;
        preflight.assert_status(StatusCode::NO_CONTENT);
        assert_eq!(
            preflight
                .header("access-control-allow-origin")
                .to_str()
                .ok(),
            Some("*"),
            "{path} preflight should allow any origin"
        );
    }
}
