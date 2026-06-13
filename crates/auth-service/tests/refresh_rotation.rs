//! Refresh-token rotation, reuse detection, and the session-bound lifecycle.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use auth_service::crypto::{random_b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use axum::http::StatusCode;
use harness::TestApp;
use harness::flows;
use url::Url;

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
            "email".to_string(),
            "offline_access".to_string(),
        ],
    }
}

/// Boots an app, signs up, runs the code flow, returns the first refresh
/// token.
async fn bootstrap(app: &mut TestApp, email: &str) -> String {
    app.seed_client(&rp_client()).await;
    let mut authenticator = flows::new_authenticator();
    flows::signup_with_passkey(app, email, &mut authenticator).await;

    let verifier = random_b64u(32);
    let challenge = sha256_b64u(&verifier);
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid offline_access")
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
    let tokens: serde_json::Value = res.json();
    tokens["refresh_token"].as_str().expect("rt").to_string()
}

async fn refresh(app: &TestApp, token: &str, client_id: &str) -> (StatusCode, serde_json::Value) {
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", client_id),
        ])
        .await;
    (res.status_code(), res.json())
}

#[tokio::test]
async fn rotation_invalidates_the_previous_token() {
    let mut app = TestApp::spawn().await;
    let rt0 = bootstrap(&mut app, "rot@example.com").await;

    let (status, tokens) = refresh(&app, &rt0, "rp").await;
    assert_eq!(status, StatusCode::OK);
    let rt1 = tokens["refresh_token"]
        .as_str()
        .expect("rotated rt")
        .to_string();
    assert_ne!(rt0, rt1);
    assert!(tokens["access_token"].is_string());
    assert!(
        tokens["id_token"].is_string(),
        "openid scope → id_token on refresh"
    );

    // Old token is dead; new token still works.
    let (status, body) = refresh(&app, &rt0, "rp").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn reuse_after_rotation_revokes_the_whole_family() {
    let mut app = TestApp::spawn().await;
    let rt0 = bootstrap(&mut app, "reuse@example.com").await;

    let (status, tokens) = refresh(&app, &rt0, "rp").await;
    assert_eq!(status, StatusCode::OK);
    let rt1 = tokens["refresh_token"].as_str().expect("rt1").to_string();

    // Replay rt0 (attacker scenario): invalid AND kills rt1's family.
    let (status, _) = refresh(&app, &rt0, "rp").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = refresh(&app, &rt1, "rp").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_dies_with_the_idp_session() {
    let mut app = TestApp::spawn().await;
    let rt0 = bootstrap(&mut app, "logout@example.com").await;

    // Kill the IdP session (single logout: refresh grants must stop).
    app.post("/api/session/logout", &serde_json::json!({}))
        .await
        .assert_status(StatusCode::OK);

    let (status, body) = refresh(&app, &rt0, "rp").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_with_wrong_client_id_revokes_the_family() {
    let mut app = TestApp::spawn().await;
    let rt0 = bootstrap(&mut app, "client@example.com").await;
    app.seed_client(&OidcClient {
        client_id: "other".to_string(),
        client_name: "Other".to_string(),
        redirect_uris: vec!["http://other.example.com/cb".to_string()],
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        allowed_origins: vec![],
        scopes: vec!["openid".to_string()],
    })
    .await;

    let (status, _) = refresh(&app, &rt0, "other").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Family treated as compromised: original client can't use it either.
    let (status, _) = refresh(&app, &rt0, "rp").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoke_endpoint_kills_the_family() {
    let mut app = TestApp::spawn().await;
    let rt0 = bootstrap(&mut app, "revoke@example.com").await;

    let res = app
        .server
        .post("/oauth/revoke")
        .form(&[("token", rt0.as_str())])
        .await;
    res.assert_status(StatusCode::OK);

    let (status, _) = refresh(&app, &rt0, "rp").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Revoking garbage is still 200 (no oracle).
    let res = app
        .server
        .post("/oauth/revoke")
        .form(&[("token", "rt_bogus.bogus")])
        .await;
    res.assert_status(StatusCode::OK);
}
