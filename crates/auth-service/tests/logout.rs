//! Logout: session cascade, refresh-family revocation, and back-channel
//! logout dispatch to a wiremock receiver.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use auth_service::crypto::{random_b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use axum::http::StatusCode;
use harness::TestApp;
use harness::flows;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RP_CALLBACK: &str = "http://rp.example.com/callback";

/// Runs signup + code flow against a client whose back-channel endpoint is the
/// given wiremock server; returns the refresh token.
async fn bootstrap_with_backchannel(
    app: &mut TestApp,
    email: &str,
    backchannel_uri: &str,
) -> String {
    app.seed_client(&OidcClient {
        client_id: "rp".to_string(),
        client_name: "RP".to_string(),
        redirect_uris: vec![RP_CALLBACK.to_string()],
        post_logout_redirect_uris: vec!["http://rp.example.com/bye".to_string()],
        backchannel_logout_uri: Some(backchannel_uri.to_string()),
        allowed_origins: vec![],
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "offline_access".to_string(),
        ],
        require_dpop: false,
    })
    .await;

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
        .add_query_param("scope", "openid profile offline_access")
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

#[tokio::test]
async fn logout_dispatches_backchannel_and_revokes_refresh() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/backchannel"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;

    let mut app = TestApp::spawn().await;
    let backchannel_uri = format!("{}/backchannel", receiver.uri());
    let refresh_token =
        bootstrap_with_backchannel(&mut app, "bye@example.com", &backchannel_uri).await;

    // Log out via the SPA endpoint.
    app.post("/api/session/logout", &serde_json::json!({}))
        .await
        .assert_status(StatusCode::OK);

    // Refresh grant is dead.
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

    // The wiremock .expect(1) is verified on drop: exactly one back-channel
    // POST was delivered. Inspect the received logout token.
    let requests = receiver
        .received_requests()
        .await
        .expect("received requests");
    assert_eq!(requests.len(), 1);
    let body = String::from_utf8(requests[0].body.clone()).expect("utf8 body");
    assert!(
        body.starts_with("logout_token="),
        "form-encoded logout token"
    );
}

#[tokio::test]
async fn rp_initiated_logout_redirects_to_registered_uri() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/backchannel"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&receiver)
        .await;

    let mut app = TestApp::spawn().await;
    let backchannel_uri = format!("{}/backchannel", receiver.uri());
    bootstrap_with_backchannel(&mut app, "rpbye@example.com", &backchannel_uri).await;

    // Mint an id_token via a second silent authorize+exchange so we have a
    // valid id_token_hint.
    let id_token = mint_id_token(&app).await;

    // RP-initiated logout with a valid hint and a registered redirect.
    let res = app
        .server
        .get("/oauth/logout")
        .add_query_param("id_token_hint", &id_token)
        .add_query_param("post_logout_redirect_uri", "http://rp.example.com/bye")
        .add_query_param("client_id", "rp")
        .add_query_param("state", "logoutstate")
        .await;
    res.assert_status(StatusCode::SEE_OTHER);
    let location = res.header("location").to_str().expect("loc").to_string();
    assert!(location.starts_with("http://rp.example.com/bye"));
    assert!(location.contains("state=logoutstate"));

    // Session is gone.
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rp_initiated_logout_without_valid_hint_goes_to_confirmation() {
    let app = TestApp::spawn().await;

    // No hint at all → SPA /logout confirmation, no destructive action.
    let res = app.server.get("/oauth/logout").await;
    res.assert_status(StatusCode::SEE_OTHER);
    let location = res.header("location").to_str().expect("loc").to_string();
    assert_eq!(location, format!("{}/logout", harness::ISSUER));

    // Garbage hint → also the confirmation page.
    let res = app
        .server
        .get("/oauth/logout")
        .add_query_param("id_token_hint", "not.a.jwt")
        .await;
    let location = res.header("location").to_str().expect("loc").to_string();
    assert_eq!(location, format!("{}/logout", harness::ISSUER));
}

/// Silent authorize + code exchange to obtain a fresh id_token for the live
/// session.
async fn mint_id_token(app: &TestApp) -> String {
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
    let tokens: serde_json::Value = res.json();
    tokens["id_token"].as_str().expect("id token").to_string()
}
