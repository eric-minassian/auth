//! Credential-lifecycle revocation: deleting a passkey severs the sessions
//! (and their refresh families) it vouched for, and refresh-token reuse
//! revokes the backing IdP session — CAEP credential-change semantics applied
//! locally, plus the RFC 9700 reuse-as-compromise response.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use auth_service::crypto::{random_b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use axum::http::StatusCode;
use harness::TestApp;
use harness::flows::{new_authenticator, origin, signup_with_passkey};
use serde_json::json;
use url::Url;
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
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "offline_access".to_string(),
        ],
        require_dpop: false,
    }
}

/// Register a second passkey on the current (fresh, stepped-up) session and
/// return its credential id.
async fn add_second_passkey(app: &mut TestApp) -> String {
    let mut second = new_authenticator();
    let res = app.post("/api/webauthn/register/start", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"].as_str().expect("id").to_string();
    let options: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("options");
    let credential = second
        .do_registration(origin(), options)
        .expect("registration");
    let res = app
        .post(
            "/api/webauthn/register/finish",
            &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "Backup" }),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    body["credential_id"].as_str().expect("id").to_string()
}

fn delete_passkey_req(app: &TestApp, credential_id: &str) -> axum_test::TestRequest {
    app.server
        .delete(&format!("/api/account/passkeys/{credential_id}"))
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
}

/// Run the code flow with the current cookie jar and return the refresh token.
async fn mint_refresh_token(app: &TestApp) -> String {
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

#[tokio::test]
async fn deleting_a_passkey_requires_a_recent_stepup() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "stale", &mut authenticator).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");
    let second_id = add_second_passkey(&mut app).await;

    // Age every full session's assertion far past the step-up window (the
    // signup enroll session may still be live; only Full sessions can call
    // account endpoints).
    for session in app.store.list_sessions(user_id).await.expect("sessions") {
        if session.level == auth_service::domain::session::SessionLevel::Full {
            app.store
                .set_session_reauth(&session.sid_hash, 1, "stale-cred")
                .await
                .expect("age reauth");
        }
    }

    let res = delete_passkey_req(&app, &second_id).await;
    res.assert_status(StatusCode::CONFLICT);
    let body: serde_json::Value = res.json();
    assert_eq!(body["error"], "reauth_required");

    // The passkey survives.
    let body: serde_json::Value = app.server.get("/api/account/passkeys").await.json();
    assert_eq!(body["passkeys"].as_array().expect("list").len(), 2);
}

#[tokio::test]
async fn deleting_a_passkey_revokes_the_sessions_and_tokens_it_established() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "sever", &mut authenticator).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");
    let doomed_id = add_second_passkey(&mut app).await;

    // A session on "another device", established by the soon-to-be-deleted
    // passkey, with a refresh family hanging off it.
    let (_, doomed_session) = app
        .store
        .create_session(
            user_id,
            auth_service::domain::session::SessionLevel::Full,
            vec!["webauthn".to_string()],
            None,
            None,
            Some(doomed_id.clone()),
        )
        .await
        .expect("victim session");
    let doomed_rt = app
        .store
        .create_refresh_family(
            &random_b64u(16),
            user_id,
            "rp",
            &doomed_session.sid_hash,
            "openid offline_access",
            None,
        )
        .await
        .expect("victim family");

    // Current session is bound to the *original* passkey, so it survives.
    // (login_as_with_credential replaces the cookie, becoming "this device".)
    let body: serde_json::Value = app.server.get("/api/account/passkeys").await.json();
    let original_id = body["passkeys"]
        .as_array()
        .expect("list")
        .iter()
        .map(|p| p["credential_id"].as_str().expect("id").to_string())
        .find(|id| *id != doomed_id)
        .expect("original credential");
    app.login_as_with_credential(user_id, Some(original_id)).await;

    let res = delete_passkey_req(&app, &doomed_id).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["ok"], true);
    assert_eq!(body["current_session_revoked"], false);

    // The bound session is gone…
    assert!(
        app.store
            .get_session_by_hash(&doomed_session.sid_hash)
            .await
            .expect("lookup")
            .is_none(),
        "session established by the deleted passkey must be revoked"
    );
    // …and its refresh family is dead.
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", doomed_rt.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);

    // The current session (bound to the surviving passkey) still works.
    app.server
        .get("/api/account/passkeys")
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn deleting_the_passkey_behind_the_current_session_logs_it_out() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "self", &mut authenticator).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");
    let doomed_id = add_second_passkey(&mut app).await;

    // Current session established by the passkey being deleted.
    app.login_as_with_credential(user_id, Some(doomed_id.clone()))
        .await;

    let res = delete_passkey_req(&app, &doomed_id).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["current_session_revoked"], true);

    // The caller's session died with its passkey.
    app.server
        .get("/api/account/passkeys")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_reuse_revokes_the_backing_session_and_siblings() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "reuse", &mut authenticator).await;
    let user_id = Uuid::parse_str(&user_id).expect("uuid");

    let rt0 = mint_refresh_token(&app).await;
    // A sibling family on the same session (another RP grant from this login).
    let sessions = app.store.list_sessions(user_id).await.expect("sessions");
    let session = sessions
        .iter()
        .find(|s| s.level == auth_service::domain::session::SessionLevel::Full)
        .expect("full session");
    let sibling_rt = app
        .store
        .create_refresh_family(
            &random_b64u(16),
            user_id,
            "rp",
            &session.sid_hash,
            "openid offline_access",
            None,
        )
        .await
        .expect("sibling family");

    // Rotate, then replay the old token: reuse.
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
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", rt0.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);

    // The backing IdP session is revoked…
    assert!(
        !app.store
            .list_sessions(user_id)
            .await
            .expect("sessions")
            .iter()
            .any(|s| s.level == auth_service::domain::session::SessionLevel::Full),
        "refresh reuse must revoke the backing IdP session"
    );
    // …the browser is signed out…
    app.server
        .get("/api/account/passkeys")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // …and sibling families die with the session.
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", sibling_rt.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
}
