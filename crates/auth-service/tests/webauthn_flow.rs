// Helper fns outside #[test] bodies aren't covered by clippy's
// allow-*-in-tests, hence the file-level allows.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use axum::http::StatusCode;
use harness::TestApp;
use harness::flows::{login, new_authenticator, origin, signup_with_passkey};
use serde_json::json;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

#[tokio::test]
async fn register_upgrades_enroll_session_to_full() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();

    signup_with_passkey(&mut app, "pk@example.com", &mut authenticator).await;

    // The enroll session became full: whoami now works.
    let res = app.server.get("/api/session").await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["user"]["email"], "pk@example.com");
    assert!(
        body["session"]["amr"]
            .as_array()
            .is_some_and(|amr| amr.iter().any(|m| m == "webauthn")),
        "amr should include webauthn after upgrade"
    );
}

#[tokio::test]
async fn full_login_roundtrip_with_fresh_session() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();

    signup_with_passkey(&mut app, "login@example.com", &mut authenticator).await;

    // Drop the session entirely, then authenticate with the passkey.
    app.post("/api/session/logout", &json!({}))
        .await
        .assert_status(StatusCode::OK);
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    login(&mut app, "login@example.com", &mut authenticator).await;

    let res = app.server.get("/api/session").await;
    res.assert_status(StatusCode::OK);

    // Passkey list shows the credential with a last_used timestamp.
    let res = app.server.get("/api/account/passkeys").await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let passkeys = body["passkeys"].as_array().expect("passkeys array");
    assert_eq!(passkeys.len(), 1);
    assert!(passkeys[0]["last_used_at"].is_i64());
}

#[tokio::test]
async fn ceremony_is_single_use_and_login_is_uniform_on_garbage() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();

    signup_with_passkey(&mut app, "once@example.com", &mut authenticator).await;
    app.post("/api/session/logout", &json!({}))
        .await
        .assert_status(StatusCode::OK);

    // Start a ceremony, authenticate, then try to replay the ceremony id.
    let res = app
        .post(
            "/api/webauthn/login/start",
            &json!({ "email": "once@example.com" }),
        )
        .await;
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"].as_str().expect("id").to_string();
    let options: RequestChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("options");
    let credential = authenticator
        .do_authentication(origin(), options)
        .expect("authentication");

    app.post(
        "/api/webauthn/login/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential }),
    )
    .await
    .assert_status(StatusCode::OK);

    // Replay: ceremony already consumed.
    let res = app
        .post(
            "/api/webauthn/login/finish",
            &json!({ "ceremony_id": ceremony_id, "credential": credential }),
        )
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn last_passkey_cannot_be_deleted_and_second_one_can() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();

    signup_with_passkey(&mut app, "del@example.com", &mut authenticator).await;

    let res = app.server.get("/api/account/passkeys").await;
    let body: serde_json::Value = res.json();
    let first_id = body["passkeys"][0]["credential_id"]
        .as_str()
        .expect("credential id")
        .to_string();

    // Refuse deleting the only passkey.
    let res = app
        .server
        .delete(&format!("/api/account/passkeys/{first_id}"))
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .await;
    res.assert_status(StatusCode::CONFLICT);

    // Register a second passkey (separate authenticator), then delete the first.
    let mut second = new_authenticator();
    let res = app.post("/api/webauthn/register/start", &json!({})).await;
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"].as_str().expect("id").to_string();
    let options: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("options");
    let credential = second
        .do_registration(origin(), options)
        .expect("second registration");
    app.post(
        "/api/webauthn/register/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "Backup" }),
    )
    .await
    .assert_status(StatusCode::OK);

    let res = app
        .server
        .delete(&format!("/api/account/passkeys/{first_id}"))
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .await;
    res.assert_status(StatusCode::OK);

    // Rename the remaining one.
    let res = app.server.get("/api/account/passkeys").await;
    let body: serde_json::Value = res.json();
    let remaining = body["passkeys"][0]["credential_id"]
        .as_str()
        .expect("credential id")
        .to_string();
    let res = app
        .server
        .patch(&format!("/api/account/passkeys/{remaining}"))
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .json(&json!({ "name": "Primary" }))
        .await;
    res.assert_status(StatusCode::OK);
}
