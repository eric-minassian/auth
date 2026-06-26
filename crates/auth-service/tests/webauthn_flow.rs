// Helper fns outside #[test] bodies aren't covered by clippy's
// allow-*-in-tests, hence the file-level allows.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use axum::http::StatusCode;
use harness::TestApp;
use harness::flows::{new_authenticator, origin, register_new_account, signup_with_passkey};
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::CreationChallengeResponse;

#[tokio::test]
async fn registering_a_passkey_does_not_elevate_to_full() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();

    let user_id = register_new_account(&mut app, "Reg", &mut authenticator).await;

    // Registering a passkey leaves an enroll session — login is the only path to
    // Full, so a Full session always implies a real WebAuthn assertion.
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::FORBIDDEN);

    // (The discoverable login ceremony is covered by the Playwright e2e — the
    // Rust soft authenticator can't emulate resident credentials. Mint the
    // post-login full session directly to cover the rest of the surface.)
    app.login_as(Uuid::parse_str(&user_id).expect("uuid")).await;
    let body: serde_json::Value = app.server.get("/api/session").await.json();
    assert_eq!(body["user"]["nickname"], "Reg");
    let amr = body["session"]["amr"].as_array().expect("amr array");
    assert!(amr.iter().any(|m| m == "webauthn"));
    assert!(
        amr.iter().all(|m| m != "pending" && m != "recovery"),
        "full session must not carry an enroll amr: {amr:?}"
    );
}

#[tokio::test]
async fn second_passkey_can_be_added_but_last_cannot_be_deleted() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    signup_with_passkey(&mut app, "del", &mut authenticator).await;

    let body: serde_json::Value = app.server.get("/api/account/passkeys").await.json();
    let first_id = body["passkeys"][0]["credential_id"]
        .as_str()
        .expect("credential id")
        .to_string();

    // Refuse deleting the only passkey.
    app.server
        .delete(&format!("/api/account/passkeys/{first_id}"))
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .await
        .assert_status(StatusCode::CONFLICT);

    // Add a second passkey. The full session is fresh from login, so the
    // add-passkey step-up requirement is satisfied.
    let mut second = new_authenticator();
    add_passkey(&mut app, &mut second, "Backup").await;

    // Now the first can be deleted.
    app.server
        .delete(&format!("/api/account/passkeys/{first_id}"))
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .await
        .assert_status(StatusCode::OK);

    // Rename the remaining one.
    let body: serde_json::Value = app.server.get("/api/account/passkeys").await.json();
    let remaining = body["passkeys"][0]["credential_id"]
        .as_str()
        .expect("credential id")
        .to_string();
    app.server
        .patch(&format!("/api/account/passkeys/{remaining}"))
        .add_header("origin", harness::ISSUER)
        .add_header("sec-fetch-site", "same-origin")
        .json(&json!({ "name": "Primary" }))
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn register_ceremony_is_single_use() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    signup_with_passkey(&mut app, "once", &mut authenticator).await;

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

    app.post(
        "/api/webauthn/register/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "X" }),
    )
    .await
    .assert_status(StatusCode::OK);

    // Replaying the same ceremony id fails — it was consumed.
    app.post(
        "/api/webauthn/register/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "X" }),
    )
    .await
    .assert_status(StatusCode::BAD_REQUEST);
}

async fn add_passkey(
    app: &mut TestApp,
    authenticator: &mut webauthn_authenticator_rs::WebauthnAuthenticator<
        webauthn_authenticator_rs::softpasskey::SoftPasskey,
    >,
    name: &str,
) {
    let res = app.post("/api/webauthn/register/start", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"].as_str().expect("id").to_string();
    let options: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("options");
    let credential = authenticator
        .do_registration(origin(), options)
        .expect("registration");
    app.post(
        "/api/webauthn/register/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": name }),
    )
    .await
    .assert_status(StatusCode::OK);
}
