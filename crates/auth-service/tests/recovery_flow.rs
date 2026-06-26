//! Recovery codes: step-up-gated generation, one-time redemption with reset,
//! and re-onboarding a new passkey — plus the WebAuthn step-up ceremony.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use axum::http::StatusCode;
use harness::TestApp;
use harness::flows::{new_authenticator, origin, signup_with_passkey};
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

#[tokio::test]
async fn recovery_code_redemption_reonboards_a_new_passkey() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    let user_id = signup_with_passkey(&mut app, "Owner", &mut authenticator).await;

    // Generate codes — a fresh login counts as the required step-up.
    let res = app.post("/api/account/recovery-codes", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let codes = body["codes"].as_array().expect("codes array");
    assert_eq!(codes.len(), 10);
    let code = codes[0].as_str().expect("code").to_string();

    // Readiness reflects the new codes.
    let readiness: serde_json::Value = app
        .server
        .get("/api/account/recovery-readiness")
        .await
        .json();
    assert_eq!(readiness["recovery_codes_remaining"], 10);
    assert_eq!(readiness["passkey_count"], 1);

    // Simulate device loss: drop the session.
    app.post("/api/session/logout", &json!({}))
        .await
        .assert_status(StatusCode::OK);

    // Redeem the code → enroll session.
    app.post("/api/recovery/redeem", &json!({ "code": code.clone() }))
        .await
        .assert_status(StatusCode::OK);

    // Redeeming again fails — one-time use.
    app.post("/api/recovery/redeem", &json!({ "code": code }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    // Register a NEW passkey from the enroll session, then log in with it.
    let mut new_device = new_authenticator();
    let res = app.post("/api/webauthn/register/start", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"].as_str().expect("id").to_string();
    let options: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("options");
    let credential = new_device
        .do_registration(origin(), options)
        .expect("registration");
    app.post(
        "/api/webauthn/register/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "New device" }),
    )
    .await
    .assert_status(StatusCode::OK);

    // Registering never elevates — still enroll until a real login.
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    app.login_as(Uuid::parse_str(&user_id).expect("uuid")).await;
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn unknown_recovery_code_is_rejected() {
    let app = TestApp::spawn().await;
    app.post(
        "/api/recovery/redeem",
        &json!({ "code": "ABCDE-ABCDE-ABCDE-ABCDE-ABCDE-A" }),
    )
    .await
    .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn webauthn_step_up_succeeds_on_full_session() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();
    signup_with_passkey(&mut app, "Stepper", &mut authenticator).await;

    let res = app.post("/api/webauthn/reauth/start", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"].as_str().expect("id").to_string();
    let options: RequestChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("options");
    let credential = authenticator
        .do_authentication(origin(), options)
        .expect("assertion");
    app.post(
        "/api/webauthn/reauth/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential }),
    )
    .await
    .assert_status(StatusCode::OK);
}
