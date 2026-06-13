//! Reusable end-to-end flows shared by integration-test binaries.

use axum::http::StatusCode;
use serde_json::json;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use super::TestApp;

pub fn origin() -> Url {
    Url::parse(super::ISSUER).expect("origin url")
}

pub fn new_authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

/// signup → OTP → passkey registration. Ends with a FULL session in the
/// cookie jar (register/finish upgrades the enroll session).
pub async fn signup_with_passkey(
    app: &mut TestApp,
    email: &str,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) {
    app.post("/api/signup/start", &json!({ "email": email }))
        .await
        .assert_status(StatusCode::OK);
    let code = app.take_otp(email);
    app.post(
        "/api/signup/verify",
        &json!({ "email": email, "code": code }),
    )
    .await
    .assert_status(StatusCode::OK);

    let res = app.post("/api/webauthn/register/start", &json!({})).await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"]
        .as_str()
        .expect("ceremony id")
        .to_string();
    let options: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("creation options");

    let credential = authenticator
        .do_registration(origin(), options)
        .expect("soft passkey registration");

    app.post(
        "/api/webauthn/register/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "SoftPasskey" }),
    )
    .await
    .assert_status(StatusCode::OK);
}

/// Email-assisted passkey login; ends with a fresh FULL session.
pub async fn login(
    app: &mut TestApp,
    email: &str,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) {
    let res = app
        .post("/api/webauthn/login/start", &json!({ "email": email }))
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"]
        .as_str()
        .expect("ceremony id")
        .to_string();
    let options: RequestChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("request options");

    let credential = authenticator
        .do_authentication(origin(), options)
        .expect("soft passkey authentication");

    app.post(
        "/api/webauthn/login/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential }),
    )
    .await
    .assert_status(StatusCode::OK);
}
