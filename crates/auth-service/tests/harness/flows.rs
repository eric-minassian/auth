//! Reusable end-to-end flows shared by integration-test binaries.

use axum::http::StatusCode;
use serde_json::json;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::CreationChallengeResponse;

use super::TestApp;

pub fn origin() -> Url {
    Url::parse(super::ISSUER).expect("origin url")
}

pub fn new_authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

/// Create an account (proof-of-work → pending user → first passkey) WITHOUT
/// logging in. Ends with an enroll-level session in the cookie jar. Returns the
/// new `user_id`.
pub async fn register_new_account(
    app: &mut TestApp,
    nickname: &str,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) -> String {
    let (challenge, nonce) = app.solve_signup_pow().await;
    let res = app
        .post(
            "/api/signup/start",
            &json!({ "nickname": nickname, "pow_challenge": challenge, "pow_nonce": nonce }),
        )
        .await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    let ceremony_id = body["ceremony_id"]
        .as_str()
        .expect("ceremony id")
        .to_string();
    let user_id = body["user_id"].as_str().expect("user id").to_string();
    let options: CreationChallengeResponse =
        serde_json::from_value(body["options"].clone()).expect("creation options");

    let credential = authenticator
        .do_registration(origin(), options)
        .expect("soft passkey registration");

    app.post(
        "/api/signup/finish",
        &json!({ "ceremony_id": ceremony_id, "credential": credential, "name": "SoftPasskey" }),
    )
    .await
    .assert_status(StatusCode::OK);
    user_id
}

/// Full onboarding: create the account, then establish a full session. Returns
/// the new `user_id`. The real discoverable login ceremony is covered by the
/// Playwright e2e (see [`TestApp::login_as`] for why Rust tests can't drive it).
pub async fn signup_with_passkey(
    app: &mut TestApp,
    nickname: &str,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
) -> String {
    let user_id = register_new_account(app, nickname, authenticator).await;
    app.login_as(uuid::Uuid::parse_str(&user_id).expect("uuid"))
        .await;
    user_id
}
