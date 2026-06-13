mod harness;

use axum::http::StatusCode;
use harness::TestApp;
use serde_json::json;

#[tokio::test]
async fn signup_end_to_end() {
    let mut app = TestApp::spawn().await;

    // Start: uniform 200, OTP email delivered.
    let res = app
        .post("/api/signup/start", &json!({ "email": "eric@example.com" }))
        .await;
    res.assert_status(StatusCode::OK);
    let code = app.take_otp("eric@example.com");

    // Wrong code burns an attempt but does not create anything.
    let res = app
        .post(
            "/api/signup/verify",
            &json!({ "email": "eric@example.com", "code": "000000" }),
        )
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);

    // Correct code: account + enroll-level session cookie.
    let res = app
        .post(
            "/api/signup/verify",
            &json!({ "email": "eric@example.com", "code": code }),
        )
        .await;
    res.assert_status(StatusCode::OK);
    assert!(
        res.header("set-cookie")
            .to_str()
            .is_ok_and(|c| c.contains("auth_session") && c.contains("HttpOnly")),
        "should set the session cookie"
    );

    // Enroll session is not enough for whoami (needs a passkey login).
    let res = app.server.get("/api/session").await;
    res.assert_status(StatusCode::FORBIDDEN);

    // The OTP was consumed: replaying the same code fails.
    let res = app
        .post(
            "/api/signup/verify",
            &json!({ "email": "eric@example.com", "code": code }),
        )
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);

    // User exists in the store with the email pointer.
    let user = app
        .store
        .get_user_by_email("eric@example.com")
        .await
        .expect("store reachable")
        .expect("user created");
    assert!(user.email_verified);
}

#[tokio::test]
async fn signup_start_is_uniform_for_existing_accounts() {
    let mut app = TestApp::spawn().await;

    // Create the account.
    app.post("/api/signup/start", &json!({ "email": "a@example.com" }))
        .await
        .assert_status(StatusCode::OK);
    let code = app.take_otp("a@example.com");
    app.post(
        "/api/signup/verify",
        &json!({ "email": "a@example.com", "code": code }),
    )
    .await
    .assert_status(StatusCode::OK);

    // Second signup start: same 200, but the email is a notice, not an OTP.
    let res = app
        .post("/api/signup/start", &json!({ "email": "a@example.com" }))
        .await;
    res.assert_status(StatusCode::OK);
    let email = app
        .last_email_to("a@example.com")
        .expect("notice email sent");
    assert!(
        harness::extract_otp(&email.text).is_none(),
        "no OTP for existing accounts"
    );
}

#[tokio::test]
async fn otp_attempts_are_capped() {
    let mut app = TestApp::spawn().await;

    app.post("/api/signup/start", &json!({ "email": "cap@example.com" }))
        .await
        .assert_status(StatusCode::OK);
    let code = app.take_otp("cap@example.com");

    for _ in 0..5 {
        app.post(
            "/api/signup/verify",
            &json!({ "email": "cap@example.com", "code": "999999" }),
        )
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    }
    // Attempt cap reached: even the correct code is rejected now.
    let res = app
        .post(
            "/api/signup/verify",
            &json!({ "email": "cap@example.com", "code": code }),
        )
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recovery_flow_issues_enroll_session() {
    let mut app = TestApp::spawn().await;

    // Existing account.
    app.post("/api/signup/start", &json!({ "email": "r@example.com" }))
        .await
        .assert_status(StatusCode::OK);
    let code = app.take_otp("r@example.com");
    app.post(
        "/api/signup/verify",
        &json!({ "email": "r@example.com", "code": code }),
    )
    .await
    .assert_status(StatusCode::OK);

    // Recovery for an unknown email: uniform 200, no email at all.
    app.post(
        "/api/recovery/start",
        &json!({ "email": "ghost@example.com" }),
    )
    .await
    .assert_status(StatusCode::OK);
    assert!(app.last_email_to("ghost@example.com").is_none());

    // Recovery for the real account.
    app.post("/api/recovery/start", &json!({ "email": "r@example.com" }))
        .await
        .assert_status(StatusCode::OK);
    let code = app.take_otp("r@example.com");
    let res = app
        .post(
            "/api/recovery/verify",
            &json!({ "email": "r@example.com", "code": code }),
        )
        .await;
    res.assert_status(StatusCode::OK);

    // Logout works from an enroll session.
    app.post("/api/session/logout", &json!({}))
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn csrf_rejects_cross_origin_posts() {
    let app = TestApp::spawn().await;

    // No Origin header.
    let res = app
        .server
        .post("/api/signup/start")
        .json(&json!({ "email": "x@example.com" }))
        .await;
    res.assert_status(StatusCode::FORBIDDEN);

    // Wrong Origin.
    let res = app
        .server
        .post("/api/signup/start")
        .add_header("origin", "https://evil.example.com")
        .json(&json!({ "email": "x@example.com" }))
        .await;
    res.assert_status(StatusCode::FORBIDDEN);

    // GETs are exempt.
    app.server
        .get("/api/healthz")
        .await
        .assert_status(StatusCode::OK);
}
