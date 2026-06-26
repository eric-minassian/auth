mod harness;

use axum::http::StatusCode;
use harness::TestApp;
use harness::flows::{new_authenticator, register_new_account};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn signup_end_to_end() {
    let mut app = TestApp::spawn().await;
    let mut authenticator = new_authenticator();

    // proof-of-work → pending account → first passkey → active account.
    let user_id = register_new_account(&mut app, "Eric", &mut authenticator).await;

    let uid = Uuid::parse_str(&user_id).expect("uuid");
    let user = app
        .store
        .get_user(uid)
        .await
        .expect("store reachable")
        .expect("user created");
    assert!(user.is_active(), "account should be active after finish");
    assert_eq!(user.nickname, "Eric");

    // Enroll session alone is not enough for whoami (needs a passkey login).
    app.server
        .get("/api/session")
        .await
        .assert_status(StatusCode::FORBIDDEN);

    // Establish a full session (the discoverable login ceremony itself is
    // covered by the Playwright e2e — see TestApp::login_as).
    app.login_as(uid).await;
    let res = app.server.get("/api/session").await;
    res.assert_status(StatusCode::OK);
    let body: serde_json::Value = res.json();
    assert_eq!(body["user"]["nickname"], "Eric");
}

#[tokio::test]
async fn signup_rejects_bad_proof_of_work() {
    let app = TestApp::spawn().await;

    // A challenge that was never issued.
    let res = app
        .post(
            "/api/signup/start",
            &json!({ "nickname": "x", "pow_challenge": "never-issued", "pow_nonce": "0" }),
        )
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);

    // A real challenge but a nonce that doesn't meet the difficulty.
    let body: serde_json::Value = app.server.get("/api/signup/pow").await.json();
    let challenge = body["challenge"].as_str().expect("challenge").to_string();
    let res = app
        .post(
            "/api/signup/start",
            &json!({ "nickname": "x", "pow_challenge": challenge, "pow_nonce": "not-a-solution" }),
        )
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pow_challenge_is_single_use() {
    let app = TestApp::spawn().await;
    let (challenge, nonce) = app.solve_signup_pow().await;

    // First use starts a ceremony.
    app.post(
        "/api/signup/start",
        &json!({ "nickname": "Once", "pow_challenge": challenge.clone(), "pow_nonce": nonce.clone() }),
    )
    .await
    .assert_status(StatusCode::OK);

    // Reusing the same solved challenge fails — it was consumed.
    app.post(
        "/api/signup/start",
        &json!({ "nickname": "Twice", "pow_challenge": challenge, "pow_nonce": nonce }),
    )
    .await
    .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn csrf_rejects_cross_origin_posts() {
    let app = TestApp::spawn().await;
    let body = json!({ "nickname": "x", "pow_challenge": "c", "pow_nonce": "0" });

    // No Origin header.
    app.server
        .post("/api/signup/start")
        .json(&body)
        .await
        .assert_status(StatusCode::FORBIDDEN);

    // Wrong Origin.
    app.server
        .post("/api/signup/start")
        .add_header("origin", "https://evil.example.com")
        .json(&body)
        .await
        .assert_status(StatusCode::FORBIDDEN);

    // GETs are exempt.
    app.server
        .get("/api/healthz")
        .await
        .assert_status(StatusCode::OK);
}
