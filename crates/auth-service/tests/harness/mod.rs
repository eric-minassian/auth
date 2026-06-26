//! Integration-test harness: real router + real DynamoDB (testcontainers
//! DynamoDB Local) + in-process signer.
//!
//! Each integration-test binary compiles this module independently, so some
//! helpers are unused in some binaries; panicking helpers are idiomatic here.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::panic)]

pub mod flows;

use auth_service::config::AppConfig;
use auth_service::domain::session::SessionLevel;
use auth_service::jwt::{LocalSigner, Signer};
use auth_service::state::AppState;
use auth_service::store::{Store, schema};
use axum::http::StatusCode;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::dynamodb_local::DynamoDb;
use uuid::Uuid;

// Plain `localhost`: webauthn-authenticator-rs only permits http origins for
// the literal localhost domain (browsers are more lenient with *.localhost).
pub const ISSUER: &str = "http://localhost";

pub struct TestApp {
    pub server: TestServer,
    pub store: Store,
    pub signer: LocalSigner,
    // Held so the container outlives the test.
    _container: ContainerAsync<DynamoDb>,
}

impl TestApp {
    pub async fn spawn() -> TestApp {
        let container = DynamoDb::default()
            .start()
            .await
            .expect("start dynamodb-local container (is Docker running?)");
        let port = container
            .get_host_port_ipv4(8000)
            .await
            .expect("container port");

        let aws = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
            .load()
            .await;
        let db = aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::config::Builder::from(&aws)
                .endpoint_url(format!("http://127.0.0.1:{port}"))
                .build(),
        );
        let table = "auth-test";
        schema::create_table_if_missing(&db, table)
            .await
            .expect("create table");
        let store = Store::new(db, table);

        let cfg =
            AppConfig::build(ISSUER.to_string(), table.to_string(), None).expect("test config");
        let signer = LocalSigner::generate();
        let state =
            AppState::new(cfg, store.clone(), Signer::Local(signer.clone())).expect("app state");

        let server = TestServer::builder()
            .save_cookies()
            .build(auth_service::build_router(state));

        TestApp {
            server,
            store,
            signer,
            _container: container,
        }
    }

    /// Register an OIDC client for tests.
    pub async fn seed_client(&self, client: &auth_service::domain::oauth::OidcClient) {
        self.store.put_client(client).await.expect("seed client");
    }

    /// Mint a full (webauthn) session for `user_id` and install its cookie.
    ///
    /// The discoverable login *ceremony* can't be driven by the Rust soft
    /// authenticator — webauthn-authenticator-rs's `SoftPasskey`/`SoftToken`
    /// reject resident keys, so they can't emulate a discoverable credential.
    /// That ceremony is covered by the Playwright e2e (CDP virtual
    /// authenticator, which supports resident keys); Rust tests use this to
    /// reach an authenticated state for the rest of the API surface.
    pub async fn login_as(&mut self, user_id: Uuid) {
        let (sid, _session) = self
            .store
            .create_session(
                user_id,
                SessionLevel::Full,
                vec!["webauthn".to_string()],
                None,
                None,
            )
            .await
            .expect("create full session");
        self.server.add_cookie(Cookie::new("auth_session", sid));
    }

    /// POST JSON with the same-origin headers the CSRF middleware requires.
    pub fn post(&self, path: &str, body: &serde_json::Value) -> axum_test::TestRequest {
        self.server
            .post(path)
            .add_header("origin", ISSUER)
            .add_header("sec-fetch-site", "same-origin")
            .json(body)
    }

    /// Fetch a signup proof-of-work challenge and solve it. Returns
    /// `(challenge, nonce)` to pass to `/api/signup/start`.
    pub async fn solve_signup_pow(&self) -> (String, String) {
        let res = self.server.get("/api/signup/pow").await;
        res.assert_status(StatusCode::OK);
        let body: serde_json::Value = res.json();
        let challenge = body["challenge"].as_str().expect("challenge").to_string();
        let difficulty = body["difficulty"].as_u64().expect("difficulty") as u32;
        let mut nonce: u64 = 0;
        loop {
            let candidate = nonce.to_string();
            if auth_service::crypto::verify_pow(&challenge, &candidate, difficulty) {
                return (challenge, candidate);
            }
            nonce += 1;
        }
    }
}
