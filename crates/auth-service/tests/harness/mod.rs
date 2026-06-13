//! Integration-test harness: real router + real DynamoDB (testcontainers
//! DynamoDB Local) + in-process signer + channel-capturing mailer.
//!
//! Each integration-test binary compiles this module independently, so some
//! helpers are unused in some binaries; panicking helpers are idiomatic here.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used, clippy::panic)]

pub mod flows;

use auth_service::config::AppConfig;
use auth_service::email::{EmailMessage, Mailer};
use auth_service::jwt::{LocalSigner, Signer};
use auth_service::state::AppState;
use auth_service::store::{Store, schema};
use axum_test::TestServer;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::dynamodb_local::DynamoDb;
use tokio::sync::mpsc::UnboundedReceiver;

// Plain `localhost`: webauthn-authenticator-rs only permits http origins for
// the literal localhost domain (browsers are more lenient with *.localhost).
pub const ISSUER: &str = "http://localhost";

pub struct TestApp {
    pub server: TestServer,
    pub store: Store,
    pub signer: LocalSigner,
    emails: UnboundedReceiver<EmailMessage>,
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

        let cfg = AppConfig::build(ISSUER.to_string(), table.to_string(), false, None)
            .expect("test config");
        let signer = LocalSigner::generate();
        let (tx, emails) = tokio::sync::mpsc::unbounded_channel();
        let state = AppState::new(
            cfg,
            store.clone(),
            Signer::Local(signer.clone()),
            Mailer::Capture(tx),
        )
        .expect("app state");

        let server = TestServer::builder()
            .save_cookies()
            .build(auth_service::build_router(state));

        TestApp {
            server,
            store,
            signer,
            emails,
            _container: container,
        }
    }

    /// Register an OIDC client for tests.
    pub async fn seed_client(&self, client: &auth_service::domain::oauth::OidcClient) {
        self.store.put_client(client).await.expect("seed client");
    }

    /// POST JSON with the same-origin headers the CSRF middleware requires.
    pub fn post(&self, path: &str, body: &serde_json::Value) -> axum_test::TestRequest {
        self.server
            .post(path)
            .add_header("origin", ISSUER)
            .add_header("sec-fetch-site", "same-origin")
            .json(body)
    }

    /// Most recent captured email for `to`, if any.
    pub fn last_email_to(&mut self, to: &str) -> Option<EmailMessage> {
        let mut found = None;
        while let Ok(msg) = self.emails.try_recv() {
            if msg.to.eq_ignore_ascii_case(to) {
                found = Some(msg);
            }
        }
        found
    }

    /// Extract the 6-digit OTP from the most recent email to `to`.
    pub fn take_otp(&mut self, to: &str) -> String {
        let email = self.last_email_to(to).expect("an email should be sent");
        extract_otp(&email.text).expect("email should contain a 6-digit code")
    }
}

pub fn extract_otp(text: &str) -> Option<String> {
    text.split(|c: char| !c.is_ascii_digit())
        .find(|run| run.len() == 6)
        .map(str::to_string)
}
