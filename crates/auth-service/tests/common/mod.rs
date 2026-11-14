//! Test harness: a real `AppState` backed by DynamoDB and KMS in
//! aws-emulator (<https://github.com/aws/aws-emulator>), a controllable clock,
//! and a client that speaks the protocol with a software passkey and a DPoP
//! key, exactly like the SDKs do.
//!
//! Tests are skipped when `AWS_ENDPOINT_URL` is not set, unless
//! `AUTH_REQUIRE_EMULATOR=1` (as in CI), in which case they fail.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::struct_field_names
)]

use auth_core::b64;
use auth_core::testing::{DpopKey, ProofParams, SoftAuthenticator, random_bytes};
use auth_service::clock::Clock;
use auth_service::config::Config;
use auth_service::{AppState, router};
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType, TableStatus,
    TimeToLiveSpecification,
};
use aws_sdk_kms::types::{KeySpec, KeyUsageType};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

pub const ISSUER: &str = "https://auth.test.example";
pub const RP_ID: &str = "test.example";
pub const ORIGIN: &str = "https://app.test.example";
pub const API: &str = "https://api.test.example";

/// A clock tests can move forward.
#[derive(Debug)]
pub struct TestClock(AtomicU64);

impl TestClock {
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct Env {
    pub state: AppState,
    pub app: Router,
    pub clock: Arc<TestClock>,
}

async fn create_table(client: &aws_sdk_dynamodb::Client, name: &str) {
    client
        .create_table()
        .table_name(name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("pk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("sk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("pk")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("sk")
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create table");
    for _ in 0..100 {
        let d = client
            .describe_table()
            .table_name(name)
            .send()
            .await
            .expect("describe table");
        if d.table().and_then(|t| t.table_status()) == Some(&TableStatus::Active) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    client
        .update_time_to_live()
        .table_name(name)
        .time_to_live_specification(
            TimeToLiveSpecification::builder()
                .attribute_name("ttl")
                .enabled(true)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("enable TTL");
}

async fn create_key(client: &aws_sdk_kms::Client, spec: KeySpec, usage: KeyUsageType) -> String {
    client
        .create_key()
        .key_spec(spec)
        .key_usage(usage)
        .description("auth-service test key")
        .send()
        .await
        .expect("create key")
        .key_metadata()
        .expect("metadata")
        .key_id()
        .to_string()
}

/// Sets up a fresh table and keys. Returns `None` (skip) if no emulator is
/// configured and the emulator is not required.
pub async fn setup() -> Option<Env> {
    if std::env::var_os("AWS_ENDPOINT_URL").is_none() {
        assert!(
            std::env::var_os("AUTH_REQUIRE_EMULATOR").is_none(),
            "AUTH_REQUIRE_EMULATOR is set but AWS_ENDPOINT_URL is not; run scripts/emulator.sh"
        );
        eprintln!("skipping: AWS_ENDPOINT_URL not set (see scripts/emulator.sh)");
        return None;
    }
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let dynamo = aws_sdk_dynamodb::Client::new(&sdk);
    let kms = aws_sdk_kms::Client::new(&sdk);
    let table = format!(
        "auth-test-{}",
        b64::encode(&random_bytes(9)).replace(['-', '_'], "x")
    );
    create_table(&dynamo, &table).await;
    let access = create_key(&kms, KeySpec::EccNistP256, KeyUsageType::SignVerify).await;
    let refresh = create_key(&kms, KeySpec::EccNistP256, KeyUsageType::SignVerify).await;
    let nonce = create_key(&kms, KeySpec::Hmac256, KeyUsageType::GenerateVerifyMac).await;

    let vars = [
        ("AUTH_ISSUER", ISSUER.to_string()),
        ("AUTH_RP_ID", RP_ID.to_string()),
        ("AUTH_RP_NAME", "Test".to_string()),
        ("AUTH_ALLOWED_ORIGINS", ORIGIN.to_string()),
        ("AUTH_CORS_ORIGINS", ORIGIN.to_string()),
        ("AUTH_AUDIENCES", API.to_string()),
        ("AUTH_CLIENT_IDS", "web,cli".to_string()),
        ("AUTH_TABLE_NAME", table),
        ("AUTH_ACCESS_TOKEN_KEY_ID", access),
        ("AUTH_REFRESH_TOKEN_KEY_ID", refresh),
        ("AUTH_DPOP_NONCE_KEY_ID", nonce),
    ];
    let config = Config::from_lookup(
        |k| {
            vars.iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.clone())
        },
        false,
    )
    .expect("config");
    let clock = Arc::new(TestClock(AtomicU64::new(auth_verifier::unix_now())));
    let state = AppState::init(config, kms, dynamo, clock.clone())
        .await
        .expect("state");
    let app = router(state.clone());
    Some(Env { state, app, clock })
}

/// A response.
#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub json: Value,
}

impl Resp {
    pub fn error(&self) -> &str {
        self.json["error"].as_str().unwrap_or("")
    }
}

/// Tokens returned by the service.
#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

impl Tokens {
    fn from(json: &Value) -> Self {
        assert_eq!(json["token_type"], "DPoP", "{json}");
        Self {
            access_token: json["access_token"].as_str().expect("access_token").into(),
            refresh_token: json["refresh_token"]
                .as_str()
                .expect("refresh_token")
                .into(),
        }
    }
}

/// A protocol client: one device (DPoP key) talking to the service.
pub struct Client<'a> {
    pub env: &'a Env,
    pub key: DpopKey,
    pub nonce: Option<String>,
    pub client_id: String,
    /// Retry once on `use_dpop_nonce`, like the SDKs do.
    pub auto_retry_nonce: bool,
}

impl<'a> Client<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self {
            env,
            key: DpopKey::generate(),
            nonce: None,
            client_id: "web".into(),
            auto_retry_nonce: true,
        }
    }

    pub fn now(&self) -> u64 {
        self.env.clock.now()
    }

    pub fn proof(&self, method: &str, path: &str, access_token: Option<&str>) -> String {
        self.key.proof(&ProofParams {
            htm: method.into(),
            htu: format!("{ISSUER}{path}"),
            iat: self.now(),
            jti: None,
            nonce: self.nonce.clone(),
            access_token: access_token.map(Into::into),
        })
    }

    /// Sends a raw request.
    pub async fn send(&mut self, req: Request<Body>) -> Resp {
        let resp = self.env.app.clone().oneshot(req).await.expect("router");
        let status = resp.status();
        let headers = resp.headers().clone();
        if let Some(n) = headers.get("dpop-nonce").and_then(|v| v.to_str().ok()) {
            self.nonce = Some(n.to_string());
        }
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        let json = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or(Value::Null)
        };
        Resp {
            status,
            headers,
            json,
        }
    }

    /// POSTs JSON, with an optional DPoP proof and access token.
    pub async fn post(
        &mut self,
        path: &str,
        body: &Value,
        dpop: bool,
        access_token: Option<&str>,
    ) -> Resp {
        self.request(Method::POST, path, Some(body), dpop, access_token)
            .await
    }

    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        dpop: bool,
        access_token: Option<&str>,
    ) -> Resp {
        let build = |c: &Self| {
            let mut b = Request::builder().method(method.clone()).uri(path);
            if dpop {
                b = b.header("dpop", c.proof(method.as_str(), path, access_token));
            }
            if let Some(t) = access_token {
                b = b.header("authorization", format!("DPoP {t}"));
            }
            match body {
                Some(v) => b
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(v).unwrap())),
                None => b.body(Body::empty()),
            }
            .unwrap()
        };
        self.send_retrying(build).await
    }

    /// Sends a request built by `build`, rebuilding it (with a fresh proof)
    /// once if the server asks for a new nonce.
    pub async fn send_retrying(&mut self, build: impl Fn(&Self) -> Request<Body>) -> Resp {
        let r = self.send(build(self)).await;
        if self.auto_retry_nonce && r.error() == "use_dpop_nonce" {
            return self.send(build(self)).await;
        }
        r
    }

    /// Fetches a nonce (any response carries one).
    pub async fn prime_nonce(&mut self) {
        let r = self
            .request(
                Method::GET,
                "/.well-known/oauth-authorization-server",
                None,
                false,
                None,
            )
            .await;
        assert!(self.nonce.is_some(), "{r:?}");
    }

    /// Sign-up with a software passkey.
    pub async fn sign_up(&mut self, auth: &mut SoftAuthenticator) -> (Tokens, String, String) {
        let opts = self
            .post("/v1/register/options", &json!({}), true, None)
            .await;
        assert_eq!(opts.status, StatusCode::OK, "{opts:?}");
        let r = self
            .complete_registration(auth, &opts.json, "/v1/register/verify")
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{r:?}");
        (
            Tokens::from(&r.json),
            r.json["account_id"].as_str().unwrap().into(),
            r.json["recovery_code"].as_str().unwrap().into(),
        )
    }

    /// Runs `navigator.credentials.create` for options and posts the result.
    pub async fn complete_registration(
        &mut self,
        auth: &mut SoftAuthenticator,
        opts: &Value,
        path: &str,
    ) -> Resp {
        let pk = &opts["publicKey"];
        let challenge = b64::decode_str(pk["challenge"].as_str().unwrap()).unwrap();
        let user = b64::decode_str(pk["user"]["id"].as_str().unwrap()).unwrap();
        let cred = auth.register(pk["rp"]["id"].as_str().unwrap(), ORIGIN, &challenge, &user);
        let body = json!({ "client_id": self.client_id, "credential": cred });
        self.post(path, &body, true, None).await
    }

    /// Sign-in with a software passkey.
    pub async fn sign_in(&mut self, auth: &mut SoftAuthenticator) -> Resp {
        let opts = self.post("/v1/login/options", &json!({}), true, None).await;
        assert_eq!(opts.status, StatusCode::OK, "{opts:?}");
        let challenge =
            b64::decode_str(opts.json["publicKey"]["challenge"].as_str().unwrap()).unwrap();
        let cred = auth.authenticate(RP_ID, ORIGIN, &challenge);
        let body = json!({ "client_id": self.client_id, "credential": cred });
        self.post("/v1/login/verify", &body, true, None).await
    }

    pub async fn sign_in_ok(&mut self, auth: &mut SoftAuthenticator) -> Tokens {
        let r = self.sign_in(auth).await;
        assert_eq!(r.status, StatusCode::OK, "{r:?}");
        Tokens::from(&r.json)
    }

    /// Refreshes, optionally for a specific resource.
    pub async fn refresh(&mut self, refresh_token: &str, resource: Option<&str>) -> Resp {
        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", self.client_id.clone()),
        ];
        if let Some(r) = resource {
            form.push(("resource", r.to_string()));
        }
        let body = serde_urlencoded::to_string(&form).unwrap();
        self.send_retrying(|c| {
            Request::post("/v1/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("dpop", c.proof("POST", "/v1/token", None))
                .body(Body::from(body.clone()))
                .unwrap()
        })
        .await
    }

    pub async fn refresh_ok(&mut self, refresh_token: &str, resource: Option<&str>) -> Tokens {
        let r = self.refresh(refresh_token, resource).await;
        assert_eq!(r.status, StatusCode::OK, "{r:?}");
        Tokens::from(&r.json)
    }

    /// An access token for the account API (audience = issuer).
    pub async fn account_token(&mut self, tokens: &Tokens) -> String {
        self.refresh_ok(&tokens.refresh_token, Some(ISSUER))
            .await
            .access_token
    }
}

/// Decodes a JWT's claims without verifying (for assertions in tests).
pub fn claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&b64::decode_str(payload).unwrap()).unwrap()
}
