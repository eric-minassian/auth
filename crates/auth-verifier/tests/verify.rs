#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use auth_core::b64;
use auth_core::decide::{ACCESS_TOKEN_TTL, STEP_UP_MAX_AGE};
use auth_core::jose::{self, AccessTokenClaims, Cnf};
use auth_core::testing::{DpopKey, LocalSigner, ProofParams};
use auth_verifier::extract::Authenticated;
use auth_verifier::{
    BoxFuture, DpopPolicy, InMemoryReplayCache, PolicyError, RequestParts, Verifier,
    VerifierConfig, VerifyError,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use std::sync::Arc;
use tower::ServiceExt;

const ISS: &str = "https://auth.example.com";
const AUD: &str = "https://api.example.com";
const BASE: &str = "https://api.example.com";
const NOW: u64 = 1_763_000_000;

struct Fixture {
    signer: LocalSigner,
    key: DpopKey,
}

impl Fixture {
    fn new() -> Self {
        Self {
            signer: LocalSigner::generate(),
            key: DpopKey::generate(),
        }
    }

    fn jwks(&self) -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({"keys": [jose::public_jwk(&self.signer.x, &self.signer.y)]}),
        )
        .unwrap()
    }

    fn verifier(&self) -> Verifier {
        Verifier::with_static_jwks(VerifierConfig::new(ISS, AUD, BASE), &self.jwks()).unwrap()
    }

    fn token(&self, iat: u64, auth_time: u64) -> String {
        self.signer.sign(
            jose::TYP_ACCESS,
            &AccessTokenClaims {
                iss: ISS.into(),
                sub: "acct_1".into(),
                aud: AUD.into(),
                client_id: "web".into(),
                iat,
                exp: iat + ACCESS_TOKEN_TTL,
                jti: b64::encode(&[9; 16]),
                auth_time,
                amr: vec!["pop".into(), "mfa".into()],
                cnf: Cnf {
                    jkt: self.key.jkt(),
                },
                sid: b64::encode(&[1; 16]),
                cid: b64::encode(b"passkey"),
                epoch: 7,
            },
        )
    }

    fn proof(
        &self,
        method: &str,
        path: &str,
        token: &str,
        iat: u64,
        nonce: Option<&str>,
    ) -> String {
        self.key.proof(&ProofParams {
            htm: method.into(),
            htu: format!("{BASE}{path}"),
            iat,
            jti: None,
            nonce: nonce.map(Into::into),
            access_token: Some(token.into()),
        })
    }
}

fn parts<'a>(method: &'a str, path: &'a str, auth: &'a str, dpop: &'a str) -> RequestParts<'a> {
    RequestParts {
        method,
        path,
        authorization: Some(auth),
        dpop: Some(dpop),
    }
}

#[tokio::test]
async fn accepts_a_valid_request() {
    let f = Fixture::new();
    let token = f.token(NOW, NOW - 30);
    let proof = f.proof("GET", "/v1/things", &token, NOW, None);
    let auth = format!("DPoP {token}");
    let id = f
        .verifier()
        .verify_at(&parts("GET", "/v1/things", &auth, &proof), NOW)
        .await
        .unwrap();
    assert_eq!(id.subject, "acct_1");
    assert_eq!(id.client_id, "web");
    assert_eq!(id.key_thumbprint, f.key.jkt());
    assert_eq!(id.expires_at, NOW + ACCESS_TOKEN_TTL);
    assert_eq!(
        id.session,
        Some(auth_verifier::SessionRef {
            credential_id: b64::encode(b"passkey"),
            epoch: 7
        })
    );
    assert!(id.require_recent_authentication(NOW).is_ok());
    assert_eq!(
        id.require_recent_authentication(NOW - 30 + STEP_UP_MAX_AGE + 1),
        Err(VerifyError::InsufficientUserAuthentication)
    );
}

#[tokio::test]
async fn rejections_map_to_the_right_error_codes() {
    let f = Fixture::new();
    let v = f.verifier();
    let token = f.token(NOW, NOW);
    let auth = format!("DPoP {token}");
    let proof = f.proof("GET", "/v1/things", &token, NOW, None);

    let bearer = format!("Bearer {token}");
    let e = v
        .verify_at(&parts("GET", "/v1/things", &bearer, &proof), NOW)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_token");

    let e = v
        .verify_at(&parts("POST", "/v1/things", &auth, &proof), NOW)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_dpop_proof");
    let e = v
        .verify_at(&parts("GET", "/v1/other", &auth, &proof), NOW)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_dpop_proof");

    let e = v
        .verify_at(
            &parts("GET", "/v1/things", &auth, &proof),
            NOW + ACCESS_TOKEN_TTL,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_token");

    let missing = RequestParts {
        method: "GET",
        path: "/v1/things",
        authorization: Some(&auth),
        dpop: None,
    };
    assert_eq!(
        v.verify_at(&missing, NOW).await.unwrap_err().code(),
        "invalid_dpop_proof"
    );

    // Token signed by a key that is not in the JWKS.
    let other = Fixture {
        signer: LocalSigner::generate(),
        key: DpopKey::generate(),
    };
    let foreign = other.token(NOW, NOW);
    let foreign_auth = format!("DPoP {foreign}");
    let foreign_proof = other.proof("GET", "/v1/things", &foreign, NOW, None);
    let e = v
        .verify_at(
            &parts("GET", "/v1/things", &foreign_auth, &foreign_proof),
            NOW,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_token");

    let challenge = e.www_authenticate().unwrap();
    assert!(
        challenge.starts_with("DPoP error=\"invalid_token\""),
        "{challenge}"
    );
    assert!(challenge.contains("algs=\"ES256\""));
}

#[tokio::test]
async fn replayed_proofs_are_rejected_with_a_replay_cache() {
    let f = Fixture::new();
    let v = f
        .verifier()
        .with_policy(Arc::new(InMemoryReplayCache::new(130, 10_000)));
    let token = f.token(NOW, NOW);
    let auth = format!("DPoP {token}");
    let proof = f.proof("GET", "/v1/things", &token, NOW, None);
    assert!(
        v.verify_at(&parts("GET", "/v1/things", &auth, &proof), NOW)
            .await
            .is_ok()
    );
    let e = v
        .verify_at(&parts("GET", "/v1/things", &auth, &proof), NOW + 1)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "invalid_dpop_proof");
}

#[derive(Debug)]
struct NoncePolicy;

impl DpopPolicy for NoncePolicy {
    fn valid_nonces(&self, _now: u64) -> BoxFuture<'_, Result<Option<Vec<Vec<u8>>>, PolicyError>> {
        Box::pin(async { Ok(Some(vec![b"good-nonce".to_vec()])) })
    }
    fn fresh_nonce(&self, _now: u64) -> BoxFuture<'_, Result<Option<String>, PolicyError>> {
        Box::pin(async { Ok(Some("good-nonce".into())) })
    }
    fn record_jti<'a>(
        &'a self,
        _: &'a [u8],
        _: &'a [u8],
        _: u64,
    ) -> BoxFuture<'a, Result<bool, PolicyError>> {
        Box::pin(async { Ok(true) })
    }
}

#[tokio::test]
async fn nonce_policy_asks_for_a_nonce() {
    let f = Fixture::new();
    let v = f.verifier().with_policy(Arc::new(NoncePolicy));
    let token = f.token(NOW, NOW);
    let auth = format!("DPoP {token}");
    let e = v
        .verify_at(
            &parts(
                "GET",
                "/v1/things",
                &auth,
                &f.proof("GET", "/v1/things", &token, NOW, None),
            ),
            NOW,
        )
        .await
        .unwrap_err();
    assert_eq!(
        e,
        VerifyError::UseDpopNonce {
            nonce: Some("good-nonce".into())
        }
    );
    assert_eq!(e.dpop_nonce(), Some("good-nonce"));
    let ok = f.proof("GET", "/v1/things", &token, NOW, Some("good-nonce"));
    assert!(
        v.verify_at(&parts("GET", "/v1/things", &auth, &ok), NOW)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn axum_extractor_end_to_end() {
    let f = Fixture::new();
    let verifier = Arc::new(f.verifier());
    let app = Router::new()
        .route(
            "/v1/me",
            get(|Authenticated(id): Authenticated| async move { id.subject }),
        )
        .with_state(verifier);

    // The extractor uses the real clock, so mint fresh credentials.
    let now = auth_verifier::unix_now();
    let token = f.token(now, now);
    let proof = f.proof("GET", "/v1/me", &token, now, None);
    let resp = app
        .clone()
        .oneshot(
            Request::get("/v1/me")
                .header("authorization", format!("DPoP {token}"))
                .header("dpop", &proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"acct_1");

    // Two DPoP headers are rejected (RFC 9449 §4.3).
    let resp = app
        .clone()
        .oneshot(
            Request::get("/v1/me")
                .header("authorization", format!("DPoP {token}"))
                .header("dpop", &proof)
                .header("dpop", &proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(www.contains("invalid_dpop_proof"));
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");

    // No credentials at all.
    let resp = app
        .oneshot(Request::get("/v1/me").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
