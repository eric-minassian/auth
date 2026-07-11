//! DPoP (RFC 9449) sender-constraining end-to-end: a token request that carries
//! a proof binds the issued tokens to that key, and the resulting refresh /
//! access tokens are useless without it.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod harness;

use auth_service::crypto::{b64u, b64u_decode, random_b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use axum::http::StatusCode;
use harness::TestApp;
use harness::flows;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rand::Rng;
use url::Url;

const RP_CALLBACK: &str = "http://rp.example.com/callback";

fn rp_client() -> OidcClient {
    OidcClient {
        client_id: "rp".to_string(),
        client_name: "Test RP".to_string(),
        redirect_uris: vec![RP_CALLBACK.to_string()],
        post_logout_redirect_uris: vec![],
        backchannel_logout_uri: None,
        allowed_origins: vec![],
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "offline_access".to_string(),
        ],
        require_dpop: false,
    }
}

/// A throwaway DPoP proof key.
struct DpopKey {
    key: SigningKey,
    x: String,
    y: String,
}

impl DpopKey {
    fn new() -> Self {
        let key = loop {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            if let Ok(k) = SigningKey::from_slice(&bytes) {
                break k;
            }
        };
        let point = key.verifying_key().to_encoded_point(false);
        let x = b64u(point.x().map(|x| x.to_vec()).unwrap_or_default());
        let y = b64u(point.y().map(|y| y.to_vec()).unwrap_or_default());
        Self { key, x, y }
    }

    fn proof(&self, htm: &str, htu: &str, ath: Option<&str>) -> String {
        self.proof_with_nonce(htm, htu, ath, None)
    }

    fn proof_with_nonce(
        &self,
        htm: &str,
        htu: &str,
        ath: Option<&str>,
        nonce: Option<&str>,
    ) -> String {
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": self.x, "y": self.y },
        });
        let mut payload = serde_json::json!({
            "jti": random_b64u(16),
            "htm": htm,
            "htu": htu,
            "iat": now(),
        });
        if let Some(ath) = ath {
            payload["ath"] = serde_json::json!(ath);
        }
        if let Some(nonce) = nonce {
            payload["nonce"] = serde_json::json!(nonce);
        }
        let signing_input = format!(
            "{}.{}",
            b64u(serde_json::to_vec(&header).unwrap()),
            b64u(serde_json::to_vec(&payload).unwrap())
        );
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let sig = sig.normalize_s().unwrap_or(sig);
        format!("{signing_input}.{}", b64u(sig.to_bytes()))
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jwt_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).expect("payload segment");
    serde_json::from_slice(&b64u_decode(payload).expect("b64")).expect("json")
}

/// Harvest the current server nonce via the RFC 9449 §8 challenge: any token
/// request whose proof lacks the nonce is answered with `use_dpop_nonce` and
/// a `DPoP-Nonce` header, before the grant itself is touched.
async fn fetch_dpop_nonce(app: &TestApp, dpop: &DpopKey, token_htu: &str) -> String {
    let res = app
        .server
        .post("/oauth/token")
        .add_header("dpop", dpop.proof("POST", token_htu, None))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "rt_probe.probe"),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json();
    assert_eq!(body["error"], "use_dpop_nonce");
    res.header("dpop-nonce")
        .to_str()
        .expect("nonce header")
        .to_string()
}

async fn code_for(app: &TestApp, verifier: &str) -> String {
    let challenge = sha256_b64u(verifier);
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid profile offline_access")
        .add_query_param("code_challenge", &challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    let url = Url::parse(res.header("location").to_str().unwrap()).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("code")
}

#[tokio::test]
async fn dpop_binds_refresh_and_userinfo_to_the_proof_key() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authn = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "dpop@example.com", &mut authn).await;

    let dpop = DpopKey::new();
    let token_htu = format!("{}/oauth/token", harness::ISSUER);
    let userinfo_htu = format!("{}/oauth/userinfo", harness::ISSUER);
    let nonce = fetch_dpop_nonce(&app, &dpop, &token_htu).await;

    // Exchange the code WITH a DPoP proof → sender-constrained tokens.
    let verifier = random_b64u(32);
    let code = code_for(&app, &verifier).await;
    let res = app
        .server
        .post("/oauth/token")
        .add_header(
            "dpop",
            dpop.proof_with_nonce("POST", &token_htu, None, Some(&nonce)),
        )
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", RP_CALLBACK),
            ("client_id", "rp"),
            ("code_verifier", verifier.as_str()),
        ])
        .await;
    res.assert_status(StatusCode::OK);
    let tokens: serde_json::Value = res.json();
    assert_eq!(tokens["token_type"], "DPoP", "token is sender-constrained");
    let access_token = tokens["access_token"].as_str().unwrap().to_string();
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_string();

    // The access token carries the cnf.jkt confirmation claim.
    let claims = jwt_claims(&access_token);
    let jkt = sha256_b64u(format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        dpop.x, dpop.y
    ));
    assert_eq!(claims["cnf"]["jkt"], jkt);

    // userinfo with the bound token but NO proof → 401.
    let res = app
        .server
        .get("/oauth/userinfo")
        .add_header("authorization", format!("Bearer {access_token}"))
        .await;
    res.assert_status(StatusCode::UNAUTHORIZED);

    // userinfo with a matching proof (correct ath) → 200.
    let ath = sha256_b64u(&access_token);
    let res = app
        .server
        .get("/oauth/userinfo")
        .add_header("authorization", format!("DPoP {access_token}"))
        .add_header("dpop", dpop.proof("GET", &userinfo_htu, Some(&ath)))
        .await;
    res.assert_status(StatusCode::OK);

    // Refresh WITHOUT a proof → rejected, and the token is NOT consumed
    // (a key-less holder can't rotate-and-discard to lock out the real client).
    let res = app
        .server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);

    // Refresh WITH a fresh proof from the same key → works.
    let res = app
        .server
        .post("/oauth/token")
        .add_header(
            "dpop",
            dpop.proof_with_nonce("POST", &token_htu, None, Some(&nonce)),
        )
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::OK);
    let rotated: serde_json::Value = res.json();
    let refresh2 = rotated["refresh_token"].as_str().unwrap().to_string();

    // Refresh with an ATTACKER's key (stolen refresh token, no DPoP key) →
    // rejected, leaving the legitimate token usable.
    let attacker = DpopKey::new();
    let res = app
        .server
        .post("/oauth/token")
        .add_header(
            "dpop",
            attacker.proof_with_nonce("POST", &token_htu, None, Some(&nonce)),
        )
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh2.as_str()),
            ("client_id", "rp"),
        ])
        .await;
    res.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn require_dpop_client_rejects_a_bearer_token_request() {
    let mut app = TestApp::spawn().await;
    // A client identical to rp but with DPoP required.
    let mut client = rp_client();
    client.client_id = "rp-dpop".to_string();
    client.require_dpop = true;
    app.seed_client(&client).await;
    let mut authn = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "require-dpop@example.com", &mut authn).await;

    let token_htu = format!("{}/oauth/token", harness::ISSUER);
    let verifier = random_b64u(32);
    let challenge = sha256_b64u(&verifier);
    let res = app
        .server
        .get("/oauth/authorize")
        .add_query_param("response_type", "code")
        .add_query_param("client_id", "rp-dpop")
        .add_query_param("redirect_uri", RP_CALLBACK)
        .add_query_param("scope", "openid")
        .add_query_param("code_challenge", &challenge)
        .add_query_param("code_challenge_method", "S256")
        .await;
    let url = Url::parse(res.header("location").to_str().unwrap()).unwrap();
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("code");

    let exchange = |dpop: Option<String>| {
        let mut req = app.server.post("/oauth/token");
        if let Some(proof) = dpop {
            req = req.add_header("dpop", proof);
        }
        req.form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", RP_CALLBACK),
            ("client_id", "rp-dpop"),
            ("code_verifier", verifier.as_str()),
        ])
    };

    // No proof → rejected BEFORE the code is consumed (the require check runs
    // ahead of code exchange).
    let res = exchange(None).await;
    res.assert_status(StatusCode::BAD_REQUEST);
    let err: serde_json::Value = res.json();
    assert_eq!(err["error"], "invalid_dpop_proof");

    // The same code, now WITH a proof, succeeds — proving it wasn't consumed.
    // (A nonce-less proof is first challenged, again without consuming the code.)
    let dpop = DpopKey::new();
    let res = exchange(Some(dpop.proof("POST", &token_htu, None))).await;
    res.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(res.json::<serde_json::Value>()["error"], "use_dpop_nonce");
    let nonce = res
        .header("dpop-nonce")
        .to_str()
        .expect("nonce")
        .to_string();
    let res = exchange(Some(dpop.proof_with_nonce(
        "POST",
        &token_htu,
        None,
        Some(&nonce),
    )))
    .await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<serde_json::Value>()["token_type"], "DPoP");
}

#[tokio::test]
async fn token_request_replaying_a_dpop_proof_is_rejected() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authn = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "replay-dpop@example.com", &mut authn).await;

    let dpop = DpopKey::new();
    let token_htu = format!("{}/oauth/token", harness::ISSUER);
    let nonce = fetch_dpop_nonce(&app, &dpop, &token_htu).await;
    let proof = dpop.proof_with_nonce("POST", &token_htu, None, Some(&nonce));

    let verifier = random_b64u(32);
    let code = code_for(&app, &verifier).await;
    let exchange = |proof: String, code: String, verifier: String| {
        app.server
            .post("/oauth/token")
            .add_header("dpop", proof)
            .form(&[
                ("grant_type", "authorization_code".to_string()),
                ("code", code),
                ("redirect_uri", RP_CALLBACK.to_string()),
                ("client_id", "rp".to_string()),
                ("code_verifier", verifier),
            ])
    };

    // First use of the proof succeeds.
    let res = exchange(proof.clone(), code, verifier.clone()).await;
    res.assert_status(StatusCode::OK);

    // Reusing the SAME proof (jti) on a new code is a replay → rejected, even
    // though the rest of the request is valid.
    let verifier2 = random_b64u(32);
    let code2 = code_for(&app, &verifier2).await;
    let res = exchange(proof, code2, verifier2).await;
    res.assert_status(StatusCode::BAD_REQUEST);
    let err: serde_json::Value = res.json();
    assert_eq!(err["error"], "invalid_dpop_proof");
}

#[tokio::test]
async fn token_endpoint_challenges_for_and_accepts_the_server_nonce() {
    let mut app = TestApp::spawn().await;
    app.seed_client(&rp_client()).await;
    let mut authn = flows::new_authenticator();
    flows::signup_with_passkey(&mut app, "nonce-dpop@example.com", &mut authn).await;

    let dpop = DpopKey::new();
    let token_htu = format!("{}/oauth/token", harness::ISSUER);

    let verifier = random_b64u(32);
    let code = code_for(&app, &verifier).await;
    let exchange = |proof: String| {
        app.server
            .post("/oauth/token")
            .add_header("dpop", proof)
            .form(&[
                ("grant_type", "authorization_code".to_string()),
                ("code", code.clone()),
                ("redirect_uri", RP_CALLBACK.to_string()),
                ("client_id", "rp".to_string()),
                ("code_verifier", verifier.clone()),
            ])
    };

    // A proof without the server nonce is challenged (RFC 9449 §8) and the
    // code is NOT consumed.
    let res = exchange(dpop.proof("POST", &token_htu, None)).await;
    res.assert_status(StatusCode::BAD_REQUEST);
    let body: serde_json::Value = res.json();
    assert_eq!(body["error"], "use_dpop_nonce");
    let nonce = res
        .header("dpop-nonce")
        .to_str()
        .expect("nonce")
        .to_string();

    // A proof with a bogus nonce is challenged again.
    let res = exchange(dpop.proof_with_nonce("POST", &token_htu, None, Some("bogus"))).await;
    res.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(res.json::<serde_json::Value>()["error"], "use_dpop_nonce");

    // Echoing the challenged nonce succeeds with the same code.
    let res = exchange(dpop.proof_with_nonce("POST", &token_htu, None, Some(&nonce))).await;
    res.assert_status(StatusCode::OK);
    assert_eq!(res.json::<serde_json::Value>()["token_type"], "DPoP");
}
