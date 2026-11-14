//! End-to-end protocol tests against DynamoDB and KMS in aws-emulator.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use auth_core::b64;
use auth_core::decide::{
    ACCESS_TOKEN_TTL, CEREMONY_TTL, REFRESH_ABSOLUTE_TTL, REFRESH_IDLE_TTL, STEP_UP_MAX_AGE,
};
use auth_core::testing::{ProofParams, SoftAuthenticator};
use auth_verifier::{RequestParts, Verifier, VerifierConfig};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use common::{API, Client, ISSUER, ORIGIN, RP_ID, claims, setup};
use serde_json::json;

macro_rules! env_or_skip {
    () => {
        match setup().await {
            Some(e) => e,
            None => return,
        }
    };
}

#[tokio::test]
async fn discovery_documents() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    let meta = c
        .request(
            Method::GET,
            "/.well-known/oauth-authorization-server",
            None,
            false,
            None,
        )
        .await;
    assert_eq!(meta.status, StatusCode::OK);
    assert_eq!(meta.json["issuer"], ISSUER);
    assert_eq!(meta.json["token_endpoint"], format!("{ISSUER}/v1/token"));
    assert_eq!(
        meta.json["dpop_signing_alg_values_supported"],
        json!(["ES256"])
    );
    assert_eq!(meta.headers["cache-control"], "public, max-age=300");

    let jwks = c
        .request(Method::GET, "/.well-known/jwks.json", None, false, None)
        .await;
    let keys = auth_verifier::jwks::parse_jwks(&serde_json::to_vec(&jwks.json).unwrap()).unwrap();
    assert_eq!(keys.len(), 1, "only the access-token key is published");

    let missing = c.request(Method::GET, "/nope", None, false, None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.error(), "not_found");
}

#[tokio::test]
async fn every_response_has_security_headers_and_a_nonce() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    let r = c.post("/v1/login/options", &json!({}), true, None).await;
    for h in [
        "dpop-nonce",
        "date",
        "cache-control",
        "x-content-type-options",
        "referrer-policy",
        "content-security-policy",
    ] {
        assert!(r.headers.contains_key(h), "missing {h}");
    }
    assert_eq!(r.headers["cache-control"], "no-store");
    let opts = &r.json["publicKey"];
    assert_eq!(opts["rpId"], RP_ID);
    assert_eq!(opts["userVerification"], "required");
    assert_eq!(
        b64::decode_str(opts["challenge"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
}

#[tokio::test]
async fn sign_up_sign_in_refresh_and_use_tokens() {
    let env = env_or_skip!();
    let mut device = Client::new(&env);
    device.prime_nonce().await;
    let mut passkey = SoftAuthenticator::new();
    let (tokens, account_id, recovery_code) = device.sign_up(&mut passkey).await;
    assert_eq!(b64::decode_str(&account_id).unwrap().len(), 16);
    assert_eq!(recovery_code.len(), 39);

    // The access token is an RFC 9068 token bound to this device's key.
    let at = claims(&tokens.access_token);
    assert_eq!(at["iss"], ISSUER);
    assert_eq!(at["sub"], account_id);
    assert_eq!(at["aud"], API);
    assert_eq!(at["client_id"], "web");
    assert_eq!(at["cnf"]["jkt"], device.key.jkt());
    assert_eq!(at["amr"], json!(["pop", "mfa"]));
    assert_eq!(
        at["exp"].as_u64().unwrap() - at["iat"].as_u64().unwrap(),
        ACCESS_TOKEN_TTL
    );

    // A resource server verifies it with the published JWKS.
    let jwks = device
        .request(Method::GET, "/.well-known/jwks.json", None, false, None)
        .await;
    let verifier = Verifier::with_static_jwks(
        VerifierConfig::new(ISSUER, API, API),
        &serde_json::to_vec(&jwks.json).unwrap(),
    )
    .unwrap();
    let proof = device.key.proof(&ProofParams {
        htm: "GET".into(),
        htu: format!("{API}/v1/things"),
        iat: device.now(),
        access_token: Some(tokens.access_token.clone()),
        ..ProofParams::default()
    });
    let auth = format!("DPoP {}", tokens.access_token);
    let id = verifier
        .verify_at(
            &RequestParts {
                method: "GET",
                path: "/v1/things",
                authorization: Some(&auth),
                dpop: Some(&proof),
            },
            device.now(),
        )
        .await
        .unwrap();
    assert_eq!(id.subject, account_id);

    // Silent refresh keeps the session and its properties.
    env.clock.advance(ACCESS_TOKEN_TTL + 1);
    let refreshed = device.refresh_ok(&tokens.refresh_token, None).await;
    let rt0 = claims(&tokens.refresh_token);
    let rt1 = claims(&refreshed.refresh_token);
    assert_eq!(rt1["sid"], rt0["sid"]);
    assert_eq!(rt1["auth_time"], rt0["auth_time"]);
    assert_eq!(rt1["cid"], rt0["cid"]);
    assert!(rt1["exp"].as_u64() > rt0["exp"].as_u64(), "sliding expiry");

    // The account API.
    let account_token = device.account_token(&refreshed).await;
    let me = device
        .request(Method::GET, "/v1/account", None, true, Some(&account_token))
        .await;
    assert_eq!(me.status, StatusCode::OK, "{me:?}");
    assert_eq!(me.json["account_id"], account_id);
    assert_eq!(me.json["passkeys"].as_array().unwrap().len(), 1);
    assert_eq!(
        me.json["passkeys"][0]["credential_id"],
        b64::encode(&passkey.credential_id)
    );

    // Sign in on a second device with the same (synced) passkey.
    let mut laptop = Client::new(&env);
    laptop.prime_nonce().await;
    let t2 = laptop.sign_in_ok(&mut passkey).await;
    assert_eq!(claims(&t2.access_token)["sub"], account_id);
    assert_eq!(claims(&t2.access_token)["cnf"]["jkt"], laptop.key.jkt());
}

#[tokio::test]
async fn dpop_is_enforced_at_token_endpoints() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.auto_retry_nonce = false;
    let mut passkey = SoftAuthenticator::new();

    // Options requests need a proof too (they bind the ceremony to the key),
    // and without a nonce the server asks for one.
    let r = c
        .request(
            Method::POST,
            "/v1/register/options",
            Some(&json!({})),
            false,
            None,
        )
        .await;
    assert_eq!(r.error(), "invalid_dpop_proof");
    // Every response carries a fresh nonce; drop it to exercise the retry.
    c.nonce = None;
    let r = c.post("/v1/register/options", &json!({}), true, None).await;
    assert_eq!(r.error(), "use_dpop_nonce");
    let opts = c.post("/v1/register/options", &json!({}), true, None).await;
    assert_eq!(opts.status, StatusCode::OK, "{opts:?}");

    // No valid nonce at verify: the server asks for one and the client retries.
    c.nonce = None;
    let r = c
        .complete_registration(&mut passkey, &opts.json, "/v1/register/verify")
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error(), "use_dpop_nonce");
    assert!(c.nonce.is_some(), "the error carries a fresh nonce");

    // The challenge was not consumed by the nonce failure.
    let r = c
        .complete_registration(&mut passkey, &opts.json, "/v1/register/verify")
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{r:?}");
    let refresh_token = r.json["refresh_token"].as_str().unwrap().to_string();

    // A stolen refresh token is useless with another device key.
    let mut thief = Client::new(&env);
    thief.prime_nonce().await;
    let r = thief.refresh(&refresh_token, None).await;
    assert_eq!(r.error(), "invalid_grant");

    // A replayed proof is rejected.
    let proof = c.proof("POST", "/v1/token", None);
    let body = format!("grant_type=refresh_token&client_id=web&refresh_token={refresh_token}");
    let send = |p: String, b: String| {
        Request::post("/v1/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("dpop", p)
            .body(Body::from(b))
            .unwrap()
    };
    assert_eq!(
        c.send(send(proof.clone(), body.clone())).await.status,
        StatusCode::OK
    );
    let replay = c.send(send(proof, body.clone())).await;
    assert_eq!(replay.error(), "invalid_dpop_proof");

    // Missing proof, a proof for another URL, and a stale nonce.
    let none = c
        .send(
            Request::post("/v1/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await;
    assert_eq!(none.error(), "invalid_dpop_proof");
    let wrong_url = c.proof("POST", "/v1/login/verify", None);
    assert_eq!(
        c.send(send(wrong_url, body.clone())).await.error(),
        "invalid_dpop_proof"
    );
    let stale_nonce = c.nonce.clone();
    env.clock.advance(700);
    let stale = c.key.proof(&ProofParams {
        htm: "POST".into(),
        htu: format!("{ISSUER}/v1/token"),
        iat: c.now(),
        nonce: stale_nonce,
        ..ProofParams::default()
    });
    assert_eq!(c.send(send(stale, body)).await.error(), "use_dpop_nonce");
}

#[tokio::test]
async fn ceremonies_are_bound_to_the_requesting_device_key() {
    let env = env_or_skip!();
    let mut device = Client::new(&env);
    device.prime_nonce().await;
    let mut passkey = SoftAuthenticator::new();
    device.sign_up(&mut passkey).await;

    // The device starts a sign-in; an attacker who captures the passkey
    // response cannot redeem it with their own key.
    let opts = device
        .post("/v1/login/options", &json!({}), true, None)
        .await;
    let challenge = b64::decode_str(opts.json["publicKey"]["challenge"].as_str().unwrap()).unwrap();
    let captured = passkey.authenticate(RP_ID, ORIGIN, &challenge);
    let body = json!({ "client_id": "web", "credential": captured });
    let mut attacker = Client::new(&env);
    attacker.prime_nonce().await;
    let r = attacker.post("/v1/login/verify", &body, true, None).await;
    assert_eq!(r.error(), "invalid_grant", "{r:?}");

    // The same holds for sign-up: the registration is bound to the key that
    // asked for the options.
    let opts = device
        .post("/v1/register/options", &json!({}), true, None)
        .await;
    let mut other = SoftAuthenticator::new();
    let r = attacker
        .complete_registration(&mut other, &opts.json, "/v1/register/verify")
        .await;
    assert_eq!(r.error(), "invalid_grant", "{r:?}");
}

#[tokio::test]
async fn ceremonies_are_single_use_and_expire() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;
    let mut passkey = SoftAuthenticator::new();
    let opts = c.post("/v1/register/options", &json!({}), true, None).await;
    let pk = &opts.json["publicKey"];
    let challenge = b64::decode_str(pk["challenge"].as_str().unwrap()).unwrap();
    let user = b64::decode_str(pk["user"]["id"].as_str().unwrap()).unwrap();
    let cred = passkey.register(RP_ID, ORIGIN, &challenge, &user);
    let body = json!({ "client_id": "web", "credential": cred });
    assert_eq!(
        c.post("/v1/register/verify", &body, true, None)
            .await
            .status,
        StatusCode::CREATED
    );
    let again = c.post("/v1/register/verify", &body, true, None).await;
    assert_eq!(again.error(), "invalid_grant");

    // An expired sign-in challenge.
    let opts = c.post("/v1/login/options", &json!({}), true, None).await;
    let challenge = b64::decode_str(opts.json["publicKey"]["challenge"].as_str().unwrap()).unwrap();
    let assertion = passkey.authenticate(RP_ID, ORIGIN, &challenge);
    env.clock.advance(CEREMONY_TTL);
    c.prime_nonce().await;
    let r = c
        .post(
            "/v1/login/verify",
            &json!({ "client_id": "web", "credential": assertion }),
            true,
            None,
        )
        .await;
    assert_eq!(r.error(), "invalid_grant");

    // A sign-in challenge cannot complete a sign-up.
    let opts = c.post("/v1/login/options", &json!({}), true, None).await;
    let challenge = b64::decode_str(opts.json["publicKey"]["challenge"].as_str().unwrap()).unwrap();
    let mut other = SoftAuthenticator::new();
    let cred = other.register(RP_ID, ORIGIN, &challenge, &[1; 16]);
    let r = c
        .post(
            "/v1/register/verify",
            &json!({ "client_id": "web", "credential": cred }),
            true,
            None,
        )
        .await;
    assert_eq!(r.error(), "invalid_grant");
}

#[tokio::test]
async fn sign_in_rejections() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;

    // Unknown passkey: the client learns it should signal the authenticator.
    let mut stranger = SoftAuthenticator::new();
    stranger.user_handle = vec![5; 16];
    let r = c.sign_in(&mut stranger).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.error(), "unknown_credential");
    assert_eq!(
        r.json["credential_id"],
        b64::encode(&stranger.credential_id)
    );

    // Phishing: an assertion made on another origin is rejected.
    let mut passkey = SoftAuthenticator::new();
    c.sign_up(&mut passkey).await;
    let opts = c.post("/v1/login/options", &json!({}), true, None).await;
    let challenge = b64::decode_str(opts.json["publicKey"]["challenge"].as_str().unwrap()).unwrap();
    let phished = passkey.authenticate(RP_ID, "https://app.test.example.evil.com", &challenge);
    let r = c
        .post(
            "/v1/login/verify",
            &json!({ "client_id": "web", "credential": phished }),
            true,
            None,
        )
        .await;
    assert_eq!(r.error(), "webauthn_rejected");

    // Unknown client and disallowed resource.
    let r = c
        .post(
            "/v1/login/verify",
            &json!({ "client_id": "evil", "credential": phished }),
            true,
            None,
        )
        .await;
    assert_eq!(r.error(), "invalid_client");
    let r = c
        .post("/v1/login/verify", &json!({ "client_id": "web", "resource": "https://evil.example", "credential": phished }), true, None)
        .await;
    assert_eq!(r.error(), "invalid_target");
}

#[tokio::test]
async fn cloned_authenticator_is_detected() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;
    let mut key = SoftAuthenticator::new();
    key.counter = Some(0);
    key.backup_eligible = false;
    c.sign_up(&mut key).await;
    c.sign_in_ok(&mut key).await;
    // Roll the counter back, as a cloned authenticator would.
    key.counter = Some(0);
    let r = c.sign_in(&mut key).await;
    assert_eq!(r.error(), "webauthn_rejected");
}

#[tokio::test]
async fn sign_out_everywhere_revokes_refresh() {
    let env = env_or_skip!();
    let mut phone = Client::new(&env);
    phone.prime_nonce().await;
    let mut passkey = SoftAuthenticator::new();
    let (t_phone, _, _) = phone.sign_up(&mut passkey).await;
    let mut laptop = Client::new(&env);
    laptop.prime_nonce().await;
    let t_laptop = laptop.sign_in_ok(&mut passkey).await;

    let at = phone.account_token(&t_phone).await;
    let laptop_at = laptop.account_token(&t_laptop).await;
    let r = phone
        .request(
            Method::POST,
            "/v1/account/logout-all",
            None,
            true,
            Some(&at),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{r:?}");

    // Revocation is immediate at the account API, even though the laptop's
    // access token has not expired yet.
    let r = laptop
        .request(Method::GET, "/v1/account", None, true, Some(&laptop_at))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{r:?}");
    assert_eq!(r.error(), "invalid_token");

    assert_eq!(
        laptop.refresh(&t_laptop.refresh_token, None).await.error(),
        "invalid_grant"
    );
    assert_eq!(
        phone.refresh(&t_phone.refresh_token, None).await.error(),
        "invalid_grant"
    );

    // Signing in again starts a session in the new epoch.
    let fresh = laptop.sign_in_ok(&mut passkey).await;
    laptop.refresh_ok(&fresh.refresh_token, None).await;
}

#[tokio::test]
async fn passkey_management_with_step_up() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;
    let mut first = SoftAuthenticator::new();
    let (tokens, _, _) = c.sign_up(&mut first).await;
    let at = c.account_token(&tokens).await;

    // Add a second passkey (fresh sign-in, so step-up passes).
    let opts = c
        .post("/v1/account/passkeys/options", &json!({}), true, Some(&at))
        .await;
    assert_eq!(opts.status, StatusCode::OK, "{opts:?}");
    let excluded = &opts.json["publicKey"]["excludeCredentials"];
    assert_eq!(excluded[0]["id"], b64::encode(&first.credential_id));
    let mut second = SoftAuthenticator::new();
    let pk = &opts.json["publicKey"];
    let challenge = b64::decode_str(pk["challenge"].as_str().unwrap()).unwrap();
    let user = b64::decode_str(pk["user"]["id"].as_str().unwrap()).unwrap();
    let cred = second.register(RP_ID, ORIGIN, &challenge, &user);
    let added = c
        .post(
            "/v1/account/passkeys/verify",
            &json!({ "credential": cred }),
            true,
            Some(&at),
        )
        .await;
    assert_eq!(added.status, StatusCode::CREATED, "{added:?}");
    let second_session = {
        let mut other = Client::new(&env);
        other.prime_nonce().await;
        other.sign_in_ok(&mut second).await
    };

    // After STEP_UP_MAX_AGE, sensitive operations require a fresh sign-in.
    env.clock.advance(STEP_UP_MAX_AGE + 1);
    let at = c.account_token(&tokens).await;
    let path = format!(
        "/v1/account/passkeys/{}",
        b64::encode(&second.credential_id)
    );
    let r = c
        .request(Method::DELETE, &path, None, true, Some(&at))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let www = r.headers["www-authenticate"].to_str().unwrap();
    assert!(
        www.contains("insufficient_user_authentication") && www.contains("max_age=300"),
        "{www}"
    );

    // Step up, then remove the second passkey: its sessions die.
    let fresh = c.sign_in_ok(&mut first).await;
    let at = c.account_token(&fresh).await;
    let r = c
        .request(Method::DELETE, &path, None, true, Some(&at))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{r:?}");
    let mut other = Client::new(&env);
    other.key = auth_core::testing::DpopKey::generate();
    other.prime_nonce().await;
    assert_eq!(
        other
            .refresh(&second_session.refresh_token, None)
            .await
            .error(),
        "invalid_grant"
    );

    // The last passkey cannot be removed; unknown ones are 404.
    let last = format!("/v1/account/passkeys/{}", b64::encode(&first.credential_id));
    assert_eq!(
        c.request(Method::DELETE, &last, None, true, Some(&at))
            .await
            .error(),
        "last_passkey"
    );
    assert_eq!(
        c.request(Method::DELETE, &path, None, true, Some(&at))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn passkey_limit_is_enforced() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;
    let mut first = SoftAuthenticator::new();
    let (tokens, _, _) = c.sign_up(&mut first).await;
    let at = c.account_token(&tokens).await;
    for i in 1..=20 {
        let opts = c
            .post("/v1/account/passkeys/options", &json!({}), true, Some(&at))
            .await;
        let pk = &opts.json["publicKey"];
        let challenge = b64::decode_str(pk["challenge"].as_str().unwrap()).unwrap();
        let user = b64::decode_str(pk["user"]["id"].as_str().unwrap()).unwrap();
        let cred = SoftAuthenticator::new().register(RP_ID, ORIGIN, &challenge, &user);
        let r = c
            .post(
                "/v1/account/passkeys/verify",
                &json!({ "credential": cred }),
                true,
                Some(&at),
            )
            .await;
        if i < 20 {
            assert_eq!(r.status, StatusCode::CREATED, "passkey {i}: {r:?}");
        } else {
            assert_eq!(r.error(), "too_many_passkeys");
        }
    }
}

#[tokio::test]
async fn recovery_replaces_passkeys_and_revokes_sessions() {
    let env = env_or_skip!();
    let mut old_device = Client::new(&env);
    old_device.prime_nonce().await;
    let mut lost = SoftAuthenticator::new();
    let (old_tokens, account_id, code) = old_device.sign_up(&mut lost).await;
    let old_at = old_device.account_token(&old_tokens).await;

    // Recovery on a new device with a new passkey. Typed codes are normalized.
    let mut device = Client::new(&env);
    device.prime_nonce().await;
    let typed = code.to_lowercase().replace('-', " ");
    let opts = device
        .post(
            "/v1/recover/options",
            &json!({ "recovery_code": typed }),
            true,
            None,
        )
        .await;
    assert_eq!(opts.status, StatusCode::OK, "{opts:?}");
    let mut replacement = SoftAuthenticator::new();
    let r = device
        .complete_registration(&mut replacement, &opts.json, "/v1/recover/verify")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{r:?}");
    let new_code = r.json["recovery_code"].as_str().unwrap().to_string();
    assert_ne!(new_code, code);
    assert_eq!(
        claims(r.json["access_token"].as_str().unwrap())["sub"],
        account_id
    );

    // Old sessions and the old passkey are dead; the old code is single-use.
    let r = old_device
        .request(Method::GET, "/v1/account", None, true, Some(&old_at))
        .await;
    assert_eq!(
        r.error(),
        "invalid_token",
        "account API rejects revoked sessions at once"
    );
    assert_eq!(
        old_device
            .refresh(&old_tokens.refresh_token, None)
            .await
            .error(),
        "invalid_grant"
    );
    assert_eq!(
        device.sign_in(&mut lost).await.error(),
        "unknown_credential"
    );
    let reuse = device
        .post(
            "/v1/recover/options",
            &json!({ "recovery_code": code }),
            true,
            None,
        )
        .await;
    assert_eq!(reuse.error(), "invalid_grant");

    // The new passkey works, and the new code can be rotated.
    let t = device.sign_in_ok(&mut replacement).await;
    let at = device.account_token(&t).await;
    let rotated = device
        .post("/v1/account/recovery-code", &json!({}), true, Some(&at))
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{rotated:?}");
    let stale = device
        .post(
            "/v1/recover/options",
            &json!({ "recovery_code": new_code }),
            true,
            None,
        )
        .await;
    assert_eq!(stale.error(), "invalid_grant");
    let bad = device
        .post(
            "/v1/recover/options",
            &json!({ "recovery_code": "not a code" }),
            true,
            None,
        )
        .await;
    assert_eq!(bad.error(), "invalid_grant");
}

#[tokio::test]
async fn account_deletion_removes_everything() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;
    let mut passkey = SoftAuthenticator::new();
    let (tokens, _, code) = c.sign_up(&mut passkey).await;
    let at = c.account_token(&tokens).await;
    let r = c
        .request(Method::DELETE, "/v1/account", None, true, Some(&at))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{r:?}");
    assert_eq!(c.sign_in(&mut passkey).await.error(), "unknown_credential");
    assert_eq!(
        c.refresh(&tokens.refresh_token, None).await.error(),
        "invalid_grant"
    );
    let recover = c
        .post(
            "/v1/recover/options",
            &json!({ "recovery_code": code }),
            true,
            None,
        )
        .await;
    assert_eq!(recover.error(), "invalid_grant");
}

#[tokio::test]
async fn session_lifetimes() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;
    let mut passkey = SoftAuthenticator::new();
    let (tokens, _, _) = c.sign_up(&mut passkey).await;

    // Idle expiry: unused for longer than the idle TTL.
    env.clock.advance(REFRESH_IDLE_TTL);
    c.prime_nonce().await;
    assert_eq!(
        c.refresh(&tokens.refresh_token, None).await.error(),
        "invalid_grant"
    );

    // Absolute expiry: refreshing every 29 days still ends after a year.
    let mut t = c.sign_in_ok(&mut passkey).await;
    let started = c.now();
    loop {
        env.clock.advance(29 * 86_400);
        c.prime_nonce().await;
        let r = c.refresh(&t.refresh_token, None).await;
        if c.now() >= started + REFRESH_ABSOLUTE_TTL {
            assert_eq!(r.error(), "invalid_grant");
            break;
        }
        assert_eq!(r.status, StatusCode::OK, "{r:?}");
        let exp = claims(r.json["refresh_token"].as_str().unwrap())["exp"]
            .as_u64()
            .unwrap();
        assert!(exp <= started + REFRESH_ABSOLUTE_TTL);
        t = common::Tokens {
            access_token: r.json["access_token"].as_str().unwrap().into(),
            refresh_token: r.json["refresh_token"].as_str().unwrap().into(),
        };
    }
}

#[tokio::test]
async fn token_endpoint_request_validation() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    c.prime_nonce().await;
    let form = |body: &str, ct: &str, c: &Client<'_>| {
        Request::post("/v1/token")
            .header("content-type", ct)
            .header("dpop", c.proof("POST", "/v1/token", None))
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let ct = "application/x-www-form-urlencoded";
    let r = c
        .send(form("grant_type=password&client_id=web", ct, &c))
        .await;
    assert_eq!(r.error(), "unsupported_grant_type");
    let r = c
        .send(form(
            "grant_type=refresh_token&grant_type=refresh_token&client_id=web&refresh_token=x",
            ct,
            &c,
        ))
        .await;
    assert_eq!(r.error(), "invalid_request");
    let r = c
        .send(form(
            "grant_type=refresh_token&client_id=web&refresh_token=x",
            "application/json",
            &c,
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let r = c
        .send(form(
            "grant_type=refresh_token&client_id=web&refresh_token=x",
            ct,
            &c,
        ))
        .await;
    assert_eq!(r.error(), "invalid_grant");
}

#[tokio::test]
async fn body_limit_and_cors() {
    let env = env_or_skip!();
    let mut c = Client::new(&env);
    let big = serde_json::json!({ "pad": "x".repeat(70 * 1024) });
    let r = c.post("/v1/login/options", &big, false, None).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(r.error(), "payload_too_large");

    let preflight = |origin: &str| {
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/v1/token")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "dpop, content-type")
            .body(Body::empty())
            .unwrap()
    };
    let ok = c.send(preflight(ORIGIN)).await;
    assert_eq!(ok.headers["access-control-allow-origin"], ORIGIN);
    assert!(ok.headers.get("access-control-allow-credentials").is_none());
    let denied = c.send(preflight("https://evil.example")).await;
    assert!(denied.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn re_registering_a_removed_passkey_does_not_revive_its_sessions() {
    let env = env_or_skip!();
    let mut phone = Client::new(&env);
    phone.prime_nonce().await;
    let mut first = SoftAuthenticator::new();
    let (tokens, _, _) = phone.sign_up(&mut first).await;
    let at = phone.account_token(&tokens).await;

    // Add a security key and sign in with it on a laptop.
    let mut security_key = SoftAuthenticator::new();
    assert_eq!(
        add_passkey(&mut phone, &mut security_key, &at).await.status,
        StatusCode::CREATED
    );
    let mut laptop = Client::new(&env);
    laptop.prime_nonce().await;
    let laptop_tokens = laptop.sign_in_ok(&mut security_key).await;

    // Remove it, then register the very same credential again.
    let path = format!(
        "/v1/account/passkeys/{}",
        b64::encode(&security_key.credential_id)
    );
    let r = phone
        .request(Method::DELETE, &path, None, true, Some(&at))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{r:?}");
    assert_eq!(
        add_passkey(&mut phone, &mut security_key, &at).await.status,
        StatusCode::CREATED
    );

    // The laptop's session started with the removed registration stays dead.
    assert_eq!(
        laptop
            .refresh(&laptop_tokens.refresh_token, None)
            .await
            .error(),
        "invalid_grant"
    );
    // Signing in again with the re-registered passkey works.
    laptop.sign_in_ok(&mut security_key).await;
}

/// Adds a passkey through the account API.
async fn add_passkey(c: &mut Client<'_>, key: &mut SoftAuthenticator, at: &str) -> common::Resp {
    let opts = c
        .post("/v1/account/passkeys/options", &json!({}), true, Some(at))
        .await;
    let pk = &opts.json["publicKey"];
    let challenge = b64::decode_str(pk["challenge"].as_str().unwrap()).unwrap();
    let user = b64::decode_str(pk["user"]["id"].as_str().unwrap()).unwrap();
    let cred = key.register(RP_ID, ORIGIN, &challenge, &user);
    c.post(
        "/v1/account/passkeys/verify",
        &json!({ "credential": cred }),
        true,
        Some(at),
    )
    .await
}
