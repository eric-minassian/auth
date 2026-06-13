//! Property tests for protocol invariants (no Docker needed).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use auth_service::crypto::{b64u, sha256_b64u};
use auth_service::domain::oauth::OidcClient;
use auth_service::jwt::LocalSigner;
use auth_service::oidc::pkce;
use proptest::prelude::*;

fn verifier_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(
            ('a'..='z')
                .chain('A'..='Z')
                .chain('0'..='9')
                .chain(['-', '.', '_', '~'])
                .collect::<Vec<char>>(),
        ),
        43..=128,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    /// Any spec-valid verifier round-trips through S256.
    #[test]
    fn pkce_round_trip(verifier in verifier_strategy()) {
        let challenge = sha256_b64u(&verifier);
        prop_assert!(pkce::verify_s256(&challenge, &verifier));
    }

    /// A verifier never matches a challenge derived from a different one.
    #[test]
    fn pkce_rejects_mismatches(a in verifier_strategy(), b in verifier_strategy()) {
        prop_assume!(a != b);
        prop_assert!(!pkce::verify_s256(&sha256_b64u(&a), &b));
    }

    /// Arbitrary garbage never panics and never validates.
    #[test]
    fn pkce_handles_garbage(challenge in ".*", verifier in ".*") {
        // Not asserting outcome for accidental valid pairs (impossible to
        // hit randomly) — only that it never panics on weird input.
        let _ = pkce::verify_s256(&challenge, &verifier);
    }

    /// Redirect URIs match exactly or not at all — no prefixes, no case
    /// folding, no trailing-slash forgiveness.
    #[test]
    fn redirect_uri_is_exact_match(suffix in ".{1,16}") {
        let registered = "https://app.example.com/callback";
        let client = OidcClient {
            client_id: "c".to_string(),
            client_name: "c".to_string(),
            redirect_uris: vec![registered.to_string()],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            allowed_origins: vec![],
            scopes: vec![],
        };
        prop_assert!(client.allows_redirect_uri(registered));
        let mutated = format!("{registered}{suffix}");
        prop_assert!(!client.allows_redirect_uri(&mutated));
        prop_assert!(!client.allows_redirect_uri("https://APP.example.com/callback"));
    }
}

/// The ES256 JWS path produces a raw 64-byte signature that verifies against
/// the published JWK — the same property the KMS signer (DER→raw conversion)
/// must satisfy.
#[test]
fn local_signer_jws_verifies_against_its_jwk() {
    let signer = LocalSigner::generate();
    let input = b"header.payload";
    let sig = signer.sign_raw(input).expect("sign");
    assert_eq!(sig.len(), 64, "JWS ES256 signatures are raw r||s, 64 bytes");

    let jwk = signer.public_jwk();
    let x = auth_service::crypto::b64u_decode(jwk["x"].as_str().expect("x")).expect("x bytes");
    let y = auth_service::crypto::b64u_decode(jwk["y"].as_str().expect("y")).expect("y bytes");
    let mut point = vec![0x04];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    use p256::ecdsa::signature::Verifier;
    let verifying_key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("verifying key from jwk");
    let signature = p256::ecdsa::Signature::from_slice(&sig).expect("signature parse");
    verifying_key.verify(input, &signature).expect("verifies");

    // kid is the RFC 7638 thumbprint of the canonical JWK.
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().expect("x"),
        jwk["y"].as_str().expect("y"),
    );
    let expected_kid = b64u(sha2::Sha256::digest(canonical.as_bytes()));
    assert_eq!(jwk["kid"].as_str(), Some(expected_kid.as_str()));
}

use sha2::Digest;
