//! DPoP (RFC 9449) proof-of-possession.
//!
//! A DPoP proof is a single-use JWS (`typ: "dpop+jwt"`, `alg: ES256`) that the
//! client signs with a key it holds privately, embedding the matching *public*
//! JWK in the header. Verifying the proof and binding the issued tokens to that
//! key's thumbprint (`cnf.jkt`) turns a bearer token — replayable by anyone who
//! exfiltrates it — into a sender-constrained one usable only by the holder of
//! the (in the browser, non-extractable) private key.
//!
//! Verification is deliberately done with `p256` directly rather than
//! `jsonwebtoken`: the verifying key comes from the proof itself, and we must
//! reject `alg: none`, private-key JWKs, and tokens whose `htm`/`htu`/`iat`/
//! `ath` don't bind to *this* request — none of which the generic JWT decoder
//! checks for us.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;

use crate::crypto::{b64u_decode, sha256_b64u};

/// Maximum age of a proof's `iat`. Proofs older than this (or dated further than
/// [`CLOCK_SKEW_SECS`] in the future) are rejected. The jti-replay record must
/// outlive this window — see `store::dpop`.
pub const PROOF_MAX_AGE_SECS: i64 = 300;
const CLOCK_SKEW_SECS: i64 = 30;

pub struct DpopProof {
    /// RFC 7638 JWK thumbprint of the proof's public key — bound into the
    /// access token's `cnf.jkt` and onto the refresh family.
    pub jkt: String,
    /// The proof's unique id, recorded to reject replays within the window.
    pub jti: String,
}

/// Verify a DPoP proof against the request it claims to bind.
///
/// `htm`/`htu` are the expected HTTP method and target URI (the latter built
/// from the canonical issuer, not the request `Host`, so it survives the
/// internal API Gateway hostname). `ath`, when `Some`, is the required
/// access-token hash for resource-server proofs (userinfo). Errors are coarse
/// on purpose — every caller responds uniformly.
pub fn verify_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    ath: Option<&str>,
    now: i64,
) -> Result<DpopProof, &'static str> {
    let mut parts = proof.split('.');
    let (header_b64, payload_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err("malformed"),
        };

    // --- Header: media type, algorithm, and the embedded public JWK ---
    let header: Value = b64u_decode(header_b64)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("bad header")?;
    if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Err("typ");
    }
    // Pin ES256: rejects `none` and every other algorithm outright.
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err("alg");
    }
    let jwk = header.get("jwk").and_then(Value::as_object).ok_or("jwk")?;
    // A proof MUST carry only the public key (RFC 9449 §4.2).
    if jwk.contains_key("d") {
        return Err("private jwk");
    }
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err("jwk params");
    }
    let x = jwk.get("x").and_then(Value::as_str).ok_or("jwk x")?;
    let y = jwk.get("y").and_then(Value::as_str).ok_or("jwk y")?;

    // --- Signature over header.payload with that key ---
    let vk = verifying_key(x, y).ok_or("jwk key")?;
    let sig_bytes = b64u_decode(sig_b64).ok_or("sig b64")?;
    if sig_bytes.len() != 64 {
        return Err("sig len");
    }
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "sig")?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| "sig verify")?;

    // jkt = RFC 7638 thumbprint over the canonical EC JWK — byte-identical to
    // the construction the signer uses for its own `kid` (see `jwt::local`).
    let jkt = sha256_b64u(format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#
    ));

    // --- Payload: bind to this method/URI/time, plus ath at resource servers ---
    let payload: Value = b64u_decode(payload_b64)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("bad payload")?;
    if payload.get("htm").and_then(Value::as_str) != Some(htm) {
        return Err("htm");
    }
    let proof_htu = payload
        .get("htu")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if normalize_htu(proof_htu) != htu {
        return Err("htu");
    }
    let iat = payload.get("iat").and_then(Value::as_i64).ok_or("iat")?;
    if iat > now + CLOCK_SKEW_SECS || iat < now - PROOF_MAX_AGE_SECS {
        return Err("iat window");
    }
    let jti = payload
        .get("jti")
        .and_then(Value::as_str)
        .filter(|j| !j.is_empty() && j.len() <= 128)
        .ok_or("jti")?
        .to_string();
    if let Some(expected) = ath
        && payload.get("ath").and_then(Value::as_str) != Some(expected)
    {
        return Err("ath");
    }

    Ok(DpopProof { jkt, jti })
}

/// `ath` (access-token hash) carried by resource-server proofs:
/// base64url(SHA-256(access_token)) — RFC 9449 §4.3.
pub fn access_token_hash(access_token: &str) -> String {
    sha256_b64u(access_token)
}

fn verifying_key(x_b64: &str, y_b64: &str) -> Option<VerifyingKey> {
    let x = b64u_decode(x_b64)?;
    let y = b64u_decode(y_b64)?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    // SEC1 uncompressed point: 0x04 || X || Y. `from_sec1_bytes` validates the
    // point is actually on the curve.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// Compare the proof's `htu` to the expected URI without its query/fragment
/// (RFC 9449 §4.3).
fn normalize_htu(htu: &str) -> &str {
    htu.split(['?', '#']).next().unwrap_or(htu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use rand::Rng;

    use crate::crypto::b64u;

    struct Proofer {
        key: SigningKey,
        x: String,
        y: String,
    }

    impl Proofer {
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

        fn jkt(&self) -> String {
            sha256_b64u(format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                self.x, self.y
            ))
        }

        fn proof(&self, header: Value, payload: Value) -> String {
            let signing_input = format!(
                "{}.{}",
                b64u(serde_json::to_vec(&header).unwrap()),
                b64u(serde_json::to_vec(&payload).unwrap())
            );
            let sig: Signature = self.key.sign(signing_input.as_bytes());
            let sig = sig.normalize_s().unwrap_or(sig);
            format!("{signing_input}.{}", b64u(sig.to_bytes()))
        }

        fn header(&self) -> Value {
            serde_json::json!({
                "typ": "dpop+jwt",
                "alg": "ES256",
                "jwk": { "kty": "EC", "crv": "P-256", "x": self.x, "y": self.y },
            })
        }
    }

    #[test]
    fn accepts_a_well_formed_proof_and_yields_the_thumbprint() {
        let p = Proofer::new();
        let proof = p.proof(
            p.header(),
            serde_json::json!({ "jti": "abc", "htm": "POST", "htu": "https://auth.example/oauth/token", "iat": 1_000 }),
        );
        let verified = verify_proof(
            &proof,
            "POST",
            "https://auth.example/oauth/token",
            None,
            1_000,
        )
        .unwrap();
        assert_eq!(verified.jkt, p.jkt());
        assert_eq!(verified.jti, "abc");
    }

    #[test]
    fn rejects_method_uri_and_time_mismatches() {
        let p = Proofer::new();
        let base = |iat: i64| {
            p.proof(
                p.header(),
                serde_json::json!({ "jti": "j", "htm": "POST", "htu": "https://auth.example/oauth/token", "iat": iat }),
            )
        };
        // wrong method
        assert!(
            verify_proof(
                &base(1_000),
                "GET",
                "https://auth.example/oauth/token",
                None,
                1_000
            )
            .is_err()
        );
        // wrong uri
        assert!(
            verify_proof(
                &base(1_000),
                "POST",
                "https://auth.example/oauth/userinfo",
                None,
                1_000
            )
            .is_err()
        );
        // stale
        assert!(
            verify_proof(
                &base(1_000),
                "POST",
                "https://auth.example/oauth/token",
                None,
                9_999
            )
            .is_err()
        );
        // future
        assert!(
            verify_proof(
                &base(9_999),
                "POST",
                "https://auth.example/oauth/token",
                None,
                1_000
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_alg_none_and_private_jwk() {
        let p = Proofer::new();
        let mut none_header = p.header();
        none_header["alg"] = serde_json::json!("none");
        let proof = p.proof(
            none_header,
            serde_json::json!({ "jti": "j", "htm": "POST", "htu": "https://a/t", "iat": 1 }),
        );
        assert!(verify_proof(&proof, "POST", "https://a/t", None, 1).is_err());

        let mut priv_header = p.header();
        priv_header["jwk"]["d"] = serde_json::json!("c2VjcmV0");
        let proof = p.proof(
            priv_header,
            serde_json::json!({ "jti": "j", "htm": "POST", "htu": "https://a/t", "iat": 1 }),
        );
        assert!(verify_proof(&proof, "POST", "https://a/t", None, 1).is_err());
    }

    #[test]
    fn enforces_ath_at_resource_servers() {
        let p = Proofer::new();
        let with_ath = |ath: &str| {
            p.proof(
                p.header(),
                serde_json::json!({ "jti": "j", "htm": "GET", "htu": "https://a/userinfo", "iat": 1, "ath": ath }),
            )
        };
        assert!(
            verify_proof(
                &with_ath("good"),
                "GET",
                "https://a/userinfo",
                Some("good"),
                1
            )
            .is_ok()
        );
        assert!(
            verify_proof(
                &with_ath("bad"),
                "GET",
                "https://a/userinfo",
                Some("good"),
                1
            )
            .is_err()
        );
        // ath required but absent
        let no_ath = p.proof(
            p.header(),
            serde_json::json!({ "jti": "j", "htm": "GET", "htu": "https://a/userinfo", "iat": 1 }),
        );
        assert!(verify_proof(&no_ath, "GET", "https://a/userinfo", Some("good"), 1).is_err());
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let p = Proofer::new();
        let other = Proofer::new();
        // Header advertises p's key, but sign with other's key.
        let signing_input = format!(
            "{}.{}",
            b64u(serde_json::to_vec(&p.header()).unwrap()),
            b64u(serde_json::to_vec(&serde_json::json!({ "jti": "j", "htm": "POST", "htu": "https://a/t", "iat": 1 })).unwrap())
        );
        let sig: Signature = other.key.sign(signing_input.as_bytes());
        let forged = format!("{signing_input}.{}", b64u(sig.to_bytes()));
        assert!(verify_proof(&forged, "POST", "https://a/t", None, 1).is_err());
    }
}
