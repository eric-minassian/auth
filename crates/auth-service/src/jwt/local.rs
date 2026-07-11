use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::SignError;
use crate::crypto::b64u;

/// In-process ES256 signer for local dev and tests. Produces byte-identical
/// JWS output to the KMS signer so every verification path is exercised the
/// same way.
#[derive(Clone)]
pub struct LocalSigner {
    key: SigningKey,
    kid: String,
    jwk: serde_json::Value,
}

impl LocalSigner {
    pub fn generate() -> Self {
        // p256 0.13 takes a rand_core 0.6 RNG, but the workspace uses rand
        // 0.9 — so draw scalar bytes ourselves. Retries when the candidate
        // is not a valid field element (probability ~2^-128).
        loop {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                return Self::from_key(key);
            }
        }
    }

    pub fn from_pem(pem: &str) -> Result<Self, SignError> {
        let key =
            SigningKey::from_pkcs8_pem(pem).map_err(|e| SignError::Signature(e.to_string()))?;
        Ok(Self::from_key(key))
    }

    pub fn to_pem(&self) -> Result<String, SignError> {
        self.key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|z| z.to_string())
            .map_err(|e| SignError::Signature(e.to_string()))
    }

    fn from_key(key: SigningKey) -> Self {
        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = (
            b64u(point.x().map(|x| x.to_vec()).unwrap_or_default()),
            b64u(point.y().map(|y| y.to_vec()).unwrap_or_default()),
        );
        // kid = RFC 7638 JWK thumbprint: SHA-256 over the canonical JWK
        // (lexicographic keys: crv, kty, x, y), base64url.
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = b64u(Sha256::digest(canonical.as_bytes()));
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": kid,
            "alg": "ES256",
            "use": "sig",
        });
        Self { key, kid, jwk }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn public_jwk(&self) -> serde_json::Value {
        self.jwk.clone()
    }

    /// Raw 64-byte r||s signature (low-S normalized) over the signing input.
    pub fn sign_raw(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        let sig: Signature = self.key.sign(signing_input);
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().to_vec())
    }
}
