pub mod claims;
pub mod local;

use serde::Serialize;
use serde_json::json;

use crate::crypto::b64u;
pub use local::LocalSigner;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signing failed: {0}")]
    Signature(String),
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Token signer. An enum (not a trait object) because the set of
/// implementations is closed and async trait objects are not worth the
/// ceremony: `Local` (p256 in-process; dev/tests) and `Kms` (AWS KMS
/// asymmetric, prod — added with the infra milestone).
#[derive(Clone)]
pub enum Signer {
    Local(LocalSigner),
}

impl Signer {
    pub fn kid(&self) -> &str {
        match self {
            Self::Local(s) => s.kid(),
        }
    }

    /// Public JWK (ES256, P-256) for the JWKS endpoint.
    pub fn public_jwk(&self) -> serde_json::Value {
        match self {
            Self::Local(s) => s.public_jwk(),
        }
    }

    /// Sign a compact JWS: base64url(header).base64url(payload).base64url(sig).
    /// `typ` is e.g. "JWT", "at+jwt", or "logout+jwt".
    pub async fn sign(&self, typ: &str, claims: &impl Serialize) -> Result<String, SignError> {
        let header = json!({ "alg": "ES256", "typ": typ, "kid": self.kid() });
        let signing_input = format!(
            "{}.{}",
            b64u(serde_json::to_vec(&header)?),
            b64u(serde_json::to_vec(claims)?)
        );
        let signature = match self {
            Self::Local(s) => s.sign_raw(signing_input.as_bytes())?,
        };
        Ok(format!("{signing_input}.{}", b64u(signature)))
    }
}
