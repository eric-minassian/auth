pub mod claims;
pub mod kms;
pub mod local;

use serde::Serialize;
use serde_json::json;

use crate::crypto::b64u;
pub use kms::KmsSigner;
pub use local::LocalSigner;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("signing failed: {0}")]
    Signature(String),
    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Token signer. An enum (not a trait object) because the set of
/// implementations is closed: `Local` (p256 in-process; dev/tests) and `Kms`
/// (AWS KMS asymmetric, prod — private key never leaves the HSM).
#[derive(Clone)]
pub enum Signer {
    Local(LocalSigner),
    Kms(KmsSigner),
}

impl Signer {
    pub fn kid(&self) -> &str {
        match self {
            Self::Local(s) => s.kid(),
            Self::Kms(s) => s.kid(),
        }
    }

    /// The active signing key's public JWK (ES256, P-256).
    pub fn public_jwk(&self) -> serde_json::Value {
        match self {
            Self::Local(s) => s.public_jwk(),
            Self::Kms(s) => s.public_jwk(),
        }
    }

    /// Every published public JWK, active first — the JWKS document. During
    /// publish-before-sign rotation this includes the standby (next) and any
    /// retired keys still within verifier windows.
    pub fn public_jwks(&self) -> Vec<serde_json::Value> {
        match self {
            Self::Local(s) => vec![s.public_jwk()],
            Self::Kms(s) => s.public_jwks(),
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
            Self::Kms(s) => s.sign_raw(signing_input.as_bytes()).await?,
        };
        Ok(format!("{signing_input}.{}", b64u(signature)))
    }
}
