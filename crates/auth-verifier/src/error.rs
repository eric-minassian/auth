//! Verification errors and their HTTP representation (RFC 9449 §7.1, §9;
//! RFC 9470 §3; RFC 6750 §3).

use auth_core::decide::{Reject, STEP_UP_MAX_AGE};
use http::StatusCode;

/// Why a request was not authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The access token is missing or invalid.
    InvalidToken {
        /// The verified check that failed, for logs. Never sent to clients.
        reason: Option<Reject>,
    },
    /// The DPoP proof is missing, invalid, replayed or not bound to the token.
    InvalidDpopProof {
        /// The verified check that failed, for logs. Never sent to clients.
        reason: Option<Reject>,
    },
    /// The client must retry with the nonce in the `DPoP-Nonce` header.
    UseDpopNonce {
        /// A fresh nonce, if the policy issues nonces.
        nonce: Option<String>,
    },
    /// The operation needs a recent passkey ceremony (step-up).
    InsufficientUserAuthentication,
    /// A dependency (JWKS endpoint, replay store) is unavailable.
    Unavailable {
        /// Detail for logs. Never sent to clients.
        detail: String,
    },
}

impl VerifyError {
    /// The OAuth error code.
    pub fn code(&self) -> &'static str {
        match self {
            VerifyError::InvalidToken { .. } => "invalid_token",
            VerifyError::InvalidDpopProof { .. } => "invalid_dpop_proof",
            VerifyError::UseDpopNonce { .. } => "use_dpop_nonce",
            VerifyError::InsufficientUserAuthentication => "insufficient_user_authentication",
            VerifyError::Unavailable { .. } => "temporarily_unavailable",
        }
    }

    /// A short human-readable description that reveals nothing about which
    /// check failed.
    pub fn description(&self) -> &'static str {
        match self {
            VerifyError::InvalidToken { .. } => "The access token is invalid.",
            VerifyError::InvalidDpopProof { .. } => "The DPoP proof is invalid.",
            VerifyError::UseDpopNonce { .. } => "Retry with the DPoP-Nonce provided.",
            VerifyError::InsufficientUserAuthentication => "A recent passkey sign-in is required.",
            VerifyError::Unavailable { .. } => "The service is temporarily unavailable.",
        }
    }

    /// The HTTP status to respond with.
    pub fn status(&self) -> StatusCode {
        match self {
            VerifyError::Unavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    /// The `WWW-Authenticate` challenge, if any.
    pub fn www_authenticate(&self) -> Option<String> {
        match self {
            VerifyError::Unavailable { .. } => None,
            VerifyError::InsufficientUserAuthentication => Some(format!(
                "DPoP error=\"insufficient_user_authentication\", error_description=\"{}\", max_age={STEP_UP_MAX_AGE}, algs=\"ES256\"",
                self.description()
            )),
            other => Some(format!(
                "DPoP error=\"{}\", error_description=\"{}\", algs=\"ES256\"",
                other.code(),
                other.description()
            )),
        }
    }

    /// The `DPoP-Nonce` header to send, if any.
    pub fn dpop_nonce(&self) -> Option<&str> {
        match self {
            VerifyError::UseDpopNonce { nonce } => nonce.as_deref(),
            _ => None,
        }
    }

    /// The JSON error body.
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({ "error": self.code(), "error_description": self.description() })
    }
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::InvalidToken { reason: Some(r) }
            | VerifyError::InvalidDpopProof { reason: Some(r) } => {
                write!(f, "{}: {r:?}", self.code())
            }
            VerifyError::Unavailable { detail } => write!(f, "{}: {detail}", self.code()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<crate::PolicyError> for VerifyError {
    fn from(e: crate::PolicyError) -> Self {
        VerifyError::Unavailable { detail: e.0 }
    }
}
