//! API errors and their OAuth-style JSON representation (protocol §10.8).
//!
//! Clients get a stable error code and a generic description. The reason a
//! check failed is logged (without tokens or any PII) but never returned.

use auth_verifier::VerifyError;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// An API error.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Malformed request.
    #[error("invalid_request: {0}")]
    InvalidRequest(&'static str),
    /// Unknown `client_id`.
    #[error("invalid_client")]
    InvalidClient,
    /// A refresh token, recovery code or ceremony was rejected.
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    /// Only `refresh_token` is supported at the token endpoint.
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    /// The requested resource is not allowed (RFC 8707).
    #[error("invalid_target")]
    InvalidTarget,
    /// The DPoP proof was rejected at a token-style endpoint.
    #[error("invalid_dpop_proof: {0}")]
    InvalidDpopProof(String),
    /// Retry with a fresh nonce (token-style endpoints).
    #[error("use_dpop_nonce")]
    UseDpopNonce,
    /// The WebAuthn response failed verification.
    #[error("webauthn_rejected: {0}")]
    WebauthnRejected(String),
    /// The passkey is not registered.
    #[error("unknown_credential")]
    UnknownCredential(String),
    /// Passkey limit reached.
    #[error("too_many_passkeys")]
    TooManyPasskeys,
    /// Cannot remove the only passkey.
    #[error("last_passkey")]
    LastPasskey,
    /// Resource not found.
    #[error("not_found")]
    NotFound,
    /// The request conflicts with current state.
    #[error("conflict: {0}")]
    Conflict(&'static str),
    /// Body too large.
    #[error("payload_too_large")]
    PayloadTooLarge,
    /// Wrong `Content-Type`.
    #[error("unsupported_media_type")]
    UnsupportedMediaType,
    /// An access-token / DPoP failure at a resource endpoint.
    #[error("{0}")]
    Verify(#[from] VerifyError),
    /// Internal failure.
    #[error("server_error: {0}")]
    Internal(String),
}

impl ApiError {
    /// Wraps any error as an internal error.
    pub fn internal(e: impl std::fmt::Display) -> Self {
        ApiError::Internal(e.to_string())
    }

    fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        use ApiError as E;
        match self {
            E::InvalidRequest(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The request is malformed.",
            ),
            E::InvalidClient => (StatusCode::BAD_REQUEST, "invalid_client", "Unknown client."),
            E::InvalidGrant(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "The grant is invalid or expired.",
            ),
            E::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Unsupported grant type.",
            ),
            E::InvalidTarget => (
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "The requested resource is not allowed.",
            ),
            E::InvalidDpopProof(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "The DPoP proof is invalid.",
            ),
            E::UseDpopNonce => (
                StatusCode::BAD_REQUEST,
                "use_dpop_nonce",
                "Retry with the DPoP-Nonce provided.",
            ),
            E::WebauthnRejected(_) => (
                StatusCode::BAD_REQUEST,
                "webauthn_rejected",
                "The passkey response was rejected.",
            ),
            E::UnknownCredential(_) => (
                StatusCode::UNAUTHORIZED,
                "unknown_credential",
                "This passkey is not registered.",
            ),
            E::TooManyPasskeys => (
                StatusCode::CONFLICT,
                "too_many_passkeys",
                "The passkey limit has been reached.",
            ),
            E::LastPasskey => (
                StatusCode::CONFLICT,
                "last_passkey",
                "The only passkey cannot be removed.",
            ),
            E::NotFound => (StatusCode::NOT_FOUND, "not_found", "Not found."),
            E::Conflict(_) => (
                StatusCode::CONFLICT,
                "conflict",
                "The request conflicts with the current state.",
            ),
            E::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "The request body is too large.",
            ),
            E::UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid_request",
                "Unsupported content type.",
            ),
            E::Verify(v) => (v.status(), v.code(), v.description()),
            E::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error.",
            ),
        }
    }

    fn log(&self) {
        match self {
            ApiError::Internal(detail) => tracing::error!(error = %detail, "internal error"),
            ApiError::Verify(VerifyError::Unavailable { detail }) => {
                tracing::error!(error = %detail, "dependency unavailable");
            }
            other => tracing::info!(rejection = %other, "request rejected"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.log();
        if let ApiError::Verify(v) = self {
            return v.into_response();
        }
        let (status, code, description) = self.parts();
        let mut body = serde_json::json!({ "error": code, "error_description": description });
        if let ApiError::UnknownCredential(id) = &self {
            body["credential_id"] = id.clone().into();
        }
        let mut resp = (status, axum::Json(body)).into_response();
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}
