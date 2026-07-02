use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::jwt::SignError;
use crate::store::StoreError;

/// Error type for the JSON API surface (`/api/*`). OAuth endpoints use
/// `crate::oidc` error types instead (RFC 6749 wire format).
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("authentication required")]
    Unauthorized,
    /// Login assertion referenced a credential id this server has no record
    /// of (e.g. the passkey was deleted on another device). Distinguishable
    /// on purpose: credential ids are unguessable 128-bit+ values, so this
    /// carries no enumeration risk, and the client uses it to signal the
    /// platform's passkey manager to prune the ghost entry.
    #[error("authentication failed")]
    UnknownCredential,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("{message}")]
    Conflict { code: &'static str, message: String },
    #[error("rate limited")]
    RateLimited,
    #[error("internal error")]
    Store(#[from] StoreError),
    #[error("internal error")]
    Sign(#[from] SignError),
    #[error("internal error")]
    Internal(String),
}

impl ApiError {
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::UnknownCredential => (StatusCode::UNAUTHORIZED, "unknown_credential"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict { code, .. } => (StatusCode::CONFLICT, code),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Store(_) | Self::Sign(_) | Self::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = ?self, "internal error");
        }
        // Message is intentionally generic for 5xx; details stay in logs.
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "internal error".to_string()
        } else {
            self.to_string()
        };
        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

impl From<garde::Report> for ApiError {
    fn from(report: garde::Report) -> Self {
        Self::BadRequest(report.to_string())
    }
}
