use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::email::MailError;
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
    Mail(#[from] MailError),
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
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict { code, .. } => (StatusCode::CONFLICT, code),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Store(_) | Self::Mail(_) | Self::Sign(_) | Self::Internal(_) => {
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
