pub mod account;
pub mod dev;
pub mod recovery;
pub mod session;
pub mod signup;
pub mod webauthn;

use axum::Json;
use axum::http::HeaderMap;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

/// Best-effort client IP for rate limiting. Behind CloudFront/API Gateway the
/// first X-Forwarded-For entry is the viewer address.
pub fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Generic success envelope (`{ "ok": true }`).
#[derive(Serialize, ToSchema)]
pub struct OkResponse {
    pub ok: bool,
}

/// Error envelope returned by every `/api/*` failure.
#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Machine-readable error code, e.g. `rate_limited`, `account_exists`.
    pub error: String,
    pub message: String,
}

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[utoipa::path(
    get,
    path = "/api/healthz",
    tag = "meta",
    responses((status = 200, body = HealthResponse)),
)]
pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}
