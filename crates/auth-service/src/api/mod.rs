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

/// Trustworthy client IP for rate limiting.
///
/// `CloudFront-Viewer-Address` is set by CloudFront and overwrites any
/// client-supplied value, so it is the authoritative source IP in production.
/// We must NOT trust the leftmost `X-Forwarded-For` entry — it is fully
/// client-controlled and would let an attacker rotate the rate-limit key at
/// will. The XFF fallback (for local dev behind Vite's proxy) takes the
/// rightmost entry, which is the one appended by the nearest trusted proxy.
pub fn client_ip(headers: &HeaderMap) -> String {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    // "<ip>:<port>" — split off the port from the right (handles IPv6 colons).
    if let Some((ip, _port)) = header("cloudfront-viewer-address").and_then(|a| a.rsplit_once(':'))
        && !ip.is_empty()
    {
        return ip.to_string();
    }

    if let Some(ip) = header("x-forwarded-for")
        .and_then(|xff| xff.split(',').map(str::trim).rfind(|s| !s.is_empty()))
    {
        return ip.to_string();
    }

    "unknown".to_string()
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
