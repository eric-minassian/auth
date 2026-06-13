pub mod dev;
pub mod recovery;
pub mod session;
pub mod signup;

use axum::Json;
use axum::http::HeaderMap;
use serde_json::{Value, json};

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

pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}
