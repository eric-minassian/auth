pub mod account;
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

/// Rate-limit key derived from the client IP. IPv6 is bucketed to its /64
/// prefix — a single allocation is 2^64 addresses, so the full address is a
/// useless key an attacker rotates for free; IPv4 is used as-is.
pub fn rate_ip_key(headers: &HeaderMap) -> String {
    let ip = client_ip(headers);
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => {
            let seg = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3])
        }
        _ => ip,
    }
}

/// Origin ASN as reported by CloudFront (`CloudFront-Viewer-ASN`), if present.
/// A coarser rate-limit key than IP, since IP-only limiting is defeated by
/// CGNAT and proxy pools. Trustworthy only behind the CloudFront origin lock
/// (see [`crate::middleware::origin`]).
pub fn client_asn(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cloudfront-viewer-asn")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
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
