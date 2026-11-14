//! Request parsing and response headers.

use crate::error::ApiError;
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

/// Maximum request body size (protocol §2).
pub const MAX_BODY: usize = 64 * 1024;

fn media_type(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    Some(
        v.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase(),
    )
}

fn body_bytes(body: Result<Bytes, BytesRejection>) -> Result<Bytes, ApiError> {
    body.map_err(|e| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge
        } else {
            ApiError::InvalidRequest("unreadable body")
        }
    })
}

/// Parses an `application/json` body. An empty body is read as `{}` so that
/// option endpoints accept a bare POST.
pub fn json<T: DeserializeOwned>(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<T, ApiError> {
    let body = body_bytes(body)?;
    let raw: &[u8] = if body.is_empty() { b"{}" } else { &body };
    if !body.is_empty() && media_type(headers).as_deref() != Some("application/json") {
        return Err(ApiError::UnsupportedMediaType);
    }
    serde_json::from_slice(raw).map_err(|_| ApiError::InvalidRequest("malformed JSON body"))
}

/// Parses an `application/x-www-form-urlencoded` body. Parameters must not be
/// repeated (RFC 6749 §3.2).
pub fn form(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<HashMap<String, String>, ApiError> {
    let body = body_bytes(body)?;
    if media_type(headers).as_deref() != Some("application/x-www-form-urlencoded") {
        return Err(ApiError::UnsupportedMediaType);
    }
    let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(&body)
        .map_err(|_| ApiError::InvalidRequest("malformed form body"))?;
    let mut out = HashMap::with_capacity(pairs.len());
    for (k, v) in pairs {
        if out.insert(k, v).is_some() {
            return Err(ApiError::InvalidRequest("repeated parameter"));
        }
    }
    Ok(out)
}

/// Adds the headers every response carries: a fresh `DPoP-Nonce`, `Date`,
/// `Cache-Control: no-store` unless set, and defensive security headers.
pub async fn response_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let now = state.clock.now();
    let headers = resp.headers_mut();
    match state.nonces.fresh(now).await {
        Ok(nonce) => {
            if let Ok(v) = HeaderValue::from_str(&nonce) {
                headers.insert("dpop-nonce", v);
            }
        }
        Err(e) => tracing::error!(error = %e, "could not compute DPoP nonce"),
    }
    let date = httpdate::fmt_http_date(std::time::UNIX_EPOCH + std::time::Duration::from_secs(now));
    if let Ok(v) = HeaderValue::from_str(&date) {
        headers.insert(header::DATE, v);
    }
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    resp
}
