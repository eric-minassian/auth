use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::crypto::ct_eq;
use crate::state::AppState;

/// Reject any request that didn't arrive via the CloudFront edge.
///
/// CloudFront injects a secret `x-origin-verify` header (an origin custom
/// header sourced from Secrets Manager) on every request it forwards; a request
/// sent straight to the API Gateway origin lacks it. Without this lock, the
/// per-IP and per-ASN rate-limit keys — derived from the `CloudFront-Viewer-*`
/// headers, which are themselves client-spoofable on a direct connection — are
/// worthless. Skipped entirely when no secret is configured (local dev / tests).
pub async fn enforce(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let Some(secret) = state.cfg.origin_verify_secret.as_deref() else {
        return next.run(req).await;
    };
    let presented = req
        .headers()
        .get("x-origin-verify")
        .and_then(|v| v.to_str().ok());
    if presented.is_some_and(|p| ct_eq(p, secret)) {
        next.run(req).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}
