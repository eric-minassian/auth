use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::state::AppState;

/// CSRF defense for the cookie-authenticated JSON API (`/api/*`): unsafe
/// methods must present an allow-listed `Origin` and a JSON content type.
/// SameSite=Lax is defense-in-depth only — sibling subdomains are same-site,
/// so a compromised sibling could otherwise ride the cookie (OWASP).
///
/// `/oauth/token` and friends are exempt by path: they never read cookies, so
/// they have no CSRF surface (and RPs on other origins must be able to call
/// them).
pub async fn enforce(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let safe_method = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let path = req.uri().path();
    // /api/reports is the browser's CSP/Trusted-Types report sink: it reads no
    // cookies and the browser POSTs it cross-context with a `reports+json`
    // content type, so the Origin/JSON CSRF gate doesn't apply (and would reject
    // it). It is rate-limited and strictly log-only instead (see api::reports).
    let csrf_exempt = path == "/api/reports";
    if safe_method || !path.starts_with("/api/") || csrf_exempt || allowed(req.headers(), &state) {
        next.run(req).await
    } else {
        let origin = req
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<none>");
        tracing::warn!(target: "audit", event = "csrf_rejected", path, origin);
        (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "csrf", "message": "cross-origin request rejected" })),
        )
            .into_response()
    }
}

fn allowed(headers: &HeaderMap, state: &AppState) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let origin_ok = header("origin").is_some_and(|o| o == state.cfg.issuer);
    let fetch_site_ok = header("sec-fetch-site").is_none_or(|s| s == "same-origin");
    let content_type_ok =
        header("content-type").is_none_or(|ct| ct.starts_with("application/json"));
    origin_ok && fetch_site_ok && content_type_ok
}
