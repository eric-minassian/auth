use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// CORS for the browser-callable OAuth endpoints (token, revoke, userinfo).
/// The allowlist is the union of registered clients' `allowed_origins` —
/// cookies are never read on these endpoints, so this is purely about
/// letting RP SPAs call them with fetch().
pub async fn allow_registered_origins(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let allowed = match &origin {
        Some(origin) => match state.store.list_clients().await {
            Ok(clients) => clients
                .iter()
                .any(|c| c.allowed_origins.iter().any(|o| o == origin)),
            Err(error) => {
                tracing::error!(?error, "cors: client list failed");
                false
            }
        },
        None => false,
    };

    if req.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        if allowed {
            apply_cors(&mut response, origin.as_deref());
            let headers = response.headers_mut();
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, OPTIONS"),
            );
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("content-type, authorization"),
            );
            headers.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("600"),
            );
        }
        return response;
    }

    let mut response = next.run(req).await;
    if allowed {
        apply_cors(&mut response, origin.as_deref());
    }
    response
}

/// CORS for the public OIDC metadata endpoints (discovery, JWKS). These expose
/// no secrets and read no cookies, so any origin may fetch them — the
/// `Access-Control-Allow-Origin: *` that public IdPs serve. RP SPAs hit
/// discovery before they are otherwise known to us, so the per-client allowlist
/// (see [`allow_registered_origins`]) can't gate it; that allowlist is reserved
/// for the credential-adjacent token/revoke/userinfo endpoints.
pub async fn allow_public(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
        return response;
    }

    let mut response = next.run(req).await;
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

fn apply_cors(response: &mut Response, origin: Option<&str>) {
    let Some(origin) = origin else { return };
    let Ok(value) = HeaderValue::from_str(origin) else {
        return;
    };
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
}
