use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use uuid::Uuid;

use super::verify_own_jws;
use crate::domain::oauth::{SCOPE_EMAIL, scope_contains};
use crate::state::AppState;

/// GET|POST /oauth/userinfo — claims for a Bearer access token.
pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                r#"Bearer error="invalid_token""#,
            )],
        )
            .into_response()
    };

    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return unauthorized();
    };
    let Some(claims) = verify_own_jws(&state.signer, &state.cfg.issuer, token) else {
        return unauthorized();
    };
    // Only access tokens may hit userinfo (not id or logout tokens).
    let scope = claims["scope"].as_str().unwrap_or_default().to_string();
    let Some(sub) = claims["sub"].as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
        return unauthorized();
    };
    if claims["client_id"].as_str().is_none() {
        return unauthorized();
    }

    let user = match state.store.get_user(sub).await {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized(),
        Err(error) => {
            tracing::error!(?error, "userinfo: user lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut body = json!({ "sub": user.user_id });
    if scope_contains(&scope, SCOPE_EMAIL) {
        body["email"] = json!(user.email);
        body["email_verified"] = json!(user.email_verified);
    }
    Json(body).into_response()
}
