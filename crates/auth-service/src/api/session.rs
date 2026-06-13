use axum::Json;
use axum::extract::State;
use axum_extra::extract::CookieJar;
use serde_json::{Value, json};

use crate::error::ApiError;
use crate::session::clear_session_cookie;
use crate::session::extract::{AnySession, FullSession};
use crate::session::logout::revoke_session_cascade;
use crate::state::AppState;

/// GET /api/session — whoami for the SPA.
pub async fn get(
    State(state): State<AppState>,
    FullSession(session): FullSession,
) -> Result<Json<Value>, ApiError> {
    let user = state
        .store
        .get_user(session.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    Ok(Json(json!({
        "user": {
            "user_id": user.user_id,
            "email": user.email,
        },
        "session": {
            "created_at": session.created_at,
            "amr": session.amr,
        },
    })))
}

/// POST /api/session/logout — destroys the IdP session and cascades:
/// revokes refresh families bound to it and dispatches back-channel logout
/// to affected RPs.
pub async fn logout(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    jar: CookieJar,
) -> Result<(CookieJar, Json<Value>), ApiError> {
    revoke_session_cascade(&state, &session).await?;
    tracing::info!(target: "audit", event = "logout", user_id = %session.user_id);
    Ok((
        jar.add(clear_session_cookie(&state.cfg)),
        Json(json!({ "ok": true })),
    ))
}
