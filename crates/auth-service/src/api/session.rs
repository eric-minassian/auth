use axum::Json;
use axum::extract::State;
use axum_extra::extract::CookieJar;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::session::clear_session_cookie;
use crate::session::extract::{AnySession, FullSession};
use crate::session::logout::revoke_session_cascade;
use crate::state::AppState;

#[derive(Serialize, ToSchema)]
pub struct SessionUser {
    pub user_id: String,
    pub nickname: String,
    /// Present (true) when a recovery redemption left older passkeys that the
    /// owner has not yet reviewed — the SPA routes to the review screen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_credential_review: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct SessionMeta {
    pub created_at: i64,
    pub amr: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SessionInfo {
    pub user: SessionUser,
    pub session: SessionMeta,
}

/// GET /api/session — whoami for the SPA.
#[utoipa::path(
    get,
    path = "/api/session",
    tag = "session",
    responses(
        (status = 200, body = SessionInfo, description = "Current user and session metadata"),
        (status = 401, body = super::ErrorResponse, description = "No session"),
        (status = 403, body = super::ErrorResponse, description = "Enroll-level session (passkey login required)"),
    ),
)]
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
            "nickname": user.nickname,
            "pending_credential_review": user.pending_credential_review.then_some(true),
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
#[utoipa::path(
    post,
    path = "/api/session/logout",
    tag = "session",
    responses(
        (status = 200, body = super::OkResponse, description = "Session destroyed, cookie cleared"),
        (status = 401, body = super::ErrorResponse),
    ),
)]
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
