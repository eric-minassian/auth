use axum::Json;
use axum::extract::{Path, State};
use garde::Validate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use crate::domain::session::REAUTH_FRESHNESS_SECS;
use crate::error::ApiError;
use crate::session::extract::FullSession;
use crate::session::logout::revoke_session_cascade;
use crate::state::AppState;
use crate::store::StoreError;
use crate::store::rate_limit::RateClass;

#[derive(Serialize, ToSchema)]
pub struct PasskeyInfo {
    pub credential_id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct PasskeyList {
    pub passkeys: Vec<PasskeyInfo>,
}

#[derive(Serialize, ToSchema)]
pub struct SessionListItem {
    pub session_id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub amr: Vec<String>,
    pub current: bool,
}

#[derive(Serialize, ToSchema)]
pub struct SessionList {
    pub sessions: Vec<SessionListItem>,
}

/// GET /api/account/passkeys
#[utoipa::path(
    get,
    path = "/api/account/passkeys",
    tag = "account",
    responses((status = 200, body = PasskeyList), (status = 403, body = super::ErrorResponse)),
)]
pub async fn list_passkeys(
    State(state): State<AppState>,
    FullSession(session): FullSession,
) -> Result<Json<Value>, ApiError> {
    let mut credentials = state.store.list_credentials(session.user_id).await?;
    credentials.sort_by_key(|c| c.created_at);
    let passkeys = credentials
        .iter()
        .map(|c| {
            json!({
                "credential_id": c.credential_id,
                "name": c.name,
                "created_at": c.created_at,
                "last_used_at": c.last_used_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "passkeys": passkeys })))
}

#[derive(Deserialize, Validate, ToSchema)]
pub struct RenameRequest {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
}

/// PATCH /api/account/passkeys/{credential_id}
#[utoipa::path(
    patch,
    path = "/api/account/passkeys/{credential_id}",
    tag = "account",
    params(("credential_id" = String, Path, description = "base64url credential id")),
    request_body = RenameRequest,
    responses((status = 200, body = super::OkResponse), (status = 404, body = super::ErrorResponse)),
)]
pub async fn rename_passkey(
    State(state): State<AppState>,
    FullSession(session): FullSession,
    Path(credential_id): Path<String>,
    Json(req): Json<RenameRequest>,
) -> Result<Json<Value>, ApiError> {
    req.validate()?;
    rate_limit_account(&state, &session.sid_hash).await?;
    match state
        .store
        .rename_credential(session.user_id, &credential_id, req.name.trim())
        .await
    {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(StoreError::ConditionFailed) => Err(ApiError::NotFound),
        Err(e) => Err(e.into()),
    }
}

/// DELETE /api/account/passkeys/{credential_id} — refuses to delete the last
/// passkey (account lockout guard; recovery would be the only way back in).
#[utoipa::path(
    delete,
    path = "/api/account/passkeys/{credential_id}",
    tag = "account",
    params(("credential_id" = String, Path, description = "base64url credential id")),
    responses(
        (status = 200, body = super::OkResponse),
        (status = 404, body = super::ErrorResponse),
        (status = 409, body = super::ErrorResponse, description = "Cannot delete the only passkey"),
    ),
)]
pub async fn delete_passkey(
    State(state): State<AppState>,
    FullSession(session): FullSession,
    Path(credential_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    rate_limit_account(&state, &session.sid_hash).await?;
    let credentials = state.store.list_credentials(session.user_id).await?;
    if credentials.len() <= 1 {
        return Err(ApiError::Conflict {
            code: "last_passkey",
            message: "cannot delete your only passkey — add another one first".to_string(),
        });
    }
    if !credentials.iter().any(|c| c.credential_id == credential_id) {
        return Err(ApiError::NotFound);
    }
    match state
        .store
        .delete_credential(session.user_id, &credential_id)
        .await
    {
        Ok(()) => {
            tracing::info!(target: "audit", event = "passkey_deleted", user_id = %session.user_id);
            Ok(Json(json!({ "ok": true })))
        }
        Err(StoreError::ConditionFailed) => Err(ApiError::NotFound),
        Err(e) => Err(e.into()),
    }
}

/// GET /api/account/sessions
#[utoipa::path(
    get,
    path = "/api/account/sessions",
    tag = "account",
    responses((status = 200, body = SessionList), (status = 403, body = super::ErrorResponse)),
)]
pub async fn list_sessions(
    State(state): State<AppState>,
    FullSession(session): FullSession,
) -> Result<Json<Value>, ApiError> {
    let mut sessions = state.store.list_sessions(session.user_id).await?;
    sessions.sort_by_key(|s| std::cmp::Reverse(s.created_at));
    let payload = sessions
        .iter()
        .map(|s| {
            json!({
                "session_id": s.sid_hash,
                "created_at": s.created_at,
                "last_seen_at": s.last_seen_at,
                "amr": s.amr,
                "current": s.sid_hash == session.sid_hash,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "sessions": payload })))
}

/// DELETE /api/account/sessions/{session_id} — session_id is the sid hash as
/// returned by the list endpoint (opaque to the client).
#[utoipa::path(
    delete,
    path = "/api/account/sessions/{session_id}",
    tag = "account",
    params(("session_id" = String, Path, description = "Opaque session id from the list endpoint")),
    responses((status = 200, body = super::OkResponse), (status = 404, body = super::ErrorResponse)),
)]
pub async fn revoke_session(
    State(state): State<AppState>,
    FullSession(session): FullSession,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    rate_limit_account(&state, &session.sid_hash).await?;
    let sessions = state.store.list_sessions(session.user_id).await?;
    let Some(target) = sessions.into_iter().find(|s| s.sid_hash == session_id) else {
        return Err(ApiError::NotFound);
    };
    revoke_session_cascade(&state, &target).await?;
    tracing::info!(target: "audit", event = "session_revoked", user_id = %session.user_id);
    Ok(Json(json!({ "ok": true })))
}

/// DELETE /api/account — permanently delete the account and everything bound
/// to it: passkeys, sessions (each cascading to refresh families +
/// back-channel logout), then the user record itself.
#[utoipa::path(
    delete,
    path = "/api/account",
    tag = "account",
    responses((status = 200, body = super::OkResponse), (status = 401, body = super::ErrorResponse)),
)]
pub async fn delete_account(
    State(state): State<AppState>,
    FullSession(session): FullSession,
    jar: axum_extra::extract::CookieJar,
) -> Result<(axum_extra::extract::CookieJar, Json<Value>), ApiError> {
    rate_limit_account(&state, &session.sid_hash).await?;
    let user = state
        .store
        .get_user(session.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    for credential in state.store.list_credentials(user.user_id).await? {
        state
            .store
            .delete_credential(user.user_id, &credential.credential_id)
            .await?;
    }
    // Revoking every session also revokes its refresh families and dispatches
    // back-channel logout to RPs.
    for s in state.store.list_sessions(user.user_id).await? {
        revoke_session_cascade(&state, &s).await?;
    }
    state.store.delete_all_recovery_codes(user.user_id).await?;
    state.store.delete_user(&user).await?;
    tracing::info!(target: "audit", event = "account_deleted", user_id = %user.user_id);

    Ok((
        jar.add(crate::session::clear_session_cookie(&state.cfg)),
        Json(json!({ "ok": true })),
    ))
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryCodes {
    pub codes: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RecoveryReadiness {
    pub passkey_count: usize,
    pub recovery_codes_remaining: usize,
}

/// POST /api/account/recovery-codes — (re)generate the account's recovery
/// codes, returning them exactly once. Requires a recent WebAuthn step-up
/// (`/api/webauthn/reauth/*`); a fresh login also counts.
#[utoipa::path(
    post,
    path = "/api/account/recovery-codes",
    tag = "account",
    responses(
        (status = 200, body = RecoveryCodes, description = "Newly generated codes (shown once)"),
        (status = 409, body = super::ErrorResponse, description = "Step-up re-authentication required"),
    ),
)]
pub async fn generate_recovery_codes(
    State(state): State<AppState>,
    FullSession(session): FullSession,
) -> Result<Json<Value>, ApiError> {
    rate_limit_account(&state, &session.sid_hash).await?;
    if crate::store::now() - session.reauth_at > REAUTH_FRESHNESS_SECS {
        return Err(ApiError::Conflict {
            code: "reauth_required",
            message: "re-authenticate with a passkey before generating recovery codes".to_string(),
        });
    }
    let codes = state.store.generate_recovery_codes(session.user_id).await?;
    tracing::info!(target: "audit", event = "recovery_codes_generated", user_id = %session.user_id);
    Ok(Json(json!({ "codes": codes })))
}

/// GET /api/account/recovery-readiness — how protected the account is against
/// device loss (passkey count + remaining recovery codes), for nudging the user
/// to add a backup passkey or save recovery codes.
#[utoipa::path(
    get,
    path = "/api/account/recovery-readiness",
    tag = "account",
    responses((status = 200, body = RecoveryReadiness), (status = 403, body = super::ErrorResponse)),
)]
pub async fn recovery_readiness(
    State(state): State<AppState>,
    FullSession(session): FullSession,
) -> Result<Json<Value>, ApiError> {
    let passkey_count = state.store.list_credentials(session.user_id).await?.len();
    let recovery_codes_remaining = state.store.count_recovery_codes(session.user_id).await?;
    Ok(Json(json!({
        "passkey_count": passkey_count,
        "recovery_codes_remaining": recovery_codes_remaining,
    })))
}

async fn rate_limit_account(state: &AppState, sid_hash: &str) -> Result<(), ApiError> {
    if !state
        .store
        .rate_allow(RateClass::AccountSession, sid_hash)
        .await?
    {
        return Err(ApiError::RateLimited);
    }
    Ok(())
}
