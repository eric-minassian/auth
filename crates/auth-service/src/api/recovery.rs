use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use garde::Validate;
use serde_json::{Value, json};

use super::client_ip;
use super::signup::{StartRequest, VerifyRequest, VerifyResponse};
use crate::domain::otp::OtpPurpose;
use crate::domain::session::SessionLevel;
use crate::email::templates;
use crate::error::ApiError;
use crate::session::logout::revoke_session_cascade;
use crate::session::session_cookie;
use crate::state::AppState;
use crate::store::rate_limit::RateClass;

/// POST /api/recovery/start — sends a recovery OTP if the account exists.
/// Uniform 200 either way (anti-enumeration).
#[utoipa::path(
    post,
    path = "/api/recovery/start",
    tag = "recovery",
    request_body = StartRequest,
    responses(
        (status = 200, body = super::OkResponse),
        (status = 429, body = super::ErrorResponse, description = "Rate limited"),
    ),
)]
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StartRequest>,
) -> Result<Json<Value>, ApiError> {
    req.validate()?;
    let email = req.email.to_lowercase();
    let ip = client_ip(&headers);
    if !state
        .store
        .rate_allow(RateClass::OtpSendEmail, &email)
        .await?
        || !state.store.rate_allow(RateClass::OtpSendIp, &ip).await?
    {
        return Err(ApiError::RateLimited);
    }

    if state.store.get_user_by_email(&email).await?.is_some() {
        let code = state.store.issue_otp(&email, OtpPurpose::Recovery).await?;
        state
            .mailer
            .send(templates::otp_email(&email, OtpPurpose::Recovery, &code))
            .await?;
        tracing::info!(target: "audit", event = "recovery_start");
    } else {
        tracing::info!(target: "audit", event = "recovery_start_unknown");
    }
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/recovery/verify — consumes the OTP and issues an enroll-level
/// session on the existing account so a new passkey can be registered.
#[utoipa::path(
    post,
    path = "/api/recovery/verify",
    tag = "recovery",
    request_body = VerifyRequest,
    responses(
        (status = 200, body = VerifyResponse, description = "Enroll-level session cookie set"),
        (status = 400, body = super::ErrorResponse, description = "Invalid or expired code"),
    ),
)]
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<VerifyRequest>,
) -> Result<(CookieJar, Json<VerifyResponse>), ApiError> {
    req.validate()?;
    let email = req.email.to_lowercase();
    let ip = client_ip(&headers);
    if !state.store.rate_allow(RateClass::OtpVerifyIp, &ip).await? {
        return Err(ApiError::RateLimited);
    }

    if !state
        .store
        .verify_otp(&email, OtpPurpose::Recovery, &req.code)
        .await?
    {
        return Err(ApiError::BadRequest("invalid or expired code".to_string()));
    }

    // OTPs for this purpose are only ever issued for existing accounts, so a
    // missing user here means it was deleted since — same uniform error.
    let user = state
        .store
        .get_user_by_email(&email)
        .await?
        .ok_or_else(|| ApiError::BadRequest("invalid or expired code".to_string()))?;

    // Recovery is a reset, not an additive grant: revoke every existing
    // session (and its refresh families, via the cascade) so a mailbox
    // compromise cannot silently coexist with the victim's live sessions, and
    // the legitimate user is forced to re-authenticate everywhere.
    for session in state.store.list_sessions(user.user_id).await? {
        revoke_session_cascade(&state, &session).await?;
    }

    let (sid, _session) = state
        .store
        .create_session(user.user_id, SessionLevel::Enroll, vec!["otp".to_string()])
        .await?;
    tracing::info!(target: "audit", event = "recovery_verified", user_id = %user.user_id);
    Ok((
        jar.add(session_cookie(&state.cfg, sid)),
        Json(VerifyResponse {
            user_id: user.user_id,
        }),
    ))
}
