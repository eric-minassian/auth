use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{client_asn, rate_ip_key};
use crate::crypto::{normalize_recovery_code, sha256_b64u};
use crate::domain::session::SessionLevel;
use crate::error::ApiError;
use crate::session::logout::revoke_session_cascade;
use crate::session::session_cookie;
use crate::state::AppState;
use crate::store::rate_limit::RateClass;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RedeemRequest {
    /// A recovery code, in any reasonable casing/grouping (normalized server-side).
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RedeemResponse {
    pub user_id: Uuid,
}

/// POST /api/recovery/redeem — consume a one-time recovery code and issue an
/// enroll-level session so a new passkey can be registered. There is no email
/// step: the code is the sole break-glass credential. On success every existing
/// session and refresh family is revoked (a reset, not an additive grant), so a
/// stolen code can't silently coexist with the victim's live sessions. Reaching
/// a full session still requires a passkey login afterwards.
#[utoipa::path(
    post, path = "/api/recovery/redeem", tag = "recovery", request_body = RedeemRequest,
    responses(
        (status = 200, body = RedeemResponse, description = "Enroll-level session cookie set"),
        (status = 400, body = super::ErrorResponse, description = "Invalid or expired code"),
        (status = 429, body = super::ErrorResponse, description = "Rate limited"),
    ),
)]
pub async fn redeem(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<RedeemRequest>,
) -> Result<(CookieJar, Json<RedeemResponse>), ApiError> {
    if !state
        .store
        .rate_allow(RateClass::RecoveryIp, &rate_ip_key(&headers))
        .await?
    {
        return Err(ApiError::RateLimited);
    }
    if let Some(asn) = client_asn(&headers)
        && !state.store.rate_allow(RateClass::RecoveryAsn, &asn).await?
    {
        return Err(ApiError::RateLimited);
    }

    // Uniform error for every failure mode (bad format / unknown / expired /
    // owner gone) — callers must not be able to distinguish them.
    let invalid = || ApiError::BadRequest("invalid or expired code".to_string());

    let canonical = normalize_recovery_code(&req.code).ok_or_else(invalid)?;
    let user_id = state
        .store
        .redeem_recovery_code(&sha256_b64u(&canonical))
        .await?
        .ok_or_else(invalid)?;

    // The code's owner must still exist and be active — prevents resurrecting a
    // deleted account through an orphaned code.
    let Some(user) = state
        .store
        .get_user(user_id)
        .await?
        .filter(|u| u.is_active())
    else {
        return Err(invalid());
    };

    for session in state.store.list_sessions(user.user_id).await? {
        revoke_session_cascade(&state, &session).await?;
    }

    let (sid, _session) = state
        .store
        .create_session(
            user.user_id,
            SessionLevel::Enroll,
            vec!["recovery".to_string()],
            super::summarize_user_agent(&headers),
            super::client_region(&headers),
            None,
        )
        .await?;
    tracing::info!(target: "audit", event = "recovery_redeemed", user_id = %user.user_id);
    Ok((
        jar.add(session_cookie(&state.cfg, sid)),
        Json(RedeemResponse {
            user_id: user.user_id,
        }),
    ))
}
