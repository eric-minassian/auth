use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;

use crate::domain::session::{IdpSession, SessionLevel};
use crate::error::ApiError;
use crate::state::AppState;
use crate::store::now;

/// Any authenticated session (enroll or full). Enroll sessions come from signup
/// (a pending account) or recovery-code redemption and may only register passkeys.
pub struct AnySession(pub IdpSession);

/// A full session (passkey-authenticated). Required by everything except the
/// passkey-registration and logout endpoints.
pub struct FullSession(pub IdpSession);

async fn extract_session(parts: &mut Parts, state: &AppState) -> Result<IdpSession, ApiError> {
    let jar = CookieJar::from_headers(&parts.headers);
    let sid = jar
        .get(&state.cfg.cookie_name)
        .map(|c| c.value().to_string())
        .ok_or(ApiError::Unauthorized)?;
    let session = state
        .store
        .get_session(&sid)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    // Rolling idle window: bump at most once per 6h of activity.
    if now() - session.last_seen_at > 6 * 3600
        && session.level == SessionLevel::Full
        && let Err(error) = state.store.touch_session(&session.sid_hash).await
    {
        tracing::warn!(?error, "session touch failed");
    }
    Ok(session)
}

impl FromRequestParts<AppState> for AnySession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(extract_session(parts, state).await?))
    }
}

impl FromRequestParts<AppState> for FullSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = extract_session(parts, state).await?;
        if session.level != SessionLevel::Full {
            return Err(ApiError::Forbidden);
        }
        Ok(Self(session))
    }
}
