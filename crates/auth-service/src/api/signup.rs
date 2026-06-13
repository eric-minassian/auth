use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use garde::Validate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::client_ip;
use crate::domain::otp::OtpPurpose;
use crate::domain::session::SessionLevel;
use crate::email::templates;
use crate::error::ApiError;
use crate::session::session_cookie;
use crate::state::AppState;
use crate::store::rate_limit::RateClass;

#[derive(Debug, Deserialize, Validate)]
pub struct StartRequest {
    #[garde(email)]
    pub email: String,
}

/// POST /api/signup/start — sends an OTP (or an "account exists" notice).
/// Uniform 200 regardless of account existence (anti-enumeration).
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
        state
            .mailer
            .send(templates::account_exists_email(&email))
            .await?;
        tracing::info!(target: "audit", event = "signup_start_existing");
    } else {
        let code = state.store.issue_otp(&email, OtpPurpose::Signup).await?;
        state
            .mailer
            .send(templates::otp_email(&email, OtpPurpose::Signup, &code))
            .await?;
        tracing::info!(target: "audit", event = "signup_start");
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyRequest {
    #[garde(email)]
    pub email: String,
    #[garde(length(min = 6, max = 6))]
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub user_id: Uuid,
}

/// POST /api/signup/verify — consumes the OTP, creates the account, and
/// issues an enroll-level session whose only capability is registering the
/// first passkey.
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
        .verify_otp(&email, OtpPurpose::Signup, &req.code)
        .await?
    {
        return Err(ApiError::BadRequest("invalid or expired code".to_string()));
    }

    let user = match state.store.create_user(&email).await {
        Ok(user) => user,
        Err(crate::store::StoreError::ConditionFailed) => {
            return Err(ApiError::Conflict {
                code: "account_exists",
                message: "an account with this email already exists — use account recovery"
                    .to_string(),
            });
        }
        Err(e) => return Err(e.into()),
    };

    let (sid, _session) = state
        .store
        .create_session(user.user_id, SessionLevel::Enroll, vec!["otp".to_string()])
        .await?;
    tracing::info!(target: "audit", event = "signup_verified", user_id = %user.user_id);
    Ok((
        jar.add(session_cookie(&state.cfg, sid)),
        Json(VerifyResponse {
            user_id: user.user_id,
        }),
    ))
}
