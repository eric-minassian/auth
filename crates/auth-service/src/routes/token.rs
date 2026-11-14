//! Refresh (protocol §6.2, §10.5; RFC 6749 §6; RFC 9449 §5).

use super::client_and_audience;
use crate::dpop;
use crate::error::ApiError;
use crate::http;
use crate::state::AppState;
use crate::tokens::{self, Session, TokenResponse};
use auth_core::b64;
use auth_core::decide::{self, AccountState, DPOP_MAX_IAT_SKEW_AUTH_SERVER, RefreshExpect};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::HeaderMap;

/// `POST /v1/token`.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
    let params = http::form(&headers, body)?;
    match params.get("grant_type").map(String::as_str) {
        Some("refresh_token") => {}
        Some(_) => return Err(ApiError::UnsupportedGrantType),
        None => return Err(ApiError::InvalidRequest("grant_type is required")),
    }
    let refresh_token = params
        .get("refresh_token")
        .ok_or(ApiError::InvalidRequest("refresh_token is required"))?;
    let (client_id, audience) = client_and_audience(
        &state,
        params.get("client_id").map(String::as_str),
        params.get("resource").map(String::as_str),
    )?;
    let now = state.clock.now();
    let proof = dpop::require_proof(&state, &headers, "POST", "/v1/token", now).await?;

    let expect = RefreshExpect {
        issuer: state.config.issuer.as_bytes().to_vec(),
        client_id: client_id.as_bytes().to_vec(),
        keys: state.refresh_keys.clone(),
        now,
        max_skew: DPOP_MAX_IAT_SKEW_AUTH_SERVER,
    };
    let verified = decide::check_refresh_token(refresh_token.as_bytes(), &expect, &proof.jkt)
        .map_err(|r| ApiError::InvalidGrant(format!("{r:?}")))?;
    let claims = verified.claims();
    let account_id =
        String::from_utf8(claims.sub.clone()).map_err(|_| ApiError::InvalidGrant("sub".into()))?;
    let (meta, credential) = tokio::try_join!(
        state.store.get_meta(&account_id),
        state.store.get_credential(&account_id, &claims.cid),
    )?;
    let meta = meta.ok_or_else(|| ApiError::InvalidGrant("account no longer exists".into()))?;
    let account = AccountState {
        epoch: meta.epoch,
        registration: credential.map(|c| c.registration_id),
    };
    let lifetimes = decide::authorize_refresh(&verified, &account)
        .map_err(|r| ApiError::InvalidGrant(format!("{r:?}")))?;

    let session = Session {
        account_id,
        client_id,
        audience,
        sid: String::from_utf8(claims.sid.clone())
            .map_err(|_| ApiError::InvalidGrant("sid".into()))?,
        auth_time: claims.auth_time,
        cid: b64::encode(&claims.cid),
        rid: b64::encode(&claims.rid),
        epoch: claims.epoch,
        jkt: b64::encode(&claims.jkt),
    };
    Ok(Json(tokens::issue(&state, &session, now, lifetimes).await?))
}
