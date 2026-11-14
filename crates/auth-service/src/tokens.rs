//! Issuing access and refresh tokens (protocol §6, §10.2).

use crate::error::ApiError;
use crate::state::AppState;
use auth_core::b64;
use auth_core::decide::Lifetimes;
use auth_core::jose::{self, AccessTokenClaims, Cnf, RefreshTokenClaims};
use serde::Serialize;

/// The facts a session is built from.
#[derive(Debug, Clone)]
pub struct Session {
    /// Account ID (`sub`).
    pub account_id: String,
    /// Client ID.
    pub client_id: String,
    /// Audience of the access token.
    pub audience: String,
    /// Session ID, constant across refreshes.
    pub sid: String,
    /// When the passkey ceremony happened.
    pub auth_time: u64,
    /// base64url credential ID of that passkey.
    pub cid: String,
    /// Account epoch when the session started.
    pub epoch: u64,
    /// base64url thumbprint of the client's DPoP key.
    pub jkt: String,
}

/// RFC 6749 §5.1 token response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// Always `DPoP`.
    pub token_type: &'static str,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
    /// The refresh token.
    pub refresh_token: String,
    /// Refresh token lifetime in seconds.
    pub refresh_token_expires_in: u64,
}

fn jti() -> Result<String, ApiError> {
    Ok(b64::encode(&crate::random::bytes::<16>()?))
}

/// Signs a new access token and refresh token for `s`.
pub async fn issue(
    state: &AppState,
    s: &Session,
    now: u64,
    l: Lifetimes,
) -> Result<TokenResponse, ApiError> {
    let cnf = Cnf { jkt: s.jkt.clone() };
    let access = AccessTokenClaims {
        iss: state.config.issuer.clone(),
        sub: s.account_id.clone(),
        aud: s.audience.clone(),
        client_id: s.client_id.clone(),
        iat: now,
        exp: l.access_exp,
        jti: jti()?,
        auth_time: s.auth_time,
        amr: jose::AMR.iter().map(|m| (*m).to_string()).collect(),
        cnf: cnf.clone(),
    };
    let refresh = RefreshTokenClaims {
        iss: state.config.issuer.clone(),
        aud: state.config.issuer.clone(),
        sub: s.account_id.clone(),
        client_id: s.client_id.clone(),
        iat: now,
        exp: l.refresh_exp,
        jti: jti()?,
        sid: s.sid.clone(),
        auth_time: s.auth_time,
        cid: s.cid.clone(),
        epoch: s.epoch,
        cnf,
    };
    let (access_token, refresh_token) = tokio::try_join!(
        state.access_signer.sign_jwt(jose::TYP_ACCESS, &access),
        state.refresh_signer.sign_jwt(jose::TYP_REFRESH, &refresh),
    )?;
    Ok(TokenResponse {
        access_token,
        token_type: "DPoP",
        expires_in: l.access_exp.saturating_sub(now),
        refresh_token,
        refresh_token_expires_in: l.refresh_exp.saturating_sub(now),
    })
}
