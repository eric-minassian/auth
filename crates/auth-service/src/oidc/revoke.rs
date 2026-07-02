use axum::Form;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;

use crate::api::AbuseContext;
use crate::crypto::{ct_eq, sha256_b64u};
use crate::state::AppState;
use crate::store::oauth::decode_refresh_token;
use crate::store::rate_limit::RateClass;

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
}

/// POST /oauth/revoke — RFC 7009. Always 200, regardless of whether the
/// token was valid (no oracle). Only refresh tokens are revocable; access
/// tokens simply age out (10 min).
///
/// The presented secret must match the family's *current* token hash
/// (constant-time): family ids appear in old wire tokens and in audit logs,
/// so revoking on the id alone would let any stale-token holder or log
/// reader kill a live grant (revocation-DoS). A stale secret is simply an
/// invalid token — RFC 7009 answers those with 200 and no action (theft of
/// an old token is still caught by reuse detection at the token endpoint).
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<RevokeRequest>,
) -> StatusCode {
    let abuse = AbuseContext::from_headers(&headers);
    match state.store.rate_allow(RateClass::TokenIp, &abuse.ip).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(target: "audit", event = "rate_limited", class = "token-ip", endpoint = "revoke", ip = %abuse.ip);
            return StatusCode::TOO_MANY_REQUESTS;
        }
        Err(error) => {
            tracing::error!(?error, "revoke: rate limit failed");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    if let Some((family_id, secret)) = decode_refresh_token(&req.token) {
        let family = match state.store.get_refresh_family(family_id).await {
            Ok(family) => family,
            Err(error) => {
                tracing::error!(?error, "revoke failed");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        };
        let presented_hash = sha256_b64u(secret);
        if let Some(family) = family
            && ct_eq(&presented_hash, &family.current_token_hash)
        {
            match state
                .store
                .revoke_refresh_family(family_id, "client_revoked")
                .await
            {
                Ok(()) => {
                    tracing::info!(target: "audit", event = "refresh_revoked", family_id);
                }
                Err(error) => {
                    tracing::error!(?error, "revoke failed");
                    return StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
        }
    }
    StatusCode::OK
}
