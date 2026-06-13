use axum::Form;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;

use crate::state::AppState;
use crate::store::oauth::decode_refresh_token;

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
}

/// POST /oauth/revoke — RFC 7009. Always 200, regardless of whether the
/// token was valid (no oracle). Only refresh tokens are revocable; access
/// tokens simply age out (10 min).
pub async fn revoke(State(state): State<AppState>, Form(req): Form<RevokeRequest>) -> StatusCode {
    if let Some((family_id, _secret)) = decode_refresh_token(&req.token) {
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
    StatusCode::OK
}
