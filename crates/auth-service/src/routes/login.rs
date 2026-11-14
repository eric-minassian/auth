//! Sign-in (protocol §10.4).

use super::{VerifyBody, client_and_audience, new_sid, webauthn_error};
use crate::error::ApiError;
use crate::http;
use crate::state::AppState;
use crate::store::{Ceremony, CeremonyKind};
use crate::tokens::{self, Session, TokenResponse};
use crate::{dpop, options};
use auth_core::b64;
use auth_core::decide::{self, CEREMONY_TTL, StoredCredential};
use auth_core::webauthn::{self, AuthenticationResponseJson};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::HeaderMap;
use serde_json::{Value, json};

/// `POST /v1/login/options`.
pub async fn options(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let _: serde_json::Map<String, Value> = http::json(&headers, body)?;
    let now = state.clock.now();
    // Bind the ceremony to the device key that asks for it (protocol §8).
    let proof = dpop::require_proof(&state, &headers, "POST", "/v1/login/options", now).await?;
    let challenge = crate::random::bytes::<32>()?;
    state
        .store
        .put_ceremony(
            &challenge,
            &Ceremony {
                kind: CeremonyKind::Login,
                account_id: None,
                recovery_key: None,
                jkt: proof.jkt,
                expires_at: now + CEREMONY_TTL,
            },
        )
        .await?;
    Ok(Json(
        json!({ "publicKey": options::request(&state.config, &challenge) }),
    ))
}

/// `POST /v1/login/verify`.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
    let req: VerifyBody<AuthenticationResponseJson> = http::json(&headers, body)?;
    let (client_id, audience) =
        client_and_audience(&state, req.client_id.as_deref(), req.resource.as_deref())?;
    let (credential_id, user_handle) =
        webauthn::assertion_ids(&req.credential).map_err(webauthn_error)?;
    let user_handle = user_handle
        .filter(|u| u.len() == 16)
        .ok_or_else(|| ApiError::WebauthnRejected("missing or malformed user handle".into()))?;
    let account_id = b64::encode(&user_handle);
    let now = state.clock.now();
    let proof = dpop::require_proof(&state, &headers, "POST", "/v1/login/verify", now).await?;

    let challenge = webauthn::challenge_of(&req.credential.response.client_data_json)
        .ok_or(ApiError::InvalidRequest("malformed clientDataJSON"))?;
    let ceremony = state
        .store
        .take_ceremony(&challenge)
        .await?
        .ok_or_else(|| ApiError::InvalidGrant("unknown or used challenge".into()))?;
    if !decide::check_ceremony(
        ceremony.kind == CeremonyKind::Login,
        &ceremony.jkt,
        &proof.jkt,
        ceremony.expires_at,
        now,
    ) {
        return Err(ApiError::InvalidGrant(
            "challenge expired or for another ceremony".into(),
        ));
    }

    let Some(stored) = state
        .store
        .get_credential(&account_id, &credential_id)
        .await?
    else {
        return Err(ApiError::UnknownCredential(b64::encode(&credential_id)));
    };
    let check = StoredCredential {
        account_id: user_handle,
        credential_id: stored.credential_id.clone(),
        cose_key: stored.public_key.clone(),
        sign_count: stored.sign_count,
        backup_eligible: stored.backup_eligible,
    };
    let ok = webauthn::verify_authentication(&state.rp, &challenge, &check, &req.credential)
        .map_err(webauthn_error)?;
    if !state
        .store
        .record_login(
            &account_id,
            &credential_id,
            stored.sign_count,
            ok.sign_count,
            ok.backup_state,
            now,
        )
        .await?
    {
        return Err(ApiError::InvalidGrant(
            "concurrent sign-in with the same passkey".into(),
        ));
    }
    let meta = state
        .store
        .get_meta(&account_id)
        .await?
        .ok_or_else(|| ApiError::InvalidGrant("account no longer exists".into()))?;

    let lifetimes =
        decide::lifetimes(now, now).map_err(|r| ApiError::Internal(format!("{r:?}")))?;
    let session = Session {
        account_id,
        client_id,
        audience,
        sid: new_sid()?,
        auth_time: now,
        cid: b64::encode(&credential_id),
        rid: b64::encode(&stored.registration_id),
        epoch: meta.epoch,
        jkt: b64::encode(&proof.jkt),
    };
    let tokens = tokens::issue(&state, &session, now, lifetimes).await?;
    tracing::info!(event = "signed_in", "sign-in completed");
    Ok(Json(tokens))
}
