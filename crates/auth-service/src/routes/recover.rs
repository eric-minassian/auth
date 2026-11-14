//! Account recovery (protocol §9, §10.6).

use super::{
    VerifyBody, client_and_audience, new_recovery_code, new_sid, recovery_key, webauthn_error,
};
use crate::error::ApiError;
use crate::http;
use crate::state::AppState;
use crate::store::{Ceremony, CeremonyKind, StoreError};
use crate::tokens::{self, Session};
use crate::{dpop, options};
use auth_core::decide::{self, CEREMONY_TTL};
use auth_core::webauthn::{self, RegistrationResponseJson};
use auth_core::{b64, crockford};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::HeaderMap;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct OptionsBody {
    recovery_code: String,
}

/// `POST /v1/recover/options`.
pub async fn options(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let req: OptionsBody = http::json(&headers, body)?;
    let invalid = || ApiError::InvalidGrant("unknown recovery code".into());
    let code = crockford::decode_recovery_code(&req.recovery_code).ok_or_else(invalid)?;
    let key = recovery_key(&code);
    let account_id = state.store.get_recovery(&key).await?.ok_or_else(invalid)?;
    let account_bytes: [u8; 16] = b64::decode_str(&account_id)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ApiError::Internal("stored account id is malformed".into()))?;
    let now = state.clock.now();
    let challenge = crate::random::bytes::<32>()?;
    state
        .store
        .put_ceremony(
            &challenge,
            &Ceremony {
                kind: CeremonyKind::Recover,
                account_id: Some(account_id),
                recovery_key: Some(key),
                expires_at: now + CEREMONY_TTL,
            },
        )
        .await?;
    Ok(Json(
        json!({ "publicKey": options::creation(&state.config, &account_bytes, &challenge, &[]) }),
    ))
}

/// `POST /v1/recover/verify`.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let req: VerifyBody<RegistrationResponseJson> = http::json(&headers, body)?;
    let (client_id, audience) =
        client_and_audience(&state, req.client_id.as_deref(), req.resource.as_deref())?;
    let now = state.clock.now();
    let proof = dpop::require_proof(&state, &headers, "POST", "/v1/recover/verify", now).await?;

    let challenge = webauthn::challenge_of(&req.credential.response.client_data_json)
        .ok_or(ApiError::InvalidRequest("malformed clientDataJSON"))?;
    let ceremony = state
        .store
        .take_ceremony(&challenge)
        .await?
        .ok_or_else(|| ApiError::InvalidGrant("unknown or used challenge".into()))?;
    if !decide::check_ceremony(
        ceremony.kind == CeremonyKind::Recover,
        ceremony.expires_at,
        now,
    ) {
        return Err(ApiError::InvalidGrant(
            "challenge expired or for another ceremony".into(),
        ));
    }
    let (Some(account_id), Some(used_key)) = (ceremony.account_id, ceremony.recovery_key) else {
        return Err(ApiError::Internal(
            "recover ceremony without account".into(),
        ));
    };

    let cred = webauthn::verify_registration(&state.rp, &challenge, &req.credential)
        .map_err(webauthn_error)?;
    let (meta, creds) = state
        .store
        .list_account(&account_id)
        .await?
        .ok_or_else(|| ApiError::InvalidGrant("account no longer exists".into()))?;
    if meta.recovery_key != used_key {
        return Err(ApiError::InvalidGrant("recovery code was replaced".into()));
    }
    let (recovery_code, new_key) = new_recovery_code()?;
    let epoch = match state
        .store
        .recover_account(&account_id, &meta, &creds, &cred, &new_key, now)
        .await
    {
        Ok(e) => e,
        Err(StoreError::Condition(_)) => {
            return Err(ApiError::InvalidGrant(
                "account changed during recovery".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    };

    let lifetimes =
        decide::lifetimes(now, now).map_err(|r| ApiError::Internal(format!("{r:?}")))?;
    let session = Session {
        account_id,
        client_id,
        audience,
        sid: new_sid()?,
        auth_time: now,
        cid: b64::encode(&cred.credential_id),
        epoch,
        jkt: b64::encode(&proof.jkt),
    };
    let tokens = tokens::issue(&state, &session, now, lifetimes).await?;
    tracing::info!(event = "account_recovered", "recovery completed");
    let mut out = serde_json::to_value(tokens).map_err(ApiError::internal)?;
    out["recovery_code"] = recovery_code.into();
    Ok(Json(out))
}
