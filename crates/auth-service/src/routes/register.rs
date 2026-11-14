//! Sign-up (protocol §10.3).

use super::{VerifyBody, client_and_audience, new_recovery_code, new_sid, webauthn_error};
use crate::error::ApiError;
use crate::http;
use crate::state::AppState;
use crate::store::{Ceremony, CeremonyKind, StoreError};
use crate::tokens::{self, Session};
use crate::{dpop, options};
use auth_core::b64;
use auth_core::decide::{self, CEREMONY_TTL};
use auth_core::webauthn::{self, RegistrationResponseJson};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

/// `POST /v1/register/options`.
pub async fn options(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let _: serde_json::Map<String, Value> = http::json(&headers, body)?;
    let now = state.clock.now();
    let account_id = crate::random::bytes::<16>()?;
    let challenge = crate::random::bytes::<32>()?;
    state
        .store
        .put_ceremony(
            &challenge,
            &Ceremony {
                kind: CeremonyKind::Register,
                account_id: Some(b64::encode(&account_id)),
                recovery_key: None,
                expires_at: now + CEREMONY_TTL,
            },
        )
        .await?;
    Ok(Json(
        json!({ "publicKey": options::creation(&state.config, &account_id, &challenge, &[]) }),
    ))
}

/// `POST /v1/register/verify`.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let req: VerifyBody<RegistrationResponseJson> = http::json(&headers, body)?;
    let (client_id, audience) =
        client_and_audience(&state, req.client_id.as_deref(), req.resource.as_deref())?;
    let now = state.clock.now();
    let proof = dpop::require_proof(&state, &headers, "POST", "/v1/register/verify", now).await?;

    let challenge = webauthn::challenge_of(&req.credential.response.client_data_json)
        .ok_or(ApiError::InvalidRequest("malformed clientDataJSON"))?;
    let ceremony = state
        .store
        .take_ceremony(&challenge)
        .await?
        .ok_or_else(|| ApiError::InvalidGrant("unknown or used challenge".into()))?;
    if !decide::check_ceremony(
        ceremony.kind == CeremonyKind::Register,
        ceremony.expires_at,
        now,
    ) {
        return Err(ApiError::InvalidGrant(
            "challenge expired or for another ceremony".into(),
        ));
    }
    let account_id = ceremony
        .account_id
        .ok_or_else(|| ApiError::Internal("register ceremony without account".into()))?;

    let cred = webauthn::verify_registration(&state.rp, &challenge, &req.credential)
        .map_err(webauthn_error)?;
    let (recovery_code, recovery_key) = new_recovery_code()?;
    match state
        .store
        .create_account(&account_id, &cred, &recovery_key, now)
        .await
    {
        Ok(()) => {}
        Err(StoreError::Condition(failed)) if failed.get(2).copied().unwrap_or(false) => {
            return Err(ApiError::WebauthnRejected(
                "credential already registered".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    }

    let lifetimes =
        decide::lifetimes(now, now).map_err(|r| ApiError::Internal(format!("{r:?}")))?;
    let session = Session {
        account_id: account_id.clone(),
        client_id,
        audience,
        sid: new_sid()?,
        auth_time: now,
        cid: b64::encode(&cred.credential_id),
        epoch: 0,
        jkt: b64::encode(&proof.jkt),
    };
    let tokens = tokens::issue(&state, &session, now, lifetimes).await?;
    tracing::info!(event = "account_created", "sign-up completed");
    let mut out = serde_json::to_value(tokens).map_err(ApiError::internal)?;
    out["account_id"] = account_id.into();
    out["recovery_code"] = recovery_code.into();
    Ok((StatusCode::CREATED, Json(out)))
}
