//! The account API (protocol §10.7). Every request is authenticated with an
//! access token for audience = issuer plus a DPoP proof (nonce required,
//! single-use `jti`), via the formally verified resource check.

use super::{new_recovery_code, webauthn_error};
use crate::error::ApiError;
use crate::http;
use crate::options;
use crate::state::AppState;
use crate::store::{AddError, Ceremony, CeremonyKind, CredentialRecord, RemoveError};
use auth_core::b64;
use auth_core::decide::{self, AccountState, CEREMONY_TTL, MAX_PASSKEYS_PER_ACCOUNT};
use auth_core::webauthn::{self, RegistrationResponseJson};
use auth_verifier::{Identity, RequestParts, VerifyError};
use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{FromRequestParts, OriginalUri, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

/// An authenticated account API caller.
#[derive(Debug)]
pub struct Caller(pub Identity);

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map_or_else(|| parts.uri.path().to_owned(), |u| u.0.path().to_owned());
        let req = RequestParts::from_http(parts, &path)?;
        let id = state.account_api.verify_at(&req, state.clock.now()).await?;
        require_active_session(state, &id).await?;
        Ok(Caller(id))
    }
}

/// Revocation takes effect immediately at the account API: the session's
/// passkey must still be registered and the account epoch unchanged
/// (strongly consistent reads), not merely the access token unexpired.
async fn require_active_session(state: &AppState, id: &Identity) -> Result<(), ApiError> {
    let revoked = || ApiError::Verify(VerifyError::InvalidToken { reason: None });
    let session = id.session.as_ref().ok_or_else(revoked)?;
    let credential_id = b64::decode_str(&session.credential_id).ok_or_else(revoked)?;
    let (meta, credential) = tokio::try_join!(
        state.store.get_meta(&id.subject),
        state.store.get_credential(&id.subject, &credential_id),
    )?;
    let Some(meta) = meta else {
        return Err(revoked());
    };
    let account = AccountState {
        epoch: meta.epoch,
        credential_present: credential.is_some(),
    };
    if decide::check_session_active(Some(session.epoch), &account) {
        Ok(())
    } else {
        Err(revoked())
    }
}

fn step_up(state: &AppState, id: &Identity) -> Result<(), ApiError> {
    id.require_recent_authentication(state.clock.now())
        .map_err(ApiError::from)
}

fn account_bytes(id: &Identity) -> Result<[u8; 16], ApiError> {
    b64::decode_str(&id.subject)
        .and_then(|v| v.try_into().ok())
        .ok_or(ApiError::Verify(VerifyError::InvalidToken { reason: None }))
}

/// Formats an AAGUID in the canonical UUID form (lowercase, hyphenated).
fn aaguid_string(aaguid: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(36);
    for (i, byte) in aaguid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn passkey_json(c: &CredentialRecord) -> Value {
    json!({
        "credential_id": b64::encode(&c.credential_id),
        "created_at": c.created_at,
        "last_used_at": c.last_used_at,
        "aaguid": aaguid_string(&c.aaguid),
        "backup_eligible": c.backup_eligible,
        "backup_state": c.backup_state,
    })
}

/// `GET /v1/account`.
pub async fn get(
    State(state): State<AppState>,
    Caller(id): Caller,
) -> Result<Json<Value>, ApiError> {
    let (meta, mut creds) = state
        .store
        .list_account(&id.subject)
        .await?
        .ok_or(ApiError::Verify(VerifyError::InvalidToken { reason: None }))?;
    creds.sort_by_key(|c| c.created_at);
    Ok(Json(json!({
        "account_id": id.subject,
        "created_at": meta.created_at,
        "passkeys": creds.iter().map(passkey_json).collect::<Vec<_>>(),
    })))
}

/// `POST /v1/account/passkeys/options` (step-up).
pub async fn passkey_options(
    State(state): State<AppState>,
    Caller(id): Caller,
) -> Result<Json<Value>, ApiError> {
    step_up(&state, &id)?;
    let account = account_bytes(&id)?;
    let (_, creds) = state
        .store
        .list_account(&id.subject)
        .await?
        .ok_or(ApiError::Verify(VerifyError::InvalidToken { reason: None }))?;
    let now = state.clock.now();
    let challenge = crate::random::bytes::<32>()?;
    state
        .store
        .put_ceremony(
            &challenge,
            &Ceremony {
                kind: CeremonyKind::AddPasskey,
                account_id: Some(id.subject.clone()),
                recovery_key: None,
                expires_at: now + CEREMONY_TTL,
            },
        )
        .await?;
    let exclude: Vec<Vec<u8>> = creds.into_iter().map(|c| c.credential_id).collect();
    Ok(Json(
        json!({ "publicKey": options::creation(&state.config, &account, &challenge, &exclude) }),
    ))
}

/// Body of `POST /v1/account/passkeys/verify`.
#[derive(Debug, Deserialize)]
pub struct AddBody {
    credential: RegistrationResponseJson,
}

/// `POST /v1/account/passkeys/verify` (step-up).
pub async fn passkey_verify(
    State(state): State<AppState>,
    Caller(id): Caller,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    step_up(&state, &id)?;
    let req: AddBody = http::json(&headers, body)?;
    let now = state.clock.now();
    let challenge = webauthn::challenge_of(&req.credential.response.client_data_json)
        .ok_or(ApiError::InvalidRequest("malformed clientDataJSON"))?;
    let ceremony = state
        .store
        .take_ceremony(&challenge)
        .await?
        .ok_or_else(|| ApiError::InvalidGrant("unknown or used challenge".into()))?;
    let matches = ceremony.kind == CeremonyKind::AddPasskey
        && ceremony.account_id.as_deref() == Some(id.subject.as_str());
    if !decide::check_ceremony(matches, ceremony.expires_at, now) {
        return Err(ApiError::InvalidGrant(
            "challenge expired or for another ceremony".into(),
        ));
    }
    let cred = webauthn::verify_registration(&state.rp, &challenge, &req.credential)
        .map_err(webauthn_error)?;
    match state
        .store
        .add_credential(&id.subject, &cred, MAX_PASSKEYS_PER_ACCOUNT, now)
        .await?
    {
        Ok(()) => {}
        Err(AddError::TooMany) => return Err(ApiError::TooManyPasskeys),
        Err(AddError::Exists) => {
            return Err(ApiError::WebauthnRejected(
                "credential already registered".into(),
            ));
        }
        Err(AddError::NoAccount) => {
            return Err(ApiError::Verify(VerifyError::InvalidToken { reason: None }));
        }
    }
    let record = state
        .store
        .get_credential(&id.subject, &cred.credential_id)
        .await?
        .ok_or_else(|| ApiError::Internal("passkey missing after insert".into()))?;
    tracing::info!(event = "passkey_added", "passkey added");
    Ok((StatusCode::CREATED, Json(passkey_json(&record))))
}

/// `DELETE /v1/account/passkeys/{credential_id}` (step-up).
pub async fn passkey_delete(
    State(state): State<AppState>,
    Caller(id): Caller,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    step_up(&state, &id)?;
    let credential_id = b64::decode_str(&credential_id).ok_or(ApiError::NotFound)?;
    match state
        .store
        .remove_credential(&id.subject, &credential_id)
        .await?
    {
        Ok(()) => {
            tracing::info!(event = "passkey_removed", "passkey removed");
            Ok(StatusCode::NO_CONTENT)
        }
        Err(RemoveError::NotFound) => Err(ApiError::NotFound),
        Err(RemoveError::Last) => Err(ApiError::LastPasskey),
    }
}

/// `POST /v1/account/logout-all`.
pub async fn logout_all(
    State(state): State<AppState>,
    Caller(id): Caller,
) -> Result<StatusCode, ApiError> {
    if !state.store.bump_epoch(&id.subject).await? {
        return Err(ApiError::Verify(VerifyError::InvalidToken { reason: None }));
    }
    tracing::info!(event = "logout_all", "all sessions revoked");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/account/recovery-code` (step-up).
pub async fn rotate_recovery_code(
    State(state): State<AppState>,
    Caller(id): Caller,
) -> Result<Json<Value>, ApiError> {
    step_up(&state, &id)?;
    let meta = state
        .store
        .get_meta(&id.subject)
        .await?
        .ok_or(ApiError::Verify(VerifyError::InvalidToken { reason: None }))?;
    let (code, key) = new_recovery_code()?;
    state
        .store
        .rotate_recovery(&id.subject, &meta.recovery_key, &key)
        .await?;
    tracing::info!(event = "recovery_code_rotated", "recovery code replaced");
    Ok(Json(json!({ "recovery_code": code })))
}

/// `DELETE /v1/account` (step-up).
pub async fn delete(
    State(state): State<AppState>,
    Caller(id): Caller,
) -> Result<StatusCode, ApiError> {
    step_up(&state, &id)?;
    let (meta, creds) = state
        .store
        .list_account(&id.subject)
        .await?
        .ok_or(ApiError::Verify(VerifyError::InvalidToken { reason: None }))?;
    state
        .store
        .delete_account(&id.subject, &meta, &creds)
        .await?;
    tracing::info!(event = "account_deleted", "account deleted");
    Ok(StatusCode::NO_CONTENT)
}
