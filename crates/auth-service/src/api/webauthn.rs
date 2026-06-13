use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use super::client_ip;
use crate::crypto::b64u;
use crate::domain::session::{IdpSession, SessionLevel};
use crate::error::ApiError;
use crate::session::extract::AnySession;
use crate::session::session_cookie;
use crate::state::AppState;
use crate::store::ceremonies::CeremonyPurpose;
use crate::store::rate_limit::RateClass;

#[derive(Serialize)]
pub struct RegisterStartResponse {
    pub ceremony_id: String,
    pub options: CreationChallengeResponse,
}

/// POST /api/webauthn/register/start — enroll or full session.
pub async fn register_start(
    State(state): State<AppState>,
    AnySession(session): AnySession,
) -> Result<Json<RegisterStartResponse>, ApiError> {
    let user = state
        .store
        .get_user(session.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let existing = state.store.list_credentials(user.user_id).await?;
    let exclude = existing
        .iter()
        .map(|c| c.passkey.cred_id().clone())
        .collect::<Vec<_>>();
    let (options, reg_state) = state
        .webauthn
        .start_passkey_registration(
            user.user_id,
            &user.email,
            &user.email,
            (!exclude.is_empty()).then_some(exclude),
        )
        .map_err(|e| ApiError::Internal(format!("webauthn start registration: {e}")))?;
    let ceremony_id = state
        .store
        .put_ceremony(
            CeremonyPurpose::Registration,
            Some(user.user_id),
            &reg_state,
        )
        .await?;
    Ok(Json(RegisterStartResponse {
        ceremony_id,
        options,
    }))
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub ceremony_id: String,
    pub credential: RegisterPublicKeyCredential,
    pub name: Option<String>,
}

/// POST /api/webauthn/register/finish — stores the passkey; upgrades an
/// enroll session to full when it was the first registration step.
pub async fn register_finish(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<Value>, ApiError> {
    let (owner, reg_state): (Option<uuid::Uuid>, PasskeyRegistration) = state
        .store
        .consume_ceremony(&req.ceremony_id, CeremonyPurpose::Registration)
        .await?
        .ok_or_else(|| ApiError::BadRequest("ceremony expired — try again".to_string()))?;
    if owner != Some(session.user_id) {
        return Err(ApiError::Forbidden);
    }
    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            tracing::info!(target: "audit", event = "passkey_register_failed", error = %e);
            ApiError::BadRequest("passkey registration failed".to_string())
        })?;
    let credential_id = b64u(passkey.cred_id());
    let name = req
        .name
        .filter(|n| !n.trim().is_empty() && n.len() <= 64)
        .unwrap_or_else(|| "Passkey".to_string());
    state
        .store
        .put_credential(session.user_id, &credential_id, &passkey, &name)
        .await?;
    if session.level == SessionLevel::Enroll {
        state
            .store
            .upgrade_session_to_full(&session.sid_hash)
            .await?;
    }
    tracing::info!(target: "audit", event = "passkey_registered", user_id = %session.user_id);
    Ok(Json(json!({ "credential_id": credential_id })))
}

/// Which authentication ceremony was started; parked in the ceremony store.
#[derive(Serialize, Deserialize)]
pub enum LoginCeremonyState {
    /// Empty allowCredentials — browser conditional UI / resident keys.
    Discoverable(DiscoverableAuthentication),
    /// Email-assisted with allowCredentials — fallback for authenticators
    /// without discoverable support.
    AllowList(PasskeyAuthentication),
}

#[derive(Deserialize, Default)]
pub struct LoginStartRequest {
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct LoginStartResponse {
    pub ceremony_id: String,
    pub options: RequestChallengeResponse,
}

/// POST /api/webauthn/login/start — no prior auth. Without an email this is
/// the discoverable (conditional-UI) flow; with one, an allowCredentials
/// challenge for that account. Unknown emails get a discoverable challenge
/// so the response shape stays uniform.
pub async fn login_start(
    State(state): State<AppState>,
    body: Option<Json<LoginStartRequest>>,
) -> Result<Json<LoginStartResponse>, ApiError> {
    let email = body.and_then(|Json(b)| b.email);
    let internal = |e: webauthn_rs::prelude::WebauthnError| {
        ApiError::Internal(format!("webauthn start login: {e}"))
    };

    let credentials = match &email {
        Some(email) => match state.store.get_user_by_email(email).await? {
            Some(user) => state
                .store
                .list_credentials(user.user_id)
                .await?
                .into_iter()
                .map(|c| c.passkey)
                .collect::<Vec<_>>(),
            None => Vec::new(),
        },
        None => Vec::new(),
    };

    let (options, ceremony_state) = if credentials.is_empty() {
        let (options, auth_state) = state
            .webauthn
            .start_discoverable_authentication()
            .map_err(internal)?;
        (options, LoginCeremonyState::Discoverable(auth_state))
    } else {
        let (options, auth_state) = state
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(internal)?;
        (options, LoginCeremonyState::AllowList(auth_state))
    };

    let ceremony_id = state
        .store
        .put_ceremony(CeremonyPurpose::Login, None, &ceremony_state)
        .await?;
    Ok(Json(LoginStartResponse {
        ceremony_id,
        options,
    }))
}

#[derive(Deserialize)]
pub struct LoginFinishRequest {
    pub ceremony_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct LoginFinishResponse {
    pub user_id: uuid::Uuid,
}

/// POST /api/webauthn/login/finish — verifies the assertion and issues a
/// full session.
pub async fn login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<LoginFinishRequest>,
) -> Result<(CookieJar, Json<LoginFinishResponse>), ApiError> {
    let ip = client_ip(&headers);
    let uniform = || ApiError::Unauthorized;

    let (_, ceremony_state): (Option<uuid::Uuid>, LoginCeremonyState) = state
        .store
        .consume_ceremony(&req.ceremony_id, CeremonyPurpose::Login)
        .await?
        .ok_or_else(|| ApiError::BadRequest("ceremony expired — try again".to_string()))?;

    let result = async {
        // Identify by the credential id in the assertion; the userHandle is
        // optional on the wire (and absent from some authenticators), so it
        // is cross-checked only when present. Authentication itself rests on
        // the signature check against the stored public key below.
        let stored = state
            .store
            .get_credential(&b64u(&req.credential.raw_id))
            .await?
            .ok_or_else(uniform)?;
        if let Some(handle) = req.credential.response.user_handle.as_ref() {
            let claimed = uuid::Uuid::from_slice(handle.as_ref()).map_err(|_| uniform())?;
            if claimed != stored.user_id {
                return Err(uniform());
            }
        }
        let auth_result = match ceremony_state {
            LoginCeremonyState::Discoverable(auth_state) => state
                .webauthn
                .finish_discoverable_authentication(
                    &req.credential,
                    auth_state,
                    &[stored.passkey.clone().into()],
                )
                .map_err(|_| uniform())?,
            LoginCeremonyState::AllowList(auth_state) => state
                .webauthn
                .finish_passkey_authentication(&req.credential, &auth_state)
                .map_err(|_| uniform())?,
        };
        Ok::<_, ApiError>((stored, auth_result))
    }
    .await;

    let (stored, auth_result) = match result {
        Ok(ok) => ok,
        Err(e) => {
            // Count failures against the IP so assertion-guessing burns the
            // login budget; result deliberately uniform.
            let _ = state.store.rate_allow(RateClass::LoginIp, &ip).await;
            tracing::info!(target: "audit", event = "login_failed");
            return Err(e);
        }
    };

    let mut passkey = stored.passkey.clone();
    if passkey.update_credential(&auth_result) == Some(true) {
        state
            .store
            .update_credential_after_auth(&stored.credential_id, &passkey)
            .await?;
    } else {
        state
            .store
            .update_credential_after_auth(&stored.credential_id, &stored.passkey)
            .await?;
    }

    let (sid, _session): (String, IdpSession) = state
        .store
        .create_session(
            stored.user_id,
            SessionLevel::Full,
            vec!["webauthn".to_string()],
        )
        .await?;
    tracing::info!(target: "audit", event = "login", user_id = %stored.user_id);
    Ok((
        jar.add(session_cookie(&state.cfg, sid)),
        Json(LoginFinishResponse {
            user_id: stored.user_id,
        }),
    ))
}
