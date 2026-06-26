use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableAuthentication, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs_core::proto::ResidentKeyRequirement;

use super::{client_asn, rate_ip_key};
use crate::crypto::b64u;
use crate::domain::session::{IdpSession, REAUTH_FRESHNESS_SECS, SessionLevel};
use crate::error::ApiError;
use crate::session::extract::{AnySession, FullSession};
use crate::session::session_cookie;
use crate::state::AppState;
use crate::store::ceremonies::CeremonyPurpose;
use crate::store::now;
use crate::store::rate_limit::RateClass;

#[derive(Serialize)]
pub struct RegisterStartResponse {
    pub ceremony_id: String,
    pub options: CreationChallengeResponse,
}

/// POST /api/webauthn/register/start — add a passkey to the current account
/// (enroll or full session). Used to add backup passkeys, and to register a new
/// passkey during recovery. Signup uses its own ceremony (`/api/signup/*`).
#[utoipa::path(
    post,
    path = "/api/webauthn/register/start",
    tag = "webauthn",
    responses(
        (status = 200, description = "{ ceremony_id, options }"),
        (status = 401),
        (status = 409, description = "Step-up re-authentication required"),
    ),
)]
pub async fn register_start(
    State(state): State<AppState>,
    AnySession(session): AnySession,
) -> Result<Json<RegisterStartResponse>, ApiError> {
    let user = state
        .store
        .get_user(session.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    // Pending accounts complete via signup/finish (atomic activate); only an
    // active account may add further passkeys.
    if !user.is_active() {
        return Err(ApiError::Forbidden);
    }
    require_stepup_for_full(&session)?;
    let label = if user.nickname.is_empty() {
        "passkey"
    } else {
        user.nickname.as_str()
    };
    let existing = state.store.list_credentials(user.user_id).await?;
    let exclude = existing
        .iter()
        .map(|c| c.passkey.cred_id().clone())
        .collect::<Vec<_>>();
    let (mut options, reg_state) = state
        .webauthn
        .start_passkey_registration(
            user.user_id,
            label,
            label,
            (!exclude.is_empty()).then_some(exclude),
        )
        .map_err(|e| ApiError::Internal(format!("webauthn start registration: {e}")))?;
    prefer_discoverable_credential(&mut options);
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

#[derive(Deserialize, ToSchema)]
pub struct RegisterFinishRequest {
    pub ceremony_id: String,
    /// Raw `navigator.credentials.create()` result (standard WebAuthn shape).
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
    pub name: Option<String>,
}

/// POST /api/webauthn/register/finish — store the passkey. Never elevates the
/// session: `Full` is reachable only via `login/finish`, so registering a
/// passkey (including during recovery) never by itself grants a full session.
#[utoipa::path(
    post,
    path = "/api/webauthn/register/finish",
    tag = "webauthn",
    responses(
        (status = 200, description = "{ credential_id }"),
        (status = 400),
        (status = 403),
        (status = 409, description = "Step-up re-authentication required"),
    ),
)]
pub async fn register_finish(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<Json<Value>, ApiError> {
    let user = state
        .store
        .get_user(session.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    if !user.is_active() {
        return Err(ApiError::Forbidden);
    }
    require_stepup_for_full(&session)?;
    let (owner, reg_state): (Option<Uuid>, PasskeyRegistration) = state
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
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.chars().count() <= 64)
        .map(str::to_string)
        .unwrap_or_else(|| "Passkey".to_string());
    state
        .store
        .put_credential(session.user_id, &credential_id, &passkey, &name)
        .await?;
    tracing::info!(target: "audit", event = "passkey_registered", user_id = %session.user_id);
    Ok(Json(json!({ "credential_id": credential_id })))
}

#[derive(Serialize)]
pub struct LoginStartResponse {
    pub ceremony_id: String,
    pub options: RequestChallengeResponse,
}

/// POST /api/webauthn/login/start — begin a usernameless, discoverable login
/// (conditional UI / resident keys). Takes no identifier; the authenticator
/// reveals which account on `finish`.
#[utoipa::path(
    post,
    path = "/api/webauthn/login/start",
    tag = "webauthn",
    responses((status = 200, description = "{ ceremony_id, options }")),
)]
pub async fn login_start(
    State(state): State<AppState>,
) -> Result<Json<LoginStartResponse>, ApiError> {
    let (options, auth_state) = state
        .webauthn
        .start_discoverable_authentication()
        .map_err(|e| ApiError::Internal(format!("webauthn start login: {e}")))?;
    let ceremony_id = state
        .store
        .put_ceremony(CeremonyPurpose::Login, None, &auth_state)
        .await?;
    Ok(Json(LoginStartResponse {
        ceremony_id,
        options,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct LoginFinishRequest {
    pub ceremony_id: String,
    /// Raw `navigator.credentials.get()` result (standard WebAuthn shape).
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct LoginFinishResponse {
    pub user_id: Uuid,
}

/// POST /api/webauthn/login/finish — verify the assertion and issue a full
/// session. The asserted credential must belong to an existing, active account,
/// and the assertion must be user-verified; only then is `amr=["webauthn"]`
/// minted. This is the sole path to a full session.
#[utoipa::path(
    post,
    path = "/api/webauthn/login/finish",
    tag = "webauthn",
    responses((status = 200, description = "{ user_id }"), (status = 401, description = "Authentication failed")),
)]
pub async fn login_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<LoginFinishRequest>,
) -> Result<(CookieJar, Json<LoginFinishResponse>), ApiError> {
    let ip = rate_ip_key(&headers);
    let uniform = || ApiError::Unauthorized;

    let (_, ceremony_state): (Option<Uuid>, DiscoverableAuthentication) = state
        .store
        .consume_ceremony(&req.ceremony_id, CeremonyPurpose::Login)
        .await?
        .ok_or_else(|| ApiError::BadRequest("ceremony expired — try again".to_string()))?;

    let result = async {
        // Identify by the credential id in the assertion; userHandle is
        // cross-checked only when present. Authentication itself rests on the
        // signature check against the stored public key.
        let stored = state
            .store
            .get_credential(&b64u(&req.credential.raw_id))
            .await?
            .ok_or_else(uniform)?;
        if let Some(handle) = req.credential.response.user_handle.as_ref() {
            let claimed = Uuid::from_slice(handle.as_ref()).map_err(|_| uniform())?;
            if claimed != stored.user_id {
                return Err(uniform());
            }
        }
        let auth_result = state
            .webauthn
            .finish_discoverable_authentication(
                &req.credential,
                ceremony_state,
                &[stored.passkey.clone().into()],
            )
            .map_err(|_| uniform())?;
        // AAL2 honesty: refuse to mint a `webauthn` session for a non-UV
        // assertion.
        if !auth_result.user_verified() {
            return Err(uniform());
        }
        // The account must exist and be active (re-checks the pending TTL;
        // prevents zombie/orphan logins).
        if !state
            .store
            .get_user(stored.user_id)
            .await?
            .is_some_and(|u| u.is_active())
        {
            return Err(uniform());
        }
        Ok::<_, ApiError>((stored, auth_result))
    }
    .await;

    let (stored, auth_result) = match result {
        Ok(ok) => ok,
        Err(e) => {
            // Count failures against the IP so assertion-guessing burns the
            // login budget; result deliberately uniform.
            let _ = state.store.rate_allow(RateClass::LoginIp, &ip).await;
            tracing::info!(target: "audit", event = "login_failed", ip = %ip, asn = client_asn(&headers).as_deref());
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

    let (sid, _session) = state
        .store
        .create_session(
            stored.user_id,
            SessionLevel::Full,
            vec!["webauthn".to_string()],
            super::summarize_user_agent(&headers),
            super::client_region(&headers),
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

#[derive(Serialize)]
pub struct ReauthStartResponse {
    pub ceremony_id: String,
    pub options: RequestChallengeResponse,
}

/// POST /api/webauthn/reauth/start — begin a step-up assertion on the current
/// full session (we know the user, so allowCredentials is scoped to their
/// passkeys). Used to gate sensitive operations like generating recovery codes.
#[utoipa::path(
    post,
    path = "/api/webauthn/reauth/start",
    tag = "webauthn",
    responses((status = 200, description = "{ ceremony_id, options }"), (status = 400), (status = 403)),
)]
pub async fn reauth_start(
    State(state): State<AppState>,
    FullSession(session): FullSession,
) -> Result<Json<ReauthStartResponse>, ApiError> {
    let credentials = state
        .store
        .list_credentials(session.user_id)
        .await?
        .into_iter()
        .map(|c| c.passkey)
        .collect::<Vec<_>>();
    if credentials.is_empty() {
        return Err(ApiError::BadRequest(
            "no passkeys to re-authenticate with".to_string(),
        ));
    }
    let (options, auth_state) = state
        .webauthn
        .start_passkey_authentication(&credentials)
        .map_err(|e| ApiError::Internal(format!("webauthn start reauth: {e}")))?;
    let ceremony_id = state
        .store
        .put_ceremony(CeremonyPurpose::Reauth, Some(session.user_id), &auth_state)
        .await?;
    Ok(Json(ReauthStartResponse {
        ceremony_id,
        options,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct ReauthFinishRequest {
    pub ceremony_id: String,
    /// Raw `navigator.credentials.get()` result (standard WebAuthn shape).
    #[schema(value_type = Object)]
    pub credential: PublicKeyCredential,
}

/// POST /api/webauthn/reauth/finish — verify the step-up assertion and stamp
/// `reauth_at` on the current session. No new session is minted.
#[utoipa::path(
    post,
    path = "/api/webauthn/reauth/finish",
    tag = "webauthn",
    responses((status = 200, description = "{ ok: true }"), (status = 401), (status = 403)),
)]
pub async fn reauth_finish(
    State(state): State<AppState>,
    FullSession(session): FullSession,
    Json(req): Json<ReauthFinishRequest>,
) -> Result<Json<Value>, ApiError> {
    let (owner, auth_state): (Option<Uuid>, PasskeyAuthentication) = state
        .store
        .consume_ceremony(&req.ceremony_id, CeremonyPurpose::Reauth)
        .await?
        .ok_or_else(|| ApiError::BadRequest("ceremony expired — try again".to_string()))?;
    if owner != Some(session.user_id) {
        return Err(ApiError::Forbidden);
    }
    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|_| ApiError::Unauthorized)?;
    if !auth_result.user_verified() {
        return Err(ApiError::Unauthorized);
    }
    // The asserted credential must belong to this user.
    let stored = state
        .store
        .get_credential(&b64u(&req.credential.raw_id))
        .await?
        .ok_or(ApiError::Unauthorized)?;
    if stored.user_id != session.user_id {
        return Err(ApiError::Unauthorized);
    }
    state
        .store
        .set_session_reauth(&session.sid_hash, now())
        .await?;
    let mut passkey = stored.passkey.clone();
    if passkey.update_credential(&auth_result) == Some(true) {
        state
            .store
            .update_credential_after_auth(&stored.credential_id, &passkey)
            .await?;
    }
    tracing::info!(target: "audit", event = "reauth", user_id = %session.user_id);
    Ok(Json(json!({ "ok": true })))
}

/// Adding a passkey from an already-established *full* session requires a recent
/// step-up assertion, so a stolen bearer session can't silently inject a
/// persistent attacker credential (which would survive session revocation) or
/// mint a fresh `reauth_at` to rotate the victim's recovery codes. Enroll
/// sessions (freshly minted by signup/recovery, and only able to register) are
/// exempt.
fn require_stepup_for_full(session: &IdpSession) -> Result<(), ApiError> {
    if session.level == SessionLevel::Full && now() - session.reauth_at > REAUTH_FRESHNESS_SECS {
        return Err(ApiError::Conflict {
            code: "reauth_required",
            message: "re-authenticate with a passkey before adding a credential".to_string(),
        });
    }
    Ok(())
}

/// Ask the authenticator to create a *discoverable* (resident) credential when
/// it can. webauthn-rs's `start_passkey_registration` requests
/// `residentKey=discouraged`; this IdP is usernameless (discoverable-only login,
/// no allowlist fallback), so we upgrade that to `preferred` — platform
/// authenticators then store a discoverable passkey, while the legacy
/// `requireResidentKey` flag stays `false` so we never hard-fail (or exhaust the
/// limited resident-key slots of) a CTAP2.0 security key. `residentKey` is an
/// unvalidated authenticator hint (the proto type documents this, and
/// `finish_passkey_registration` ignores it), so overriding the generated
/// options before they reach the client is safe.
pub(crate) fn prefer_discoverable_credential(options: &mut CreationChallengeResponse) {
    if let Some(selection) = options.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Preferred);
    }
}
