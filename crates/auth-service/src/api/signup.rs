use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyRegistration, RegisterPublicKeyCredential,
};

use super::{client_asn, rate_ip_key};
use crate::crypto::{b64u, verify_pow};
use crate::domain::session::SessionLevel;
use crate::error::ApiError;
use crate::session::extract::AnySession;
use crate::session::session_cookie;
use crate::state::AppState;
use crate::store::ceremonies::CeremonyPurpose;
use crate::store::rate_limit::RateClass;

#[derive(Serialize, ToSchema)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: u32,
}

/// GET /api/signup/pow — issue a one-time proof-of-work challenge the client
/// must solve before `signup/start`. A soft cost on mass automated signup
/// (open registration has no email to lean on); not a Sybil/humanness proof.
#[utoipa::path(
    get, path = "/api/signup/pow", tag = "signup",
    responses(
        (status = 200, body = PowChallenge),
        (status = 429, body = super::ErrorResponse, description = "Rate limited"),
    ),
)]
pub async fn pow(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PowChallenge>, ApiError> {
    rate_limit_signup(&state, &headers).await?;
    let (challenge, difficulty) = state.store.issue_pow_challenge().await?;
    Ok(Json(PowChallenge {
        challenge,
        difficulty,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct StartRequest {
    /// User-chosen display nickname (non-unique, sanitized server-side).
    pub nickname: String,
    /// The challenge string from `GET /api/signup/pow`.
    pub pow_challenge: String,
    /// A nonce such that `SHA-256("{challenge}:{nonce}")` meets the difficulty.
    pub pow_nonce: String,
}

#[derive(Serialize)]
pub struct StartResponse {
    pub ceremony_id: String,
    pub user_id: Uuid,
    /// Raw `PublicKeyCredentialCreationOptions` for
    /// `navigator.credentials.create()` (standard WebAuthn shape).
    pub options: CreationChallengeResponse,
}

/// POST /api/signup/start — verify the proof-of-work, create a *pending*
/// account, and begin a passkey registration ceremony. No email, no username:
/// a nickname plus a passkey is the entire signup. Returns an enroll-level
/// session whose only capability is finishing this registration.
#[utoipa::path(
    post, path = "/api/signup/start", tag = "signup", request_body = StartRequest,
    responses(
        (status = 200, description = "{ ceremony_id, user_id, options }; enroll session cookie set"),
        (status = 400, body = super::ErrorResponse, description = "Bad nickname or proof of work"),
        (status = 429, body = super::ErrorResponse, description = "Rate limited"),
    ),
)]
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<StartRequest>,
) -> Result<(CookieJar, Json<StartResponse>), ApiError> {
    rate_limit_signup(&state, &headers).await?;

    let nickname = sanitize_nickname(&req.nickname)
        .ok_or_else(|| ApiError::BadRequest("invalid nickname".to_string()))?;

    // Proof of work: consume the one-time challenge, then verify the solution
    // against the difficulty it was issued at.
    let Some(difficulty) = state
        .store
        .consume_pow_challenge(&req.pow_challenge)
        .await?
    else {
        return Err(ApiError::BadRequest(
            "invalid or expired challenge".to_string(),
        ));
    };
    if !verify_pow(&req.pow_challenge, &req.pow_nonce, difficulty) {
        return Err(ApiError::BadRequest("invalid proof of work".to_string()));
    }

    let user = state.store.create_user(&nickname).await?;
    let (mut options, reg_state) = state
        .webauthn
        .start_passkey_registration(user.user_id, &nickname, &nickname, None)
        .map_err(|e| ApiError::Internal(format!("webauthn start registration: {e}")))?;
    crate::api::webauthn::prefer_discoverable_credential(&mut options);
    let ceremony_id = state
        .store
        .put_ceremony(CeremonyPurpose::Signup, Some(user.user_id), &reg_state)
        .await?;
    let (sid, _session) = state
        .store
        .create_session(
            user.user_id,
            SessionLevel::Enroll,
            vec!["pending".to_string()],
            crate::api::summarize_user_agent(&headers),
            crate::api::client_region(&headers),
        )
        .await?;
    tracing::info!(target: "audit", event = "signup_start", user_id = %user.user_id);
    Ok((
        jar.add(session_cookie(&state.cfg, sid)),
        Json(StartResponse {
            ceremony_id,
            user_id: user.user_id,
            options,
        }),
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct FinishRequest {
    pub ceremony_id: String,
    /// Raw `navigator.credentials.create()` result (standard WebAuthn shape).
    #[schema(value_type = Object)]
    pub credential: RegisterPublicKeyCredential,
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct FinishResponse {
    pub user_id: Uuid,
    pub credential_id: String,
}

/// POST /api/signup/finish — verify the passkey and activate the account
/// atomically with its first credential. Deliberately does NOT mint a full
/// session: the client then logs in with the new passkey (`login/finish`) to
/// obtain one, so a full session always reflects a real, user-verified
/// assertion (and `amr` is honest).
#[utoipa::path(
    post, path = "/api/signup/finish", tag = "signup",
    responses(
        (status = 200, description = "{ user_id, credential_id }"),
        (status = 400, body = super::ErrorResponse),
        (status = 403, body = super::ErrorResponse),
    ),
)]
pub async fn finish(
    State(state): State<AppState>,
    AnySession(session): AnySession,
    Json(req): Json<FinishRequest>,
) -> Result<Json<FinishResponse>, ApiError> {
    let (owner, reg_state): (Option<Uuid>, PasskeyRegistration) = state
        .store
        .consume_ceremony(&req.ceremony_id, CeremonyPurpose::Signup)
        .await?
        .ok_or_else(|| ApiError::BadRequest("ceremony expired — try again".to_string()))?;
    if owner != Some(session.user_id) {
        return Err(ApiError::Forbidden);
    }
    // User verification is enforced by webauthn-rs (passkey registration
    // requires it by default); a non-user-verified authenticator fails here.
    let passkey = state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            tracing::info!(target: "audit", event = "passkey_register_failed", error = %e);
            ApiError::BadRequest("passkey registration failed".to_string())
        })?;
    let credential_id = b64u(passkey.cred_id());
    let name = credential_name(req.name.as_deref());
    state
        .store
        .activate_user_with_first_credential(session.user_id, &credential_id, &passkey, &name)
        .await
        .map_err(|e| match e {
            crate::store::StoreError::ConditionFailed => {
                ApiError::BadRequest("account already set up — sign in".to_string())
            }
            other => other.into(),
        })?;
    tracing::info!(target: "audit", event = "signup_completed", user_id = %session.user_id);
    Ok(Json(FinishResponse {
        user_id: session.user_id,
        credential_id,
    }))
}

/// Sanitize a user-supplied nickname into safe, display-only text: strips
/// Unicode control, bidirectional-override, and zero-width characters (which
/// enable display-spoofing in the passkey chooser and RP UIs), trims, and
/// bounds the length to 64 characters. Returns `None` if nothing usable
/// remains. The nickname is never an identifier — RPs must treat it as mutable,
/// untrusted display data and HTML-escape it.
fn sanitize_nickname(input: &str) -> Option<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c,
                    '\u{00AD}'                // soft hyphen
                    | '\u{061C}'              // arabic letter mark (bidi)
                    | '\u{180E}'              // mongolian vowel separator
                    | '\u{200B}'..='\u{200F}' // zero-width chars + LTR/RTL marks
                    | '\u{202A}'..='\u{202E}' // bidi embeddings / overrides
                    | '\u{2060}'..='\u{2064}' // word joiner / invisible operators
                    | '\u{2066}'..='\u{2069}' // bidi isolates
                    | '\u{FEFF}'              // BOM / zero-width no-break space
                    | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation anchors
                )
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(64).collect())
}

fn credential_name(name: Option<&str>) -> String {
    name.map(str::trim)
        .filter(|n| !n.is_empty() && n.chars().count() <= 64)
        .map(str::to_string)
        .unwrap_or_else(|| "Passkey".to_string())
}

async fn rate_limit_signup(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    if !state
        .store
        .rate_allow(RateClass::SignupIp, &rate_ip_key(headers))
        .await?
    {
        return Err(ApiError::RateLimited);
    }
    if let Some(asn) = client_asn(headers)
        && !state.store.rate_allow(RateClass::SignupAsn, &asn).await?
    {
        return Err(ApiError::RateLimited);
    }
    Ok(())
}
