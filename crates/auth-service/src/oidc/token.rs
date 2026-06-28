use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{OAuthError, dpop, pkce};
use crate::api::AbuseContext;
use crate::crypto::random_b64u;
use crate::domain::oauth::{SCOPE_OFFLINE_ACCESS, SCOPE_OPENID, SCOPE_PROFILE, scope_contains};
use crate::domain::session::ACR_PHISHING_RESISTANT;
use crate::domain::user::User;
use crate::jwt::claims::{
    ACCESS_TOKEN_TTL_SECS, AccessTokenClaims, Cnf, ID_TOKEN_TTL_SECS, IdTokenClaims,
};
use crate::state::AppState;
use crate::store::now;
use crate::store::oauth::{CodeConsume, RotateOutcome, decode_refresh_token};
use crate::store::rate_limit::RateClass;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// POST /oauth/token — authorization_code (with PKCE) and refresh_token
/// grants for public clients.
#[utoipa::path(
    post,
    path = "/oauth/token",
    tag = "oidc",
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, body = TokenResponse),
        (status = 400, description = "OAuth error (RFC 6749 §5.2)"),
    ),
)]
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Result<Response, OAuthError> {
    let abuse = AbuseContext::from_headers(&headers);
    if !state
        .store
        .rate_allow(RateClass::TokenIp, &abuse.ip)
        .await
        .map_err(OAuthError::from)?
    {
        return Err(OAuthError {
            error: "slow_down",
            description: "rate limited",
        });
    }

    // If the request carries a DPoP proof, validate it once here and bind the
    // issued tokens to its key. Absent a proof, tokens are plain bearer
    // (incremental rollout — DPoP is honored, not required).
    let htu = format!("{}/oauth/token", state.cfg.issuer);
    let dpop_jkt = dpop_binding(&state, &headers, &htu).await?;

    // A client may opt into requiring DPoP: with no proof, reject before issuing
    // an unbound bearer token. Only look up the client in the rejectable case
    // (no proof) — a presented proof satisfies the requirement regardless.
    if dpop_jkt.is_none()
        && let Some(client_id) = req.client_id.as_deref()
        && state
            .store
            .get_client(client_id)
            .await?
            .is_some_and(|client| client.require_dpop)
    {
        return Err(invalid_dpop("DPoP proof required for this client"));
    }

    let response = match req.grant_type.as_str() {
        "authorization_code" => exchange_code(&state, &req, dpop_jkt.as_deref(), &abuse).await?,
        "refresh_token" => refresh(&state, &req, dpop_jkt.as_deref(), &abuse).await?,
        _ => return Err(OAuthError::unsupported_grant_type()),
    };
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(response),
    )
        .into_response())
}

fn invalid_dpop(description: &'static str) -> OAuthError {
    OAuthError {
        error: "invalid_dpop_proof",
        description,
    }
}

/// Validate a DPoP proof presented with this token request, if any, and return
/// the key thumbprint to sender-constrain the issued tokens. `None` = a plain
/// bearer request. A malformed or replayed proof is a hard `invalid_dpop_proof`.
async fn dpop_binding(
    state: &AppState,
    headers: &HeaderMap,
    htu: &str,
) -> Result<Option<String>, OAuthError> {
    let mut proofs = headers.get_all("dpop").iter();
    let Some(first) = proofs.next() else {
        return Ok(None);
    };
    // Exactly one proof is permitted (RFC 9449 §4.1).
    if proofs.next().is_some() {
        return Err(invalid_dpop("multiple DPoP proofs"));
    }
    let proof = first
        .to_str()
        .map_err(|_| invalid_dpop("malformed DPoP header"))?;
    let verified = dpop::verify_proof(proof, "POST", htu, None, now())
        .map_err(|_| invalid_dpop("invalid DPoP proof"))?;
    // One-time-use: reject a replayed proof.
    if !state
        .store
        .record_dpop_jti(&verified.jkt, &verified.jti)
        .await?
    {
        return Err(invalid_dpop("DPoP proof replay"));
    }
    Ok(Some(verified.jkt))
}

async fn exchange_code(
    state: &AppState,
    req: &TokenRequest,
    dpop_jkt: Option<&str>,
    abuse: &AbuseContext,
) -> Result<TokenResponse, OAuthError> {
    let code = req
        .code
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
    let client_id = req
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("client_id is required"))?;
    let verifier = req
        .code_verifier
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("code_verifier is required"))?;
    let redirect_uri = req
        .redirect_uri
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;

    // Pre-generate the family id so the consume tombstone can reference it
    // (replay → revoke the family minted here).
    let family_id = random_b64u(16);
    let data = match state.store.consume_auth_code(code, &family_id).await? {
        CodeConsume::Consumed(data) => data,
        CodeConsume::Replayed { issued_family_id } => {
            tracing::warn!(target: "audit", event = "code_replayed", client_id, ip = %abuse.ip, asn = abuse.asn.as_deref());
            if let Some(family) = issued_family_id {
                state
                    .store
                    .revoke_refresh_family(&family, "code_replay")
                    .await?;
            }
            return Err(OAuthError::invalid_grant());
        }
        CodeConsume::Invalid => return Err(OAuthError::invalid_grant()),
    };

    // Bindings: client, redirect_uri, PKCE.
    if data.client_id != client_id
        || data.redirect_uri != redirect_uri
        || !pkce::verify_s256(&data.code_challenge, verifier)
    {
        return Err(OAuthError::invalid_grant());
    }

    let user = state
        .store
        .get_user(data.user_id)
        .await?
        .ok_or_else(OAuthError::invalid_grant)?;

    let refresh_token = if scope_contains(&data.scope, SCOPE_OFFLINE_ACCESS) {
        Some(
            state
                .store
                .create_refresh_family(
                    &family_id,
                    data.user_id,
                    client_id,
                    &data.sid_hash,
                    &data.scope,
                    dpop_jkt,
                )
                .await?,
        )
    } else {
        None
    };

    tracing::info!(target: "audit", event = "code_exchanged", client_id, user_id = %data.user_id);
    mint(
        state,
        MintInput {
            client_id,
            user: &user,
            sid_hash: &data.sid_hash,
            scope: &data.scope,
            nonce: data.nonce.as_deref(),
            auth_time: data.auth_time,
            amr: &data.amr,
            // The acr resolved at /authorize (`phr` / `phr-stepup`); fall back to
            // the phishing-resistant baseline for a code minted before the field
            // existed (transient, ≤60s TTL).
            acr: if data.acr.is_empty() {
                ACR_PHISHING_RESISTANT
            } else {
                &data.acr
            },
            refresh_token,
            dpop_jkt,
        },
    )
    .await
}

async fn refresh(
    state: &AppState,
    req: &TokenRequest,
    dpop_jkt: Option<&str>,
    abuse: &AbuseContext,
) -> Result<TokenResponse, OAuthError> {
    let token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    let client_id = req
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("client_id is required"))?;

    // DPoP gate, checked BEFORE the token is consumed: a sender-constrained
    // family may only be rotated by presenting a proof for the same key. This
    // is the crux of sender-constraining — an exfiltrated refresh token is
    // useless without the (in the browser, non-extractable) DPoP private key.
    // Gating before rotation also stops a key-less holder from
    // rotating-and-discarding the token to lock out the legitimate client.
    if let Some((family_id, _)) = decode_refresh_token(token)
        && let Some(family) = state.store.get_refresh_family(family_id).await?
        && let Some(expected) = family.dpop_jkt.as_deref()
        && dpop_jkt != Some(expected)
    {
        return Err(invalid_dpop("DPoP key mismatch"));
    }

    let (family, new_token) = match state.store.rotate_refresh_token(token).await? {
        RotateOutcome::Rotated { family, new_token } => (family, new_token),
        RotateOutcome::ReuseDetected { family } => {
            tracing::warn!(
                target: "audit",
                event = "refresh_reuse_detected",
                client_id = %family.client_id,
                user_id = %family.user_id,
                family_id = %family.family_id,
                ip = %abuse.ip,
                asn = abuse.asn.as_deref(),
            );
            return Err(OAuthError::invalid_grant());
        }
        RotateOutcome::Invalid => return Err(OAuthError::invalid_grant()),
    };

    if family.client_id != client_id {
        // Token presented by the wrong client — treat as compromise.
        state
            .store
            .revoke_refresh_family(&family.family_id, "client_mismatch")
            .await?;
        return Err(OAuthError::invalid_grant());
    }

    // The IdP session backing this family must still be alive: refresh
    // tokens die with the session (logout cascade).
    let session = state.store.get_session_by_hash(&family.sid_hash).await?;
    let Some(session) = session.filter(|s| !s.is_expired(now())) else {
        state
            .store
            .revoke_refresh_family(&family.family_id, "session_gone")
            .await?;
        return Err(OAuthError::invalid_grant());
    };

    let user = state
        .store
        .get_user(family.user_id)
        .await?
        .ok_or_else(OAuthError::invalid_grant)?;

    tracing::info!(target: "audit", event = "refresh_rotated", client_id, user_id = %family.user_id);
    mint(
        state,
        MintInput {
            client_id,
            user: &user,
            sid_hash: &family.sid_hash,
            scope: &family.scope,
            nonce: None,
            auth_time: session.created_at,
            // Carry the session's real authentication methods rather than a
            // hardcoded value. Refresh families are only ever backed by full
            // sessions (login_finish), so today this is always ["webauthn"].
            amr: &session.amr,
            // A refresh carries the phishing-resistant baseline. The stepped-up
            // acr is point-in-time at the authorize event; it must not silently
            // persist across refreshes — an RP that needs it re-challenges.
            acr: ACR_PHISHING_RESISTANT,
            refresh_token: Some(new_token),
            // The new access token stays bound to the family's DPoP key.
            dpop_jkt: family.dpop_jkt.as_deref(),
        },
    )
    .await
}

struct MintInput<'a> {
    client_id: &'a str,
    user: &'a User,
    sid_hash: &'a str,
    scope: &'a str,
    nonce: Option<&'a str>,
    auth_time: i64,
    amr: &'a [String],
    /// Authentication Context Class Reference to stamp (`phr` / `phr-stepup`).
    acr: &'a str,
    refresh_token: Option<String>,
    dpop_jkt: Option<&'a str>,
}

async fn mint(state: &AppState, input: MintInput<'_>) -> Result<TokenResponse, OAuthError> {
    let ts = now();

    let access = AccessTokenClaims {
        iss: state.cfg.issuer.clone(),
        sub: input.user.user_id.to_string(),
        aud: input.client_id.to_string(),
        client_id: input.client_id.to_string(),
        scope: input.scope.to_string(),
        sid: input.sid_hash.to_string(),
        iat: ts,
        exp: ts + ACCESS_TOKEN_TTL_SECS,
        jti: Uuid::now_v7().to_string(),
        acr: input.acr.to_string(),
        amr: input.amr.to_vec(),
        cnf: input.dpop_jkt.map(|jkt| Cnf {
            jkt: jkt.to_string(),
        }),
    };
    let access_token = state.signer.sign("at+jwt", &access).await?;

    let id_token = if scope_contains(input.scope, SCOPE_OPENID) {
        let profile = scope_contains(input.scope, SCOPE_PROFILE);
        let id = IdTokenClaims {
            iss: state.cfg.issuer.clone(),
            sub: input.user.user_id.to_string(),
            aud: input.client_id.to_string(),
            iat: ts,
            exp: ts + ID_TOKEN_TTL_SECS,
            auth_time: input.auth_time,
            sid: input.sid_hash.to_string(),
            amr: input.amr.to_vec(),
            acr: input.acr.to_string(),
            nonce: input.nonce.map(str::to_string),
            nickname: profile.then(|| input.user.nickname.clone()),
            updated_at: profile.then_some(input.user.updated_at),
        };
        Some(state.signer.sign("JWT", &id).await?)
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,
        // RFC 9449 §5: a sender-constrained token is returned as `DPoP`, telling
        // the client to present it with a proof at resource servers.
        token_type: if input.dpop_jkt.is_some() {
            "DPoP".to_string()
        } else {
            "Bearer".to_string()
        },
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: input.scope.to_string(),
        id_token,
        refresh_token: input.refresh_token,
    })
}
