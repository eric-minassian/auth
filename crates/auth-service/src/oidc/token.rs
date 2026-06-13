use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{OAuthError, pkce};
use crate::api::client_ip;
use crate::crypto::random_b64u;
use crate::domain::oauth::{SCOPE_EMAIL, SCOPE_OFFLINE_ACCESS, SCOPE_OPENID, scope_contains};
use crate::domain::user::User;
use crate::jwt::claims::{
    ACCESS_TOKEN_TTL_SECS, AccessTokenClaims, ID_TOKEN_TTL_SECS, IdTokenClaims,
};
use crate::state::AppState;
use crate::store::now;
use crate::store::oauth::{CodeConsume, RotateOutcome};
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
    let ip = client_ip(&headers);
    if !state
        .store
        .rate_allow(RateClass::TokenIp, &ip)
        .await
        .map_err(OAuthError::from)?
    {
        return Err(OAuthError {
            error: "slow_down",
            description: "rate limited",
        });
    }

    let response = match req.grant_type.as_str() {
        "authorization_code" => exchange_code(&state, &req).await?,
        "refresh_token" => refresh(&state, &req).await?,
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

async fn exchange_code(state: &AppState, req: &TokenRequest) -> Result<TokenResponse, OAuthError> {
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
            tracing::warn!(target: "audit", event = "code_replayed", client_id);
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
            refresh_token,
        },
    )
    .await
}

async fn refresh(state: &AppState, req: &TokenRequest) -> Result<TokenResponse, OAuthError> {
    let token = req
        .refresh_token
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    let client_id = req
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("client_id is required"))?;

    let (family, new_token) = match state.store.rotate_refresh_token(token).await? {
        RotateOutcome::Rotated { family, new_token } => (family, new_token),
        RotateOutcome::ReuseDetected { family } => {
            tracing::warn!(
                target: "audit",
                event = "refresh_reuse_detected",
                client_id = %family.client_id,
                user_id = %family.user_id,
                family_id = %family.family_id,
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
    let session_alive = state
        .store
        .get_session_by_hash(&family.sid_hash)
        .await?
        .is_some_and(|s| !s.is_expired(now()));
    if !session_alive {
        state
            .store
            .revoke_refresh_family(&family.family_id, "session_gone")
            .await?;
        return Err(OAuthError::invalid_grant());
    }

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
            auth_time: family.created_at,
            amr: &["webauthn".to_string()],
            refresh_token: Some(new_token),
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
    refresh_token: Option<String>,
}

async fn mint(state: &AppState, input: MintInput<'_>) -> Result<TokenResponse, OAuthError> {
    let ts = now();
    let email_scope = scope_contains(input.scope, SCOPE_EMAIL);

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
        email: email_scope.then(|| input.user.email.clone()),
    };
    let access_token = state.signer.sign("at+jwt", &access).await?;

    let id_token = if scope_contains(input.scope, SCOPE_OPENID) {
        let id = IdTokenClaims {
            iss: state.cfg.issuer.clone(),
            sub: input.user.user_id.to_string(),
            aud: input.client_id.to_string(),
            iat: ts,
            exp: ts + ID_TOKEN_TTL_SECS,
            auth_time: input.auth_time,
            sid: input.sid_hash.to_string(),
            amr: input.amr.to_vec(),
            nonce: input.nonce.map(str::to_string),
            email: email_scope.then(|| input.user.email.clone()),
            email_verified: email_scope.then_some(input.user.email_verified),
        };
        Some(state.signer.sign("JWT", &id).await?)
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: input.scope.to_string(),
        id_token,
        refresh_token: input.refresh_token,
    })
}
