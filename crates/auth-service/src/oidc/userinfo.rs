use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use uuid::Uuid;

use super::{dpop, verify_own_jws};
use crate::domain::oauth::{SCOPE_PROFILE, scope_contains};
use crate::state::AppState;
use crate::store::now;

/// GET|POST /oauth/userinfo — claims for an access token. A DPoP-bound token
/// (`cnf.jkt` present) additionally requires a matching DPoP proof; a plain
/// bearer token is accepted as before.
pub async fn userinfo(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                r#"Bearer error="invalid_token", DPoP error="invalid_token""#,
            )],
        )
            .into_response()
    };

    // Accept the token under either the `Bearer` or `DPoP` auth scheme.
    let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("DPoP "))
        })
    else {
        return unauthorized();
    };
    // Only an access token may hit userinfo. Enforce the media type explicitly
    // (RFC 9068 §4 / RFC 8725 §3.11) rather than inferring from the presence of
    // a `client_id` claim: an id_token (typ "JWT") or logout token
    // (typ "logout+jwt") must be rejected here even though they share a signer.
    if jsonwebtoken::decode_header(token)
        .ok()
        .and_then(|h| h.typ)
        .as_deref()
        != Some("at+jwt")
    {
        return unauthorized();
    }
    let Some(claims) = verify_own_jws(&state.signer, &state.cfg.issuer, token) else {
        return unauthorized();
    };
    let scope = claims["scope"].as_str().unwrap_or_default().to_string();
    let Some(sub) = claims["sub"].as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
        return unauthorized();
    };

    // DPoP: if the access token is sender-constrained, the request MUST present
    // a proof for the same key, hashed to this token (`ath`), bound to this
    // method/URI. A stolen DPoP-bound token is useless without the proof.
    if let Some(expected_jkt) = claims["cnf"]["jkt"].as_str() {
        let htu = format!("{}/oauth/userinfo", state.cfg.issuer);
        let Some(proof) = headers.get("dpop").and_then(|v| v.to_str().ok()) else {
            return unauthorized();
        };
        let ath = dpop::access_token_hash(token);
        let Ok(verified) = dpop::verify_proof(proof, method.as_str(), &htu, Some(&ath), now())
        else {
            return unauthorized();
        };
        if verified.jkt != expected_jkt {
            return unauthorized();
        }
        match state
            .store
            .record_dpop_jti(&verified.jkt, &verified.jti)
            .await
        {
            Ok(true) => {}
            Ok(false) => return unauthorized(), // replay
            Err(error) => {
                tracing::error!(?error, "userinfo: dpop jti record failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    let user = match state.store.get_user(sub).await {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized(),
        Err(error) => {
            tracing::error!(?error, "userinfo: user lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut body = json!({ "sub": user.user_id });
    if scope_contains(&scope, SCOPE_PROFILE) {
        body["nickname"] = json!(user.nickname);
        body["updated_at"] = json!(user.updated_at);
    }
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(body),
    )
        .into_response()
}
