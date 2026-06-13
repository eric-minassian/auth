pub mod authorize;
pub mod cors;
pub mod discovery;
pub mod jwks;
pub mod pkce;
pub mod revoke;
pub mod token;
pub mod userinfo;

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// RFC 6749 §5.2 error response for the token/revocation endpoints.
/// Descriptions are deliberately non-specific (no "expired vs replayed").
pub struct OAuthError {
    pub error: &'static str,
    pub description: &'static str,
}

impl OAuthError {
    pub fn invalid_request(description: &'static str) -> Self {
        Self {
            error: "invalid_request",
            description,
        }
    }

    pub fn invalid_grant() -> Self {
        Self {
            error: "invalid_grant",
            description: "the provided grant is invalid",
        }
    }

    pub fn invalid_client() -> Self {
        Self {
            error: "invalid_client",
            description: "unknown client",
        }
    }

    pub fn unsupported_grant_type() -> Self {
        Self {
            error: "unsupported_grant_type",
            description: "only authorization_code and refresh_token are supported",
        }
    }

    pub fn server_error() -> Self {
        Self {
            error: "server_error",
            description: "internal error",
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = match self.error {
            "invalid_client" => StatusCode::UNAUTHORIZED,
            "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        };
        (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({ "error": self.error, "error_description": self.description })),
        )
            .into_response()
    }
}

impl From<crate::store::StoreError> for OAuthError {
    fn from(e: crate::store::StoreError) -> Self {
        tracing::error!(error = ?e, "store error in oauth endpoint");
        Self::server_error()
    }
}

impl From<crate::jwt::SignError> for OAuthError {
    fn from(e: crate::jwt::SignError) -> Self {
        tracing::error!(error = ?e, "signing error in oauth endpoint");
        Self::server_error()
    }
}

/// Verify a JWS this service issued (userinfo bearer tokens, id_token_hint).
/// Returns the raw claims after checking signature, exp, and issuer; None on
/// any failure (callers respond uniformly).
pub fn verify_own_jws(
    signer: &crate::jwt::Signer,
    issuer: &str,
    token: &str,
) -> Option<serde_json::Value> {
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(signer.public_jwk()).ok()?;
    let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).ok()?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[issuer]);
    // aud varies per registered client; callers check it where it matters.
    validation.validate_aud = false;
    let claims =
        jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation).map(|data| data.claims);
    match claims {
        Ok(claims) => Some(claims),
        Err(error) => {
            tracing::debug!(%error, "jws verification failed");
            None
        }
    }
}
