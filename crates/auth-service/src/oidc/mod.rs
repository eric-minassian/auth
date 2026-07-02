pub mod authorize;
pub mod cors;
pub mod discovery;
pub mod dpop;
pub mod jwks;
pub mod logout;
pub mod pkce;
pub mod revoke;
pub mod security_txt;
pub mod token;
pub mod userinfo;

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// RFC 6749 §5.2 error response for the token/revocation endpoints.
/// Descriptions are deliberately non-specific (no "expired vs replayed").
#[derive(Default)]
pub struct OAuthError {
    pub error: &'static str,
    pub description: &'static str,
    /// Fresh server nonce for a `use_dpop_nonce` challenge (RFC 9449 §8),
    /// emitted as a `DPoP-Nonce` response header.
    pub dpop_nonce: Option<String>,
}

impl OAuthError {
    pub fn invalid_request(description: &'static str) -> Self {
        Self {
            error: "invalid_request",
            description,
            ..Self::default()
        }
    }

    /// RFC 9449 §8: the client must retry with this server nonce echoed in a
    /// fresh proof. The SDK (and any conformant DPoP client) does so
    /// transparently.
    pub fn use_dpop_nonce(nonce: String) -> Self {
        Self {
            error: "use_dpop_nonce",
            description: "a server nonce is required in the DPoP proof",
            dpop_nonce: Some(nonce),
        }
    }

    pub fn invalid_grant() -> Self {
        Self {
            error: "invalid_grant",
            description: "the provided grant is invalid",
            ..Self::default()
        }
    }

    pub fn invalid_client() -> Self {
        Self {
            error: "invalid_client",
            description: "unknown client",
            ..Self::default()
        }
    }

    pub fn unsupported_grant_type() -> Self {
        Self {
            error: "unsupported_grant_type",
            description: "only authorization_code and refresh_token are supported",
            ..Self::default()
        }
    }

    pub fn server_error() -> Self {
        Self {
            error: "server_error",
            description: "internal error",
            ..Self::default()
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = match self.error {
            "invalid_client" => StatusCode::UNAUTHORIZED,
            "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
            // Rate limiting is an HTTP-level condition, not an OAuth grant
            // error — 429 lets clients back off generically.
            "slow_down" => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::BAD_REQUEST,
        };
        let mut response = (
            status,
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({ "error": self.error, "error_description": self.description })),
        )
            .into_response();
        if let Some(nonce) = self.dpop_nonce
            && let Ok(value) = axum::http::HeaderValue::from_str(&nonce)
        {
            response.headers_mut().insert("dpop-nonce", value);
        }
        response
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
/// Returns the raw claims after checking signature, `typ`, and issuer; None on
/// any failure (callers respond uniformly).
///
/// `expected_typ` pins the token class: without it an access token
/// (`at+jwt`) would pass wherever an id_token is expected, and vice versa —
/// same key, same issuer, different authority. `allow_expired` exists for
/// `id_token_hint` at RP-initiated logout, where the hint is routinely
/// presented after the id_token's 5-minute lifetime (OIDC RP-Initiated
/// Logout §2: expired hints SHOULD still be accepted for identifying the
/// session); signature and issuer are still enforced.
pub fn verify_own_jws(
    signer: &crate::jwt::Signer,
    issuer: &str,
    token: &str,
    expected_typ: &str,
    allow_expired: bool,
) -> Option<serde_json::Value> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    // RFC 7515 §4.1.9: typ comparisons are case-insensitive, and bare values
    // are equivalent to their application/-prefixed form.
    let typ = header.typ.as_deref()?;
    let typ = typ.strip_prefix("application/").unwrap_or(typ);
    if !typ.eq_ignore_ascii_case(expected_typ) {
        return None;
    }
    // Select the published key matching the token's kid — during a keyring
    // rotation, tokens signed by the previous key must still verify while it
    // remains published. No kid (or no match) falls back to the active key.
    let header_kid = header.kid;
    let jwks = signer.public_jwks();
    let jwk_value = header_kid
        .as_deref()
        .and_then(|kid| {
            jwks.iter()
                .find(|j| j.get("kid").and_then(serde_json::Value::as_str) == Some(kid))
        })
        .or_else(|| jwks.first())?
        .clone();
    let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk_value).ok()?;
    let key = jsonwebtoken::DecodingKey::from_jwk(&jwk).ok()?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[issuer]);
    // aud varies per registered client; callers check it where it matters.
    validation.validate_aud = false;
    validation.validate_exp = !allow_expired;
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
