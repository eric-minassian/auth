//! HTTP handlers (protocol §10).

pub mod account;
pub mod login;
pub mod recover;
pub mod register;
pub mod token;
pub mod well_known;

use crate::error::ApiError;
use crate::state::AppState;
use auth_core::webauthn::WebauthnError;
use auth_core::{b64, crockford, crypto};
use serde::Deserialize;

/// Body of the `*/verify` endpoints.
#[derive(Debug, Deserialize)]
pub struct VerifyBody<C> {
    /// The client making the request.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Requested audience (RFC 8707).
    #[serde(default)]
    pub resource: Option<String>,
    /// The WebAuthn response.
    pub credential: C,
}

/// Validates `client_id` and `resource`, returning the audience to use.
pub fn client_and_audience(
    state: &AppState,
    client_id: Option<&str>,
    resource: Option<&str>,
) -> Result<(String, String), ApiError> {
    let client_id = client_id.ok_or(ApiError::InvalidRequest("client_id is required"))?;
    if !state.config.client_allowed(client_id) {
        return Err(ApiError::InvalidClient);
    }
    let audience = match resource {
        Some(r) if state.config.audience_allowed(r) => r.to_string(),
        Some(_) => return Err(ApiError::InvalidTarget),
        None => state.config.default_audience().to_string(),
    };
    Ok((client_id.to_string(), audience))
}

/// Maps a WebAuthn failure to an API error.
pub fn webauthn_error(e: WebauthnError) -> ApiError {
    match e {
        WebauthnError::Malformed => ApiError::InvalidRequest("malformed credential"),
        WebauthnError::Rejected(r) => ApiError::WebauthnRejected(format!("{r:?}")),
    }
}

/// A new random recovery code: its display form and its storage key.
pub fn new_recovery_code() -> Result<(String, String), ApiError> {
    let code = crate::random::bytes::<{ crockford::RECOVERY_CODE_LEN }>()?;
    Ok((crockford::encode_recovery_code(&code), recovery_key(&code)))
}

/// The storage key of a recovery code: `base64url(SHA-256(domain || code))`.
pub fn recovery_key(code: &[u8; crockford::RECOVERY_CODE_LEN]) -> String {
    let mut m = b"auth-recovery-v1".to_vec();
    m.extend_from_slice(code);
    b64::encode(&crypto::sha256(&m))
}

/// A new random registration ID (protocol §8).
pub fn new_registration_id() -> Result<[u8; 16], ApiError> {
    crate::random::bytes::<16>()
}

/// A new random session ID.
pub fn new_sid() -> Result<String, ApiError> {
    Ok(b64::encode(&crate::random::bytes::<16>()?))
}
