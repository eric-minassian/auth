//! WebAuthn Level 3 JSON response handling on top of the verified checks.
//!
//! This module decodes `RegistrationResponseJSON` / `AuthenticationResponseJSON`
//! (the output of `PublicKeyCredential.prototype.toJSON()`) and hands the raw
//! bytes to [`crate::decide`]. It makes no security decisions of its own
//! beyond structural validation.

use crate::b64;
use crate::decide::{self, AssertionOk, NewCredential, Reject, RpPolicy, StoredCredential};
use serde::{Deserialize, Serialize};

/// Errors from response handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebauthnError {
    /// The JSON structure is wrong (bad base64url, `id` ≠ `rawId`, wrong `type`).
    Malformed,
    /// A verified check rejected the response.
    Rejected(Reject),
}

impl core::fmt::Display for WebauthnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WebauthnError::Malformed => f.write_str("malformed WebAuthn response"),
            WebauthnError::Rejected(r) => write!(f, "WebAuthn response rejected: {r:?}"),
        }
    }
}

impl std::error::Error for WebauthnError {}

/// `AuthenticatorAttestationResponseJSON`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestationResponseJson {
    /// base64url `clientDataJSON`.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// base64url `attestationObject`.
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// Reported transports (informational).
    #[serde(default)]
    pub transports: Vec<String>,
}

/// `RegistrationResponseJSON`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistrationResponseJson {
    /// base64url credential ID.
    pub id: String,
    /// base64url credential ID (must equal `id`).
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Must be `public-key`.
    #[serde(rename = "type")]
    pub typ: String,
    /// The attestation response.
    pub response: AttestationResponseJson,
}

/// `AuthenticatorAssertionResponseJSON`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AssertionResponseJson {
    /// base64url `clientDataJSON`.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// base64url `authenticatorData`.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// base64url signature.
    pub signature: String,
    /// base64url user handle.
    #[serde(
        rename = "userHandle",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub user_handle: Option<String>,
}

/// `AuthenticationResponseJSON`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthenticationResponseJson {
    /// base64url credential ID.
    pub id: String,
    /// base64url credential ID (must equal `id`).
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Must be `public-key`.
    #[serde(rename = "type")]
    pub typ: String,
    /// The assertion response.
    pub response: AssertionResponseJson,
}

/// Transport hints WebAuthn defines; anything else is dropped.
const KNOWN_TRANSPORTS: [&str; 6] = ["ble", "hybrid", "internal", "nfc", "smart-card", "usb"];

/// A verified new credential plus informational metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// COSE_Key bytes as encoded by the authenticator.
    pub cose_key: Vec<u8>,
    /// COSE algorithm.
    pub alg: i64,
    /// Initial signature counter.
    pub sign_count: u32,
    /// Authenticator model identifier (all zeros for most passkey providers).
    pub aaguid: [u8; 16],
    /// Backup eligibility (fixed for the credential's lifetime).
    pub backup_eligible: bool,
    /// Current backup state.
    pub backup_state: bool,
    /// Known transports, deduplicated and sorted.
    pub transports: Vec<String>,
}

fn credential_id(id: &str, raw_id: &str, typ: &str) -> Result<Vec<u8>, WebauthnError> {
    if typ != "public-key" || id != raw_id {
        return Err(WebauthnError::Malformed);
    }
    b64::decode_str(raw_id).ok_or(WebauthnError::Malformed)
}

fn decode(s: &str) -> Result<Vec<u8>, WebauthnError> {
    b64::decode_str(s).ok_or(WebauthnError::Malformed)
}

/// Extracts the challenge from a `clientDataJSON` without verifying anything,
/// so the caller can look up (and consume) the matching ceremony record. The
/// verified check compares it again against the consumed record.
pub fn challenge_of(client_data_json_b64: &str) -> Option<Vec<u8>> {
    let raw = b64::decode_str(client_data_json_b64)?;
    crate::wire::parse_client_data(&raw).map(|cd| cd.challenge)
}

/// Verifies a registration response.
pub fn verify_registration(
    policy: &RpPolicy,
    challenge: &[u8],
    resp: &RegistrationResponseJson,
) -> Result<RegisteredCredential, WebauthnError> {
    let raw_id = credential_id(&resp.id, &resp.raw_id, &resp.typ)?;
    let cdj = decode(&resp.response.client_data_json)?;
    let att = decode(&resp.response.attestation_object)?;
    let c: NewCredential = decide::check_registration(policy, challenge, &cdj, &att, &raw_id)
        .map_err(WebauthnError::Rejected)?;
    let aaguid = <[u8; 16]>::try_from(c.aaguid.as_slice()).map_err(|_| WebauthnError::Malformed)?;
    let mut transports: Vec<String> = resp
        .response
        .transports
        .iter()
        .filter(|t| KNOWN_TRANSPORTS.contains(&t.as_str()))
        .cloned()
        .collect();
    transports.sort();
    transports.dedup();
    Ok(RegisteredCredential {
        credential_id: c.credential_id,
        cose_key: c.cose_key,
        alg: c.alg,
        sign_count: c.sign_count,
        aaguid,
        backup_eligible: c.backup_eligible,
        backup_state: c.backup_state,
        transports,
    })
}

/// The identifiers an authentication response claims, for looking up the
/// stored credential. Returns `(credential_id, user_handle)`.
pub fn assertion_ids(
    resp: &AuthenticationResponseJson,
) -> Result<(Vec<u8>, Option<Vec<u8>>), WebauthnError> {
    let raw_id = credential_id(&resp.id, &resp.raw_id, &resp.typ)?;
    let uh = match &resp.response.user_handle {
        Some(u) => Some(decode(u)?),
        None => None,
    };
    Ok((raw_id, uh))
}

/// Verifies an authentication response against a stored credential.
pub fn verify_authentication(
    policy: &RpPolicy,
    challenge: &[u8],
    stored: &StoredCredential,
    resp: &AuthenticationResponseJson,
) -> Result<AssertionOk, WebauthnError> {
    let (raw_id, user_handle) = assertion_ids(resp)?;
    let cdj = decode(&resp.response.client_data_json)?;
    let ad = decode(&resp.response.authenticator_data)?;
    let sig = decode(&resp.response.signature)?;
    decide::check_assertion(
        policy,
        challenge,
        stored,
        &cdj,
        &ad,
        &sig,
        &raw_id,
        &user_handle,
    )
    .map_err(WebauthnError::Rejected)
}
