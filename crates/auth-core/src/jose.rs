//! Building the JWTs this service issues (protocol §6).
//!
//! Signing itself happens in AWS KMS; this module only produces the exact
//! signing input and assembles the compact serialization. Claim names and
//! types here must match the trusted parsers in [`crate::wire`]; the
//! round-trip tests below and in `auth-service` keep them in sync.

use crate::b64;
use crate::vtypes::VerifyKey;
use serde::{Deserialize, Serialize};

/// `typ` of access tokens (RFC 9068).
pub const TYP_ACCESS: &str = "at+jwt";
/// `typ` of refresh tokens.
pub const TYP_REFRESH: &str = "rt+jwt";
/// `typ` of DPoP proofs (RFC 9449).
pub const TYP_DPOP: &str = "dpop+jwt";
/// The only signature algorithm used anywhere.
pub const ALG: &str = "ES256";

/// Authentication methods (RFC 8176): proof of possession of a key, with user
/// verification making it multi-factor.
pub const AMR: [&str; 2] = ["pop", "mfa"];

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'a str,
    kid: &'a str,
}

/// Confirmation claim (RFC 9449 §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    /// base64url JWK SHA-256 thumbprint.
    pub jkt: String,
}

/// Access token claims (protocol §6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub auth_time: u64,
    pub amr: Vec<String>,
    pub cnf: Cnf,
    /// Session ID (constant across refreshes).
    pub sid: String,
    /// base64url credential ID of the passkey that started the session.
    pub cid: String,
    /// base64url registration ID of that passkey.
    pub rid: String,
    /// Account session epoch when the session started.
    pub epoch: u64,
}

/// Refresh token claims (protocol §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub client_id: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub sid: String,
    pub auth_time: u64,
    pub cid: String,
    pub rid: String,
    pub epoch: u64,
    pub cnf: Cnf,
}

/// The `kid` of a P-256 key: its RFC 7638 thumbprint.
pub fn kid_for(x: &[u8; 32], y: &[u8; 32]) -> String {
    b64::encode(&crate::crypto::jwk_thumbprint_p256(x, y))
}

/// A verification key for [`crate::decide`], with `kid` = thumbprint.
pub fn verify_key(x: &[u8; 32], y: &[u8; 32]) -> VerifyKey {
    VerifyKey {
        kid: kid_for(x, y).into_bytes(),
        x: x.to_vec(),
        y: y.to_vec(),
    }
}

/// Public JWK (RFC 7517) for a JWKS document.
pub fn public_jwk(x: &[u8; 32], y: &[u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64::encode(x),
        "y": b64::encode(y),
        "kid": kid_for(x, y),
        "alg": ALG,
        "use": "sig",
    })
}

/// `BASE64URL(header) || '.' || BASE64URL(claims)`.
pub fn signing_input<C: Serialize>(
    typ: &str,
    kid: &str,
    claims: &C,
) -> Result<String, serde_json::Error> {
    let header = serde_json::to_vec(&Header { alg: ALG, typ, kid })?;
    let payload = serde_json::to_vec(claims)?;
    Ok(format!(
        "{}.{}",
        b64::encode(&header),
        b64::encode(&payload)
    ))
}

/// Appends a fixed-form ES256 signature to a signing input.
pub fn compact(signing_input: &str, signature: &[u8; 64]) -> String {
    format!("{signing_input}.{}", b64::encode(signature))
}
