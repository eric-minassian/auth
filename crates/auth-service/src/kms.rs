//! AWS KMS: token signing keys and the DPoP nonce MAC key (protocol §5, §7.2).
//!
//! Private keys never leave KMS. Every signature KMS returns is converted from
//! DER to the fixed JWS form and verified locally with the key's public half
//! before use, so a misconfigured key or a faulty response can never produce a
//! token that verifiers would reject (or worse, one signed by the wrong key).

use auth_core::decide;
use auth_core::vtypes::VerifyKey;
use auth_core::{b64, crypto, der, jose, spki};
use aws_sdk_kms::Client;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{
    KeySpec, KeyUsageType, MacAlgorithmSpec, MessageType, SigningAlgorithmSpec,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::ApiError;

/// A startup error while loading a key.
#[derive(Debug, thiserror::Error)]
#[error("KMS key {key_id}: {reason}")]
pub struct KeyError {
    key_id: String,
    reason: String,
}

fn key_error(key_id: &str, reason: impl Into<String>) -> KeyError {
    KeyError {
        key_id: key_id.to_string(),
        reason: reason.into(),
    }
}

/// The public half of a P-256 signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// X coordinate.
    pub x: [u8; 32],
    /// Y coordinate.
    pub y: [u8; 32],
}

impl PublicKey {
    /// The `kid` (RFC 7638 thumbprint).
    pub fn kid(&self) -> String {
        jose::kid_for(&self.x, &self.y)
    }

    /// As a verification key.
    pub fn verify_key(&self) -> VerifyKey {
        jose::verify_key(&self.x, &self.y)
    }

    /// As a public JWK.
    pub fn jwk(&self) -> serde_json::Value {
        jose::public_jwk(&self.x, &self.y)
    }
}

/// Loads and validates the public key of an `ECC_NIST_P256` / `SIGN_VERIFY` key.
pub async fn load_public_key(client: &Client, key_id: &str) -> Result<PublicKey, KeyError> {
    let out = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| {
            key_error(
                key_id,
                format!(
                    "GetPublicKey failed: {}",
                    aws_sdk_kms::error::DisplayErrorContext(e)
                ),
            )
        })?;
    if out.key_spec() != Some(&KeySpec::EccNistP256) {
        return Err(key_error(key_id, "key spec must be ECC_NIST_P256"));
    }
    if out.key_usage() != Some(&KeyUsageType::SignVerify) {
        return Err(key_error(key_id, "key usage must be SIGN_VERIFY"));
    }
    if !out
        .signing_algorithms()
        .contains(&SigningAlgorithmSpec::EcdsaSha256)
    {
        return Err(key_error(key_id, "key must support ECDSA_SHA_256"));
    }
    let der = out
        .public_key()
        .ok_or_else(|| key_error(key_id, "no public key returned"))?;
    let (x, y) = spki::p256_xy(der.as_ref())
        .ok_or_else(|| key_error(key_id, "unexpected public key encoding"))?;
    Ok(PublicKey { x, y })
}

/// Loads several keys.
pub async fn load_public_keys(
    client: &Client,
    key_ids: &[String],
) -> Result<Vec<PublicKey>, KeyError> {
    let mut keys = Vec::with_capacity(key_ids.len());
    for id in key_ids {
        keys.push(load_public_key(client, id).await?);
    }
    Ok(keys)
}

/// A KMS-backed JWT signer.
#[derive(Debug, Clone)]
pub struct KmsSigner {
    client: Client,
    key_id: String,
    public: PublicKey,
    kid: String,
}

impl KmsSigner {
    /// Loads the signer for `key_id`.
    pub async fn load(client: Client, key_id: String) -> Result<Self, KeyError> {
        let public = load_public_key(&client, &key_id).await?;
        let kid = public.kid();
        Ok(Self {
            client,
            key_id,
            public,
            kid,
        })
    }

    /// The public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Signs `claims` as a compact JWS with header `{alg: ES256, typ, kid}`.
    pub async fn sign_jwt<C: Serialize + Sync>(
        &self,
        typ: &str,
        claims: &C,
    ) -> Result<String, ApiError> {
        let signing_input =
            jose::signing_input(typ, &self.kid, claims).map_err(ApiError::internal)?;
        let digest = crypto::sha256(signing_input.as_bytes());
        let out = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|e| {
                ApiError::Internal(format!(
                    "KMS Sign failed: {}",
                    aws_sdk_kms::error::DisplayErrorContext(e)
                ))
            })?;
        let der_sig = out
            .signature()
            .ok_or_else(|| ApiError::Internal("KMS Sign returned no signature".into()))?;
        let fixed = der::der_to_fixed(der_sig.as_ref())
            .ok_or_else(|| ApiError::Internal("KMS Sign returned a malformed signature".into()))?;
        if !crypto::verify_es256_jws(
            &self.public.x,
            &self.public.y,
            signing_input.as_bytes(),
            &fixed,
        ) {
            return Err(ApiError::Internal(
                "KMS signature does not verify with the key's public half".into(),
            ));
        }
        Ok(jose::compact(&signing_input, &fixed))
    }
}

/// Validates that `key_id` is an `HMAC_256` / `GENERATE_VERIFY_MAC` key.
pub async fn check_hmac_key(client: &Client, key_id: &str) -> Result<(), KeyError> {
    let out = client
        .describe_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|e| {
            key_error(
                key_id,
                format!(
                    "DescribeKey failed: {}",
                    aws_sdk_kms::error::DisplayErrorContext(e)
                ),
            )
        })?;
    let meta = out
        .key_metadata()
        .ok_or_else(|| key_error(key_id, "no key metadata"))?;
    if meta.key_spec() != Some(&KeySpec::Hmac256)
        || meta.key_usage() != Some(&KeyUsageType::GenerateVerifyMac)
    {
        return Err(key_error(
            key_id,
            "key must be HMAC_256 with GENERATE_VERIFY_MAC usage",
        ));
    }
    Ok(())
}

const NONCE_DOMAIN: &[u8] = b"auth-dpop-nonce-v1";

/// DPoP nonces (protocol §7.2): `base64url(window || HMAC(K, domain || window))`.
///
/// HMAC is deterministic, so the nonce for a window is computed once per
/// instance and cached; validating a proof's nonce is a membership check
/// against the current and previous windows' nonces, done by the verified
/// `decide::check_dpop`.
#[derive(Debug, Clone)]
pub struct NonceService {
    client: Client,
    key_id: String,
    cache: Arc<RwLock<BTreeMap<u64, String>>>,
}

impl NonceService {
    /// A nonce service backed by the HMAC key `key_id`.
    pub fn new(client: Client, key_id: String) -> Self {
        Self {
            client,
            key_id,
            cache: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    async fn nonce_for(&self, window: u64) -> Result<String, ApiError> {
        if let Some(n) = self.cache.read().await.get(&window) {
            return Ok(n.clone());
        }
        let mut msg = NONCE_DOMAIN.to_vec();
        msg.extend_from_slice(&window.to_be_bytes());
        let out = self
            .client
            .generate_mac()
            .key_id(&self.key_id)
            .message(Blob::new(msg))
            .mac_algorithm(MacAlgorithmSpec::HmacSha256)
            .send()
            .await
            .map_err(|e| {
                ApiError::Internal(format!(
                    "KMS GenerateMac failed: {}",
                    aws_sdk_kms::error::DisplayErrorContext(e)
                ))
            })?;
        let mac = out
            .mac()
            .ok_or_else(|| ApiError::Internal("KMS returned no MAC".into()))?;
        let mut raw = window.to_be_bytes().to_vec();
        raw.extend_from_slice(mac.as_ref());
        let nonce = b64::encode(&raw);
        let mut cache = self.cache.write().await;
        cache.insert(window, nonce.clone());
        // Keep only the windows that can still be valid.
        let keep_from = window.saturating_sub(1);
        cache.retain(|w, _| *w >= keep_from);
        Ok(nonce)
    }

    /// The nonce to hand out now.
    pub async fn fresh(&self, now: u64) -> Result<String, ApiError> {
        let (current, _) = decide::nonce_windows(now);
        self.nonce_for(current).await
    }

    /// The nonces accepted now: the current and the previous window's.
    pub async fn valid(&self, now: u64) -> Result<Vec<Vec<u8>>, ApiError> {
        let (current, previous) = decide::nonce_windows(now);
        let mut out = vec![self.nonce_for(current).await?.into_bytes()];
        if let Some(p) = previous {
            out.push(self.nonce_for(p).await?.into_bytes());
        }
        Ok(out)
    }
}
