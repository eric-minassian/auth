use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use p256::ecdsa::Signature;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::SignError;
use crate::crypto::b64u;

/// ES256 signer backed by an AWS KMS asymmetric key (`ECC_NIST_P256`,
/// `SIGN_VERIFY`). The private key never leaves KMS; the public key is fetched
/// once at construction for the JWKS endpoint and `kid` derivation.
#[derive(Clone)]
pub struct KmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
    kid: String,
    jwk: serde_json::Value,
}

impl KmsSigner {
    /// Fetch the public key from KMS and derive the JWK + kid. Call once at
    /// cold start.
    pub async fn new(client: aws_sdk_kms::Client, key_id: String) -> Result<Self, SignError> {
        let public_key = client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .map_err(|e| SignError::Signature(format!("kms get_public_key: {e:?}")))?;
        let der = public_key
            .public_key()
            .ok_or_else(|| SignError::Signature("kms returned no public key".to_string()))?;

        // KMS returns a DER SubjectPublicKeyInfo; parse it to the P-256 point.
        let verifying_key = p256::PublicKey::from_public_key_der(der.as_ref())
            .map_err(|e| SignError::Signature(format!("parse spki: {e}")))?;
        let point = verifying_key.to_encoded_point(false);
        let (x, y) = (
            b64u(point.x().map(|x| x.to_vec()).unwrap_or_default()),
            b64u(point.y().map(|y| y.to_vec()).unwrap_or_default()),
        );
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = b64u(Sha256::digest(canonical.as_bytes()));
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": kid,
            "alg": "ES256",
            "use": "sig",
        });
        Ok(Self {
            client,
            key_id,
            kid,
            jwk,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn public_jwk(&self) -> serde_json::Value {
        self.jwk.clone()
    }

    /// Sign the JWS signing input. We hash locally and ask KMS to sign the
    /// digest, then convert the DER signature KMS returns into the raw 64-byte
    /// `r||s` form JWS requires (low-S normalized).
    pub async fn sign_raw(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        let digest = Sha256::digest(signing_input);
        let result = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|e| SignError::Signature(format!("kms sign: {e:?}")))?;
        let der = result
            .signature()
            .ok_or_else(|| SignError::Signature("kms returned no signature".to_string()))?;
        der_to_raw(der.as_ref())
    }
}

/// Convert a DER-encoded ECDSA signature into the raw 64-byte `r||s` form,
/// normalizing to low-S (BIP-0062 / JWS expectation).
pub fn der_to_raw(der: &[u8]) -> Result<Vec<u8>, SignError> {
    let signature = Signature::from_der(der)
        .map_err(|e| SignError::Signature(format!("parse der sig: {e}")))?;
    let normalized = signature.normalize_s().unwrap_or(signature);
    Ok(normalized.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::Verifier};
    use rand::Rng;

    #[test]
    fn der_to_raw_round_trips_and_verifies() {
        // p256 0.13 wants a rand_core 0.6 RNG; draw bytes ourselves.
        let key = loop {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            if let Ok(k) = SigningKey::from_slice(&bytes) {
                break k;
            }
        };
        let message = b"the.jws.signing.input";
        let signature: Signature = key.sign(message);

        // Emulate what KMS returns: a DER signature.
        let der = signature.to_der();
        let raw = der_to_raw(der.as_bytes()).expect("convert");
        assert_eq!(raw.len(), 64, "raw ES256 signature is exactly 64 bytes");

        // The raw signature verifies against the public key.
        let verifying: VerifyingKey = *key.verifying_key();
        let parsed = Signature::from_slice(&raw).expect("parse raw");
        verifying.verify(message, &parsed).expect("verifies");
    }
}
