//! Cryptographic primitives, all delegated to AWS-LC (`aws-lc-rs`).
//!
//! Nothing here implements cryptography. These functions are the trusted
//! primitives that the verified decision layer (`decide`) calls through
//! axiomatized wrappers (`axioms`).
//!
//! Under Kani, the functions that would call into C are replaced by
//! nondeterministic stubs, which over-approximate every possible result.

use crate::cose::PublicKey;

/// SHA-256.
#[cfg(not(kani))]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-256 (Kani stub).
#[cfg(kani)]
pub fn sha256(_data: &[u8]) -> [u8; 32] {
    kani::any()
}

#[cfg(not(kani))]
fn uncompressed_point(x: &[u8; 32], y: &[u8; 32]) -> [u8; 65] {
    let mut p = [0u8; 65];
    p[0] = 0x04;
    p[1..33].copy_from_slice(x);
    p[33..].copy_from_slice(y);
    p
}

/// Returns true iff the key is well formed for its algorithm: for P-256 the
/// point is on the curve and not the identity; for Ed25519 the encoding is
/// accepted by AWS-LC. RSA moduli are range-checked by the COSE parser and by
/// AWS-LC at verification time.
#[cfg(not(kani))]
pub fn public_key_is_valid(key: &PublicKey) -> bool {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey};
    match key {
        PublicKey::Es256 { x, y } => {
            ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, uncompressed_point(x, y)).is_ok()
        }
        PublicKey::Ed25519 { x } => ParsedPublicKey::new(&ED25519, x).is_ok(),
        PublicKey::Rs256 { .. } => true,
    }
}

/// Key validation (Kani stub).
#[cfg(kani)]
pub fn public_key_is_valid(_key: &PublicKey) -> bool {
    kani::any()
}

/// Verifies a WebAuthn signature: ES256 signatures are ASN.1 DER
/// (WebAuthn §6.5.6), Ed25519 signatures are 64 raw bytes, RS256 signatures are
/// PKCS#1 v1.5.
#[cfg(not(kani))]
pub fn verify_webauthn(key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
        UnparsedPublicKey,
    };
    match key {
        PublicKey::Es256 { x, y } => {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, uncompressed_point(x, y))
                .verify(message, signature)
                .is_ok()
        }
        PublicKey::Ed25519 { x } => UnparsedPublicKey::new(&ED25519, x)
            .verify(message, signature)
            .is_ok(),
        PublicKey::Rs256 { n, e } => RsaPublicKeyComponents { n, e }
            .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
            .is_ok(),
    }
}

/// WebAuthn signature verification (Kani stub).
#[cfg(kani)]
pub fn verify_webauthn(_key: &PublicKey, _message: &[u8], _signature: &[u8]) -> bool {
    kani::any()
}

/// Verifies a WebAuthn signature with a stored COSE_Key.
pub fn verify_cose(cose_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    crate::cose::parse_exact(cose_key).is_some_and(|k| verify_webauthn(&k, message, signature))
}

/// Verifies a JWS `ES256` signature (fixed 64-byte `r || s`, RFC 7518 §3.4).
#[cfg(not(kani))]
pub fn verify_es256_jws(x: &[u8], y: &[u8], signing_input: &[u8], signature: &[u8]) -> bool {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    let (Ok(x), Ok(y)) = (<&[u8; 32]>::try_from(x), <&[u8; 32]>::try_from(y)) else {
        return false;
    };
    signature.len() == 64
        && UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, uncompressed_point(x, y))
            .verify(signing_input, signature)
            .is_ok()
}

/// JWS verification (Kani stub).
#[cfg(kani)]
pub fn verify_es256_jws(_x: &[u8], _y: &[u8], _signing_input: &[u8], _signature: &[u8]) -> bool {
    kani::any()
}

/// RFC 7638 JWK thumbprint of a P-256 public key: SHA-256 over the JSON object
/// with the required members in lexicographic order and no whitespace.
pub fn jwk_thumbprint_p256(x: &[u8], y: &[u8]) -> [u8; 32] {
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        crate::b64::encode(x),
        crate::b64::encode(y)
    );
    sha256(canonical.as_bytes())
}

/// Constant-time equality for secrets.
#[cfg(not(kani))]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Constant-time equality (Kani model: plain equality).
#[cfg(kani)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a == b
}

#[cfg(all(test, not(kani)))]
mod tests {
    use super::*;

    #[test]
    fn sha256_vector() {
        // FIPS 180-2 "abc".
        assert_eq!(
            crate::b64::encode(&sha256(b"abc")),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn rfc7638_style_thumbprint_is_stable() {
        // RFC 7638 §3.1 uses an RSA key; this checks the P-256 canonical form
        // against an independently computed value (RFC 9449 §4.1 example jwk).
        let x = crate::b64::decode_str("l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs")
            .unwrap_or_default();
        let y = crate::b64::decode_str("9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA")
            .unwrap_or_default();
        let jkt = crate::b64::encode(&jwk_thumbprint_p256(&x, &y));
        assert_eq!(jkt, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    }
}
