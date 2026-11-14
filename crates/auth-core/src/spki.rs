//! Extraction of P-256 public key coordinates from a DER SubjectPublicKeyInfo
//! (the format AWS KMS `GetPublicKey` returns).
//!
//! Only the exact encoding of an uncompressed `id-ecPublicKey` / `prime256v1`
//! key is accepted.

/// DER prefix of a P-256 SubjectPublicKeyInfo up to and including the
/// uncompressed-point marker `0x04`.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, // SEQUENCE, 89 bytes
    0x30, 0x13, // SEQUENCE, 19 bytes (AlgorithmIdentifier)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, // OID 1.2.840.10045.2.1 id-ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, // OID 1.2.840.10045.3.1.7 prime256v1
    0x03, 0x42, 0x00, // BIT STRING, 66 bytes, 0 unused bits
    0x04, // uncompressed point
];

/// Returns the `(x, y)` coordinates of a P-256 SubjectPublicKeyInfo.
pub fn p256_xy(spki: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let rest = spki.strip_prefix(&P256_SPKI_PREFIX[..])?;
    let (x, y) = (rest.get(..32)?, rest.get(32..)?);
    Some((<[u8; 32]>::try_from(x).ok()?, <[u8; 32]>::try_from(y).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    #[test]
    fn matches_aws_lc_encoding() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let spki = kp.public_key().as_der().unwrap();
        let (x, y) = p256_xy(spki.as_ref()).unwrap();
        let point = kp.public_key().as_ref();
        assert_eq!(&point[1..33], &x);
        assert_eq!(&point[33..], &y);
    }

    #[test]
    fn rejects_other_encodings() {
        assert_eq!(p256_xy(&[]), None);
        let mut long = P256_SPKI_PREFIX.to_vec();
        long.extend_from_slice(&[0u8; 65]);
        assert_eq!(p256_xy(&long), None);
        let mut short = P256_SPKI_PREFIX.to_vec();
        short.extend_from_slice(&[0u8; 63]);
        assert_eq!(p256_xy(&short), None);
    }
}
