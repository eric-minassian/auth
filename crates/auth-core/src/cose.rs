//! COSE_Key (RFC 9052 §7, RFC 9053) parsing for passkey public keys.
//!
//! Only the three algorithms in the protocol profile are accepted:
//!
//! | COSE alg | kty | Curve / size |
//! |---|---|---|
//! | `-7` ES256 | `2` EC2 | `crv = 1` (P-256), `x`/`y` 32 bytes each |
//! | `-8` EdDSA | `1` OKP | `crv = 6` (Ed25519), `x` 32 bytes |
//! | `-257` RS256 | `3` RSA | modulus 2048–4096 bits without leading zero, `e = 65537` |
//!
//! Every label other than the ones listed for the key type is rejected, which in
//! particular rejects private key material (`d`, label `-4`).

use crate::cbor::{self, Value};

/// COSE algorithm identifier for ES256.
pub const ALG_ES256: i64 = -7;
/// COSE algorithm identifier for EdDSA (Ed25519 here).
pub const ALG_EDDSA: i64 = -8;
/// COSE algorithm identifier for RS256.
pub const ALG_RS256: i64 = -257;

/// Returns true iff `alg` is one of the algorithms this service accepts.
pub const fn alg_allowed(alg: i64) -> bool {
    matches!(alg, ALG_ES256 | ALG_EDDSA | ALG_RS256)
}

/// A validated passkey public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// ECDSA P-256 with SHA-256.
    Es256 {
        /// X coordinate.
        x: [u8; 32],
        /// Y coordinate.
        y: [u8; 32],
    },
    /// Ed25519.
    Ed25519 {
        /// Public key bytes.
        x: [u8; 32],
    },
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256 {
        /// Modulus, big-endian, no leading zero byte.
        n: Vec<u8>,
        /// Public exponent (always 65537).
        e: Vec<u8>,
    },
}

impl PublicKey {
    /// The COSE algorithm identifier of this key.
    pub const fn alg(&self) -> i64 {
        match self {
            PublicKey::Es256 { .. } => ALG_ES256,
            PublicKey::Ed25519 { .. } => ALG_EDDSA,
            PublicKey::Rs256 { .. } => ALG_RS256,
        }
    }
}

const KTY: i64 = 1;
const ALG: i64 = 3;
const P_CRV_OR_N: i64 = -1;
const P_X_OR_E: i64 = -2;
const P_Y: i64 = -3;

const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const KTY_RSA: i64 = 3;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

const RSA_MIN_MODULUS_BYTES: usize = 256;
const RSA_MAX_MODULUS_BYTES: usize = 512;
const RSA_E_65537: [u8; 3] = [0x01, 0x00, 0x01];

fn bytes32(v: &Value<'_>) -> Option<[u8; 32]> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(*b).ok(),
        _ => None,
    }
}

fn only_labels(map: &Value<'_>, allowed: &[i64]) -> bool {
    match map {
        Value::Map(entries) => entries
            .iter()
            .all(|(k, _)| k.as_i64().is_some_and(|l| allowed.contains(&l))),
        _ => false,
    }
}

fn from_value(map: &Value<'_>) -> Option<PublicKey> {
    let kty = map.map_get_int(KTY)?.as_i64()?;
    let alg = map.map_get_int(ALG)?.as_i64()?;
    match (kty, alg) {
        (KTY_EC2, ALG_ES256) => {
            if !only_labels(map, &[KTY, ALG, P_CRV_OR_N, P_X_OR_E, P_Y]) {
                return None;
            }
            if map.map_get_int(P_CRV_OR_N)?.as_i64()? != CRV_P256 {
                return None;
            }
            let x = bytes32(map.map_get_int(P_X_OR_E)?)?;
            let y = bytes32(map.map_get_int(P_Y)?)?;
            let key = PublicKey::Es256 { x, y };
            crate::crypto::public_key_is_valid(&key).then_some(key)
        }
        (KTY_OKP, ALG_EDDSA) => {
            if !only_labels(map, &[KTY, ALG, P_CRV_OR_N, P_X_OR_E]) {
                return None;
            }
            if map.map_get_int(P_CRV_OR_N)?.as_i64()? != CRV_ED25519 {
                return None;
            }
            let x = bytes32(map.map_get_int(P_X_OR_E)?)?;
            let key = PublicKey::Ed25519 { x };
            crate::crypto::public_key_is_valid(&key).then_some(key)
        }
        (KTY_RSA, ALG_RS256) => {
            if !only_labels(map, &[KTY, ALG, P_CRV_OR_N, P_X_OR_E]) {
                return None;
            }
            let Value::Bytes(n) = map.map_get_int(P_CRV_OR_N)? else {
                return None;
            };
            let Value::Bytes(e) = map.map_get_int(P_X_OR_E)? else {
                return None;
            };
            let leading_zero = n.first().is_none_or(|b| *b == 0);
            if leading_zero
                || n.len() < RSA_MIN_MODULUS_BYTES
                || n.len() > RSA_MAX_MODULUS_BYTES
                || *e != RSA_E_65537
            {
                return None;
            }
            Some(PublicKey::Rs256 {
                n: n.to_vec(),
                e: e.to_vec(),
            })
        }
        _ => None,
    }
}

/// Parses a COSE_Key at the start of `input`. Returns the key and the number of
/// bytes it occupies (the authenticator data may continue with extensions).
pub fn parse_prefix(input: &[u8]) -> Option<(PublicKey, usize)> {
    // The reported length is exactly the CBOR item extent, which Kani proves
    // is non-zero and within `input` (`cbor_item_len_within_bounds`). This is
    // the contract `axioms::cose_prefix` assumes.
    let used = cbor::item_len(input)?;
    let value = cbor::decode_exact(input.get(..used)?)?;
    let key = from_value(&value)?;
    Some((key, used))
}

/// Parses a COSE_Key that occupies all of `input` (the stored form).
pub fn parse_exact(input: &[u8]) -> Option<PublicKey> {
    let (key, used) = parse_prefix(input)?;
    (used == input.len()).then_some(key)
}

/// COSE_Key encoding, for building test credentials.
#[cfg(any(test, feature = "test-support"))]
pub fn encode(key: &PublicKey) -> Vec<u8> {
    use crate::cbor::encode::Item;
    let entries = match key {
        PublicKey::Es256 { x, y } => vec![
            (Item::Int(KTY), Item::Int(KTY_EC2)),
            (Item::Int(ALG), Item::Int(ALG_ES256)),
            (Item::Int(P_CRV_OR_N), Item::Int(CRV_P256)),
            (Item::Int(P_X_OR_E), Item::Bytes(x.to_vec())),
            (Item::Int(P_Y), Item::Bytes(y.to_vec())),
        ],
        PublicKey::Ed25519 { x } => vec![
            (Item::Int(KTY), Item::Int(KTY_OKP)),
            (Item::Int(ALG), Item::Int(ALG_EDDSA)),
            (Item::Int(P_CRV_OR_N), Item::Int(CRV_ED25519)),
            (Item::Int(P_X_OR_E), Item::Bytes(x.to_vec())),
        ],
        PublicKey::Rs256 { n, e } => vec![
            (Item::Int(KTY), Item::Int(KTY_RSA)),
            (Item::Int(ALG), Item::Int(ALG_RS256)),
            (Item::Int(P_CRV_OR_N), Item::Bytes(n.clone())),
            (Item::Int(P_X_OR_E), Item::Bytes(e.clone())),
        ],
    };
    Item::Map(entries).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::encode::Item;

    fn p256_point() -> ([u8; 32], [u8; 32]) {
        // The P-256 generator point, a valid public key.
        let x = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ];
        let y = [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ];
        (x, y)
    }

    #[test]
    fn es256_roundtrip_and_prefix() {
        let (x, y) = p256_point();
        let key = PublicKey::Es256 { x, y };
        let mut bytes = encode(&key);
        let len = bytes.len();
        assert_eq!(parse_exact(&bytes), Some(key.clone()));
        bytes.extend_from_slice(&[0xa0]); // trailing extensions map
        assert_eq!(parse_prefix(&bytes), Some((key, len)));
        assert_eq!(parse_exact(&bytes), None);
    }

    #[test]
    fn rejects_point_not_on_curve() {
        let (x, mut y) = p256_point();
        y[31] ^= 1;
        assert_eq!(parse_exact(&encode(&PublicKey::Es256 { x, y })), None);
    }

    #[test]
    fn rejects_private_key_material_and_unknown_labels() {
        let (x, y) = p256_point();
        let with_d = Item::Map(vec![
            (Item::Int(1), Item::Int(2)),
            (Item::Int(3), Item::Int(-7)),
            (Item::Int(-1), Item::Int(1)),
            (Item::Int(-2), Item::Bytes(x.to_vec())),
            (Item::Int(-3), Item::Bytes(y.to_vec())),
            (Item::Int(-4), Item::Bytes(vec![1; 32])),
        ]);
        assert_eq!(parse_exact(&with_d.to_vec()), None);
    }

    #[test]
    fn rejects_mismatched_alg_and_curve() {
        let (x, y) = p256_point();
        let wrong_alg = Item::Map(vec![
            (Item::Int(1), Item::Int(2)),
            (Item::Int(3), Item::Int(-35)), // ES384
            (Item::Int(-1), Item::Int(1)),
            (Item::Int(-2), Item::Bytes(x.to_vec())),
            (Item::Int(-3), Item::Bytes(y.to_vec())),
        ]);
        assert_eq!(parse_exact(&wrong_alg.to_vec()), None);
        let wrong_crv = Item::Map(vec![
            (Item::Int(1), Item::Int(2)),
            (Item::Int(3), Item::Int(-7)),
            (Item::Int(-1), Item::Int(2)), // P-384
            (Item::Int(-2), Item::Bytes(x.to_vec())),
            (Item::Int(-3), Item::Bytes(y.to_vec())),
        ]);
        assert_eq!(parse_exact(&wrong_crv.to_vec()), None);
    }

    #[test]
    fn rsa_limits() {
        let mut n = vec![0xc5; 256];
        let ok = PublicKey::Rs256 {
            n: n.clone(),
            e: RSA_E_65537.to_vec(),
        };
        assert_eq!(parse_exact(&encode(&ok)), Some(ok));
        n.truncate(255);
        assert_eq!(
            parse_exact(&encode(&PublicKey::Rs256 {
                n,
                e: RSA_E_65537.to_vec()
            })),
            None
        );
        let e3 = PublicKey::Rs256 {
            n: vec![0xc5; 256],
            e: vec![3],
        };
        assert_eq!(parse_exact(&encode(&e3)), None);
        let mut lz = vec![0xc5; 257];
        lz[0] = 0;
        assert_eq!(
            parse_exact(&encode(&PublicKey::Rs256 {
                n: lz,
                e: RSA_E_65537.to_vec()
            })),
            None
        );
    }
}
