//! Conversion of DER `ECDSA-Sig-Value` (as returned by AWS KMS) to the fixed
//! 64-byte `r || s` form JWS requires (RFC 7518 §3.4).
//!
//! The parser is strict DER: definite minimal lengths, minimal positive
//! INTEGERs, no trailing data, and `r`, `s` non-zero and at most 32 bytes.
//! Kani proves it never panics and that `der_to_fixed(fixed_to_der(x)) == x`
//! for every one of the 2^512 fixed signatures (see `kani_proofs`).

fn split_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = input.split_first()?;
    if t != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else if first == 0x81 {
        let (&l, rest) = rest.split_first()?;
        if l < 0x80 {
            return None; // non-minimal length
        }
        (usize::from(l), rest)
    } else {
        return None; // longer forms are never needed for P-256 signatures
    };
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Parses a minimal positive DER INTEGER and returns its magnitude without
/// leading zeros.
fn positive_integer(value: &[u8]) -> Option<&[u8]> {
    let (&first, rest) = value.split_first()?;
    if first & 0x80 != 0 {
        return None; // negative
    }
    let magnitude = if first == 0 {
        let (&second, _) = rest.split_first()?; // a lone 0x00 is zero
        if second & 0x80 == 0 {
            return None; // non-minimal
        }
        rest
    } else {
        value
    };
    Some(magnitude)
}

/// Converts a DER ECDSA P-256 signature into the fixed `r || s` form.
pub fn der_to_fixed(der: &[u8]) -> Option<[u8; 64]> {
    let (seq, trailing) = split_tlv(der, 0x30)?;
    if !trailing.is_empty() {
        return None;
    }
    let (r, rest) = split_tlv(seq, 0x02)?;
    let (s, rest) = split_tlv(rest, 0x02)?;
    if !rest.is_empty() {
        return None;
    }
    let r = positive_integer(r)?;
    let s = positive_integer(s)?;
    if r.len() > 32 || s.len() > 32 {
        return None;
    }
    let mut out = [0u8; 64];
    let (out_r, out_s) = out.split_at_mut(32);
    out_r.get_mut(32 - r.len()..)?.copy_from_slice(r);
    out_s.get_mut(32 - s.len()..)?.copy_from_slice(s);
    Some(out)
}

/// Writes a minimal positive DER INTEGER for `magnitude` at `out[at..]` and
/// returns the new end position.
fn write_integer(out: &mut [u8; 72], at: usize, magnitude: &[u8; 32]) -> Option<usize> {
    let start = magnitude.iter().position(|b| *b != 0)?;
    let trimmed = magnitude.get(start..)?;
    let pad = trimmed.first().is_some_and(|b| b & 0x80 != 0);
    let len = trimmed.len() + usize::from(pad);
    *out.get_mut(at)? = 0x02;
    *out.get_mut(at + 1)? = u8::try_from(len).ok()?;
    let mut pos = at + 2;
    if pad {
        *out.get_mut(pos)? = 0;
        pos += 1;
    }
    out.get_mut(pos..pos + trimmed.len())?
        .copy_from_slice(trimmed);
    Some(pos + trimmed.len())
}

/// Encodes a fixed `r || s` signature as DER into a fixed buffer, returning
/// the encoded length. `None` if `r` or `s` is zero. The allocation-free core
/// that Kani checks.
pub(crate) fn fixed_to_der_array(fixed: &[u8; 64]) -> Option<([u8; 72], usize)> {
    let (r, s) = fixed.split_at(32);
    let r: &[u8; 32] = r.try_into().ok()?;
    let s: &[u8; 32] = s.try_into().ok()?;
    let mut out = [0u8; 72];
    out[0] = 0x30;
    let after_r = write_integer(&mut out, 2, r)?;
    let end = write_integer(&mut out, after_r, s)?;
    out[1] = u8::try_from(end - 2).ok()?;
    Some((out, end))
}

/// Converts a fixed `r || s` signature into DER. Returns `None` if `r` or `s`
/// is zero (such a signature is invalid in either form).
pub fn fixed_to_der(fixed: &[u8; 64]) -> Option<Vec<u8>> {
    let (out, len) = fixed_to_der_array(fixed)?;
    out.get(..len).map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_non_canonical() {
        // r = 1, s = 1, canonical.
        assert!(der_to_fixed(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_some());
        let bad: &[&[u8]] = &[
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01], // non-minimal r
            &[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01],       // negative r
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],       // zero r
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00], // trailing
            &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // non-minimal length
            &[0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01],             // truncated
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],       // wrong tag
        ];
        for b in bad {
            assert_eq!(der_to_fixed(b), None, "{b:02x?}");
        }
    }

    #[test]
    fn kms_style_signature_converts_and_verifies() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{
            ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED, EcdsaKeyPair, KeyPair,
            UnparsedPublicKey,
        };
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        for i in 0..64u8 {
            let msg = [i; 40];
            let der = kp.sign(&rng, &msg).unwrap();
            let fixed = der_to_fixed(der.as_ref()).unwrap();
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, kp.public_key().as_ref())
                .verify(&msg, &fixed)
                .unwrap();
            assert_eq!(fixed_to_der(&fixed).unwrap(), der.as_ref());
        }
    }

    proptest! {
        #[test]
        fn roundtrip(r in proptest::array::uniform32(any::<u8>()), s in proptest::array::uniform32(any::<u8>())) {
            let mut fixed = [0u8; 64];
            fixed[..32].copy_from_slice(&r);
            fixed[32..].copy_from_slice(&s);
            if let Some(der) = fixed_to_der(&fixed) {
                prop_assert_eq!(der_to_fixed(&der), Some(fixed));
            }
        }
    }
}
