//! Kani bounded model-checking harnesses.
//!
//! Each harness proves a property for **every** input in its domain (not a
//! sample). Absence of panics, arithmetic overflow and out-of-bounds access is
//! checked automatically on every path, in addition to the explicit assertions.
//! Cryptographic functions are replaced by nondeterministic stubs (see
//! `crypto`), which over-approximate every possible result.
//!
//! The parsers are structured so that the part that decides what is accepted
//! is allocation-free (group codecs, the CBOR item walker, the JWS separator
//! scan, the recovery-code bit packing); those cores are checked here, and the
//! public functions only concatenate their results.
//!
//! Run with `cargo kani -p auth-core`.

use crate::{b64, cbor, crockford, der, spki, wire};

/// A symbolic byte string of length at most `N`.
fn bytes<const N: usize>() -> ([u8; N], usize) {
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any_where(|l: &usize| *l <= N);
    (buf, len)
}

// ------------------------------------------------------------------ base64url

fn encode_group_roundtrip<const N: usize>() {
    let group: [u8; N] = kani::any();
    let (symbols, used) = b64::encode_group(&group);
    assert!(used == N + 1);
    let (decoded, n) = b64::decode_group(&symbols[..used]).expect("own encoding decodes");
    assert!(n == N);
    assert!(decoded[..n] == group[..]);
}

/// Encoding then decoding any group of 1–3 bytes gives the same bytes.
#[kani::proof]
#[kani::unwind(5)]
fn b64_group_roundtrip() {
    encode_group_roundtrip::<1>();
    encode_group_roundtrip::<2>();
    encode_group_roundtrip::<3>();
}

fn decode_group_canonical<const N: usize>() {
    let group: [u8; N] = kani::any();
    if let Some((decoded, n)) = b64::decode_group(&group) {
        assert!(n + 1 == N);
        let (symbols, used) = b64::encode_group(&decoded[..n]);
        assert!(used == N);
        assert!(symbols[..used] == group[..]);
    }
}

/// Every accepted group of symbols is the canonical encoding of its bytes, so
/// no two different strings decode to the same bytes. Groups of 0, 1 or more
/// than 4 symbols are rejected.
#[kani::proof]
#[kani::unwind(7)]
fn b64_group_canonical() {
    decode_group_canonical::<2>();
    decode_group_canonical::<3>();
    decode_group_canonical::<4>();
    let (buf, len) = bytes::<6>();
    if len <= 1 || len >= 5 {
        assert!(b64::decode_group(&buf[..len]).is_none());
    }
}

fn decode_len<const N: usize>() {
    let input: [u8; N] = kani::any();
    if let Some(out) = b64::decode(&input) {
        assert!(out.len() <= N);
    }
}

/// The full decoder never panics on inputs of up to 9 symbols.
#[kani::proof]
#[kani::unwind(4)]
fn b64_decode_never_panics() {
    decode_len::<0>();
    decode_len::<1>();
    decode_len::<2>();
    decode_len::<3>();
    decode_len::<4>();
    decode_len::<5>();
    decode_len::<6>();
    decode_len::<7>();
    decode_len::<8>();
    decode_len::<9>();
}

// ------------------------------------------------------------------ CBOR

/// The CBOR item walker (which determines what `decode_prefix` reports as
/// consumed) never panics and never reports more bytes than it was given.
#[kani::proof]
#[kani::unwind(11)]
fn cbor_item_len_within_bounds() {
    let (buf, len) = bytes::<8>();
    if let Some(used) = cbor::item_len(&buf[..len]) {
        assert!(used >= 1 && used <= len);
    }
}

// ------------------------------------------------------------------ DER

/// The strict DER parser never panics on inputs of up to 12 bytes.
#[kani::proof]
#[kani::unwind(14)]
fn der_to_fixed_never_panics() {
    let (buf, len) = bytes::<12>();
    let _ = der::der_to_fixed(&buf[..len]);
}

/// Every one of the 2^512 fixed signatures with non-zero `r` and `s` survives
/// DER encoding and strict decoding unchanged.
#[kani::proof]
#[kani::unwind(66)] // comparing the 64-byte arrays unrolls a 64-step loop
fn der_roundtrip() {
    let fixed: [u8; 64] = kani::any();
    if let Some((encoded, len)) = der::fixed_to_der_array(&fixed) {
        assert!(len <= 72);
        assert!(der::der_to_fixed(&encoded[..len]) == Some(fixed));
    } else {
        assert!(fixed[..32].iter().all(|b| *b == 0) || fixed[32..].iter().all(|b| *b == 0));
    }
}

// ------------------------------------------------------------------ SPKI

/// Only an exactly 91-byte SubjectPublicKeyInfo is accepted.
#[kani::proof]
#[kani::unwind(30)]
fn spki_accepts_only_exact_length() {
    let (buf, len) = bytes::<93>();
    if spki::p256_xy(&buf[..len]).is_some() {
        assert!(len == 91);
    }
}

// ------------------------------------------------------------------ recovery codes

/// Bit packing of every one of the 2^160 recovery codes round-trips.
#[kani::proof]
#[kani::unwind(34)]
fn crockford_symbols_roundtrip() {
    let code: [u8; crockford::RECOVERY_CODE_LEN] = kani::any();
    let symbols = crockford::to_symbols(&code);
    assert!(symbols.iter().all(|s| *s < 32));
    assert!(crockford::from_symbols(&symbols) == Some(code));
}

/// Every alphabet symbol maps to its index, so display and parsing agree.
#[kani::proof]
#[kani::unwind(34)]
fn crockford_alphabet_inverse() {
    let i: u8 = kani::any_where(|i: &u8| *i < 32);
    let symbol = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[usize::from(i)];
    assert!(crockford::value(symbol) == Some(i));
    assert!(crockford::value(symbol.to_ascii_lowercase()) == Some(i));
}

/// Parsing typed input never panics.
#[kani::proof]
#[kani::unwind(34)]
fn crockford_decode_never_panics() {
    let (buf, len) = bytes::<10>();
    let _ = crockford::decode_bytes(&buf[..len]);
}

// ------------------------------------------------------------------ JWS

/// Contract assumed by `axioms::split_jws`: a split succeeds only if the input
/// contains exactly two `.` separators; `split_jws` takes the signing input as
/// the exact prefix before the second one.
#[kani::proof]
#[kani::unwind(12)]
fn split_jws_separators() {
    let (buf, len) = bytes::<10>();
    let raw = &buf[..len];
    match wire::dot_positions(raw) {
        Some((first, second)) => {
            assert!(first < second && second < len);
            assert!(raw[first] == b'.' && raw[second] == b'.');
            for (i, b) in raw.iter().enumerate() {
                if i != first && i != second {
                    assert!(*b != b'.');
                }
            }
        }
        None => {
            let dots = raw.iter().filter(|b| **b == b'.').count();
            assert!(dots != 2);
        }
    }
}
