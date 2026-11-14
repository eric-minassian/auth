//! base64url, DER, SPKI and recovery-code encodings: no panics, and every
//! accepted input round-trips to exactly itself (canonical encodings).
#![no_main]

use auth_core::{b64, crockford, der, spki};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(bytes) = b64::decode(data) {
        assert_eq!(b64::encode(&bytes).as_bytes(), data, "base64url decoding must be canonical");
    }
    let enc = b64::encode(data);
    assert_eq!(b64::decode(enc.as_bytes()).as_deref(), Some(data));

    if let Some(fixed) = der::der_to_fixed(data) {
        assert_eq!(der::fixed_to_der(&fixed).as_deref(), Some(data), "DER decoding must be canonical");
    }
    if let Ok(fixed) = <[u8; 64]>::try_from(data) {
        if let Some(d) = der::fixed_to_der(&fixed) {
            assert_eq!(der::der_to_fixed(&d), Some(fixed));
        }
    }
    let _ = spki::p256_xy(data);
    if let Ok(s) = core::str::from_utf8(data) {
        if let Some(code) = crockford::decode_recovery_code(s) {
            let text = crockford::encode_recovery_code(&code);
            assert_eq!(crockford::decode_recovery_code(&text), Some(code));
        }
    }
});
