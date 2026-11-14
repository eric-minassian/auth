//! CBOR and COSE_Key parsing: no panics, and reported lengths never exceed the
//! input (the contract the Verus proofs assume for `cose_prefix`).
#![no_main]

use auth_core::{cbor, cose};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((_, used)) = cbor::decode_prefix(data) {
        assert!(used >= 1 && used <= data.len());
    }
    let _ = cbor::decode_exact(data);
    let _ = cbor::is_single_map(data);
    if let Some((key, used)) = cose::parse_prefix(data) {
        assert!(used >= 1 && used <= data.len());
        assert!(cose::alg_allowed(key.alg()));
        assert_eq!(cose::parse_exact(&data[..used]), Some(key));
    }
});
