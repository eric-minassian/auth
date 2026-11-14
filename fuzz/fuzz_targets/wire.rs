//! The trusted JSON/CBOR parsers: no panics on any input.
#![no_main]

use auth_core::wire;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = wire::parse_client_data(data);
    let _ = wire::parse_att_obj(data);
    let _ = wire::parse_jws_header(data);
    let _ = wire::parse_dpop_claims(data);
    let _ = wire::parse_access_claims(data);
    let _ = wire::parse_refresh_claims(data);
    if let Some(parts) = wire::split_jws(data) {
        let dots = data.iter().filter(|b| **b == b'.').count();
        assert_eq!(dots, 2);
        assert!(data.starts_with(&parts.signing_input));
    }
});
