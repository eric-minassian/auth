//! DPoP, access-token and refresh-token checks on arbitrary input: no panics,
//! and no forgery is ever accepted (the fuzzer does not hold any private key).
#![no_main]

use auth_core::decide::{
    AccessExpect, DpopExpect, RefreshExpect, check_dpop, check_refresh_token, check_resource_request,
};
use auth_core::testing::LocalSigner;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn keys() -> &'static Vec<auth_core::vtypes::VerifyKey> {
    static KEYS: OnceLock<Vec<auth_core::vtypes::VerifyKey>> = OnceLock::new();
    KEYS.get_or_init(|| vec![LocalSigner::generate().verify_key()])
}

fuzz_target!(|data: &[u8]| {
    let now = 1_763_000_000;
    let mut split = data.splitn(2, |b| *b == b'\n');
    let a = split.next().unwrap_or_default();
    let b = split.next().unwrap_or_default();
    let d = DpopExpect {
        htm: b"GET".to_vec(),
        htu: b"https://api.example.com/x".to_vec(),
        now,
        max_skew: 60,
        valid_nonces: None,
        access_token: Some(a.to_vec()),
    };
    // A DPoP proof is self-signed, so the fuzzer can in principle build a valid
    // one; it must still never panic.
    let _ = check_dpop(b, &d);
    let ae = AccessExpect {
        issuer: b"https://auth.example.com".to_vec(),
        audience: b"https://api.example.com".to_vec(),
        keys: keys().clone(),
        now,
        max_skew: 60,
    };
    assert!(check_resource_request(a, b, &ae, &d).is_err(), "access token forged");
    let re = RefreshExpect {
        issuer: b"https://auth.example.com".to_vec(),
        client_id: b"web".to_vec(),
        keys: keys().clone(),
        now,
        max_skew: 120,
    };
    assert!(check_refresh_token(a, &re, b).is_err(), "refresh token forged");
});
