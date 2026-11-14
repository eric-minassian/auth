//! Full WebAuthn verification pipeline on arbitrary JSON responses: no panics,
//! and nothing is accepted without a valid signature from the stored key.
#![no_main]

use auth_core::crypto::sha256;
use auth_core::decide::{RpPolicy, StoredCredential};
use auth_core::webauthn::{
    AuthenticationResponseJson, RegistrationResponseJson, verify_authentication, verify_registration,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let policy = RpPolicy {
        rp_id_hash: sha256(b"example.com").to_vec(),
        origins: vec![b"https://app.example.com".to_vec()],
    };
    let challenge = [7u8; 32];
    if let Ok(resp) = serde_json::from_slice::<RegistrationResponseJson>(data) {
        // Without a valid authenticator response for this challenge nothing
        // reaches Ok, but every path must terminate cleanly.
        let _ = verify_registration(&policy, &challenge, &resp);
    }
    if let Ok(resp) = serde_json::from_slice::<AuthenticationResponseJson>(data) {
        let stored = StoredCredential {
            account_id: vec![1; 16],
            credential_id: vec![2; 16],
            // A valid P-256 COSE key whose private key nobody has.
            cose_key: auth_core::cose::encode(&auth_core::testing::SoftAuthenticator::new().public_key()),
            sign_count: 0,
            backup_eligible: true,
        };
        assert!(verify_authentication(&policy, &challenge, &stored, &resp).is_err());
    }
});
