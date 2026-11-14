#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
//! End-to-end tests of the verified WebAuthn checks using real binary formats
//! produced by a software authenticator. Every rejection path in
//! `decide::check_registration` / `check_assertion` is exercised.

use auth_core::b64;
use auth_core::cbor::encode::Item;
use auth_core::crypto::sha256;
use auth_core::decide::{
    FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV, Reject, RpPolicy, StoredCredential,
};
use auth_core::testing::{Alg, AttestationKind, SoftAuthenticator, random_bytes};
use auth_core::webauthn::{
    RegisteredCredential, WebauthnError, verify_authentication, verify_registration,
};

type Mutation = Box<dyn Fn(&mut auth_core::testing::Ceremony)>;

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://app.example.com";

fn policy() -> RpPolicy {
    RpPolicy {
        rp_id_hash: sha256(RP_ID.as_bytes()).to_vec(),
        origins: vec![
            ORIGIN.as_bytes().to_vec(),
            b"android:apk-key-hash:abc".to_vec(),
        ],
    }
}

fn register(auth: &mut SoftAuthenticator) -> (RegisteredCredential, Vec<u8>) {
    let challenge = random_bytes(32);
    let user = random_bytes(16);
    let resp = auth.register(RP_ID, ORIGIN, &challenge, &user);
    let cred = verify_registration(&policy(), &challenge, &resp).expect("registration accepted");
    (cred, user)
}

fn stored(cred: &RegisteredCredential, user: &[u8]) -> StoredCredential {
    StoredCredential {
        account_id: user.to_vec(),
        credential_id: cred.credential_id.clone(),
        cose_key: cred.cose_key.clone(),
        sign_count: cred.sign_count,
        backup_eligible: cred.backup_eligible,
    }
}

fn rejected(r: Result<impl core::fmt::Debug, WebauthnError>) -> Reject {
    match r {
        Err(WebauthnError::Rejected(reason)) => reason,
        other => panic!("expected a verified rejection, got {other:?}"),
    }
}

#[test]
fn registration_and_login_succeed_for_every_algorithm() {
    for alg in [Alg::Es256, Alg::Ed25519, Alg::Rs256] {
        let mut auth = SoftAuthenticator::with_alg(alg);
        let (cred, user) = register(&mut auth);
        assert_eq!(cred.credential_id, auth.credential_id);
        assert_eq!(cred.alg, auth.public_key().alg());
        assert!(cred.backup_eligible && cred.backup_state);
        assert_eq!(
            cred.transports,
            vec!["hybrid".to_string(), "internal".to_string()]
        );
        let challenge = random_bytes(32);
        let resp = auth.authenticate(RP_ID, ORIGIN, &challenge);
        let ok = verify_authentication(&policy(), &challenge, &stored(&cred, &user), &resp)
            .unwrap_or_else(|e| panic!("{alg:?}: {e}"));
        assert_eq!(ok.sign_count, 0);
    }
}

#[test]
fn packed_self_attestation_is_verified() {
    let mut auth = SoftAuthenticator::new();
    let challenge = random_bytes(32);
    let mut c = auth.ceremony("webauthn.create", RP_ID, ORIGIN, &challenge);
    c.attestation = AttestationKind::PackedSelf;
    let resp = auth.register_with(&c, &random_bytes(16));
    assert!(verify_registration(&policy(), &challenge, &resp).is_ok());

    c.attestation = AttestationKind::PackedWrongAlg;
    let resp = auth.register_with(&c, &random_bytes(16));
    assert_eq!(
        rejected(verify_registration(&policy(), &challenge, &resp)),
        Reject::AttestationUnsupported
    );

    c.attestation = AttestationKind::FidoU2f;
    let resp = auth.register_with(&c, &random_bytes(16));
    assert_eq!(
        rejected(verify_registration(&policy(), &challenge, &resp)),
        Reject::AttestationUnsupported
    );
}

#[test]
fn registration_rejections() {
    let mut auth = SoftAuthenticator::new();
    let challenge = random_bytes(32);
    let base = auth.ceremony("webauthn.create", RP_ID, ORIGIN, &challenge);
    let user = random_bytes(16);

    let cases: Vec<(&str, Mutation, Reject)> = vec![
        (
            "wrong type",
            Box::new(|c| c.client_data.typ = "webauthn.get".into()),
            Reject::ClientDataWrongType,
        ),
        (
            "other challenge",
            Box::new(|c| c.client_data.challenge = vec![7; 32]),
            Reject::ChallengeMismatch,
        ),
        (
            "phishing origin",
            Box::new(|c| c.client_data.origin = "https://app.example.com.evil".into()),
            Reject::OriginNotAllowed,
        ),
        (
            "cross origin",
            Box::new(|c| c.client_data.cross_origin = Some(true)),
            Reject::CrossOrigin,
        ),
        (
            "top origin",
            Box::new(|c| c.client_data.top_origin = Some(ORIGIN.into())),
            Reject::TopOriginPresent,
        ),
        (
            "other rp id",
            Box::new(|c| c.rp_id = "evil.com".into()),
            Reject::RpIdMismatch,
        ),
        (
            "no UP",
            Box::new(|c| c.flags &= !FLAG_UP),
            Reject::UserNotPresent,
        ),
        (
            "no UV",
            Box::new(|c| c.flags &= !FLAG_UV),
            Reject::UserNotVerified,
        ),
        (
            "BS without BE",
            Box::new(|c| c.flags = (c.flags & !FLAG_BE) | FLAG_BS),
            Reject::BackupStateInvalid,
        ),
        (
            "no AT",
            Box::new(|c| c.flags &= !FLAG_AT),
            Reject::AuthDataMalformed,
        ),
        (
            "trailing bytes",
            Box::new(|c| c.extensions = vec![0x00]),
            Reject::ExtensionsMalformed,
        ),
        (
            "ED without map",
            Box::new(|c| c.flags |= FLAG_ED),
            Reject::ExtensionsMalformed,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut c = base.clone();
        mutate(&mut c);
        let resp = auth.register_with(&c, &user);
        let got = rejected(verify_registration(&policy(), &challenge, &resp));
        // Without AT the attested data is absent, so the short auth data is
        // reported either as missing attested data or as malformed.
        if expected == Reject::AuthDataMalformed {
            assert!(
                matches!(got, Reject::AuthDataMalformed | Reject::AttestedDataMissing),
                "{name}: {got:?}"
            );
        } else {
            assert_eq!(got, expected, "{name}");
        }
    }

    // Extensions are accepted when ED is set and they form exactly one map.
    let mut c = base.clone();
    c.flags |= FLAG_ED;
    c.extensions = Item::Map(vec![(Item::Text("credProtect".into()), Item::Int(2))]).to_vec();
    let resp = auth.register_with(&c, &user);
    assert!(verify_registration(&policy(), &challenge, &resp).is_ok());
}

#[test]
fn registration_rejects_mismatched_raw_id_and_json_shape() {
    let mut auth = SoftAuthenticator::new();
    let challenge = random_bytes(32);
    let mut resp = auth.register(RP_ID, ORIGIN, &challenge, &random_bytes(16));
    let other = b64::encode(&random_bytes(16));
    resp.id.clone_from(&other);
    resp.raw_id = other;
    assert_eq!(
        rejected(verify_registration(&policy(), &challenge, &resp)),
        Reject::CredentialIdMismatch
    );

    let mut resp = auth.register(RP_ID, ORIGIN, &challenge, &random_bytes(16));
    resp.id = b64::encode(&random_bytes(16));
    assert_eq!(
        verify_registration(&policy(), &challenge, &resp).unwrap_err(),
        WebauthnError::Malformed
    );

    let mut resp = auth.register(RP_ID, ORIGIN, &challenge, &random_bytes(16));
    resp.typ = "password".into();
    assert_eq!(
        verify_registration(&policy(), &challenge, &resp).unwrap_err(),
        WebauthnError::Malformed
    );
}

#[test]
fn authentication_rejections() {
    let mut auth = SoftAuthenticator::new();
    let (cred, user) = register(&mut auth);
    let s = stored(&cred, &user);
    let challenge = random_bytes(32);
    let base = auth.ceremony("webauthn.get", RP_ID, ORIGIN, &challenge);

    let cases: Vec<(&str, Mutation, Reject)> = vec![
        (
            "wrong type",
            Box::new(|c| c.client_data.typ = "webauthn.create".into()),
            Reject::ClientDataWrongType,
        ),
        (
            "replayed challenge",
            Box::new(|c| c.client_data.challenge = vec![1; 32]),
            Reject::ChallengeMismatch,
        ),
        (
            "phishing origin",
            Box::new(|c| c.client_data.origin = "https://login.example-secure.com".into()),
            Reject::OriginNotAllowed,
        ),
        (
            "other rp id",
            Box::new(|c| c.rp_id = "example.org".into()),
            Reject::RpIdMismatch,
        ),
        (
            "no UP",
            Box::new(|c| c.flags &= !FLAG_UP),
            Reject::UserNotPresent,
        ),
        (
            "no UV",
            Box::new(|c| c.flags &= !FLAG_UV),
            Reject::UserNotVerified,
        ),
        (
            "AT set",
            Box::new(|c| c.flags |= FLAG_AT),
            Reject::AttestedDataUnexpected,
        ),
        (
            "BE changed",
            Box::new(|c| c.flags &= !(FLAG_BE | FLAG_BS)),
            Reject::BackupEligibilityChanged,
        ),
        (
            "trailing bytes",
            Box::new(|c| c.extensions = vec![0xa0, 0x00]),
            Reject::ExtensionsMalformed,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut c = base.clone();
        mutate(&mut c);
        let resp = auth.authenticate_with(&c);
        assert_eq!(
            rejected(verify_authentication(&policy(), &challenge, &s, &resp)),
            expected,
            "{name}"
        );
    }
}

#[test]
fn authentication_rejects_wrong_key_user_handle_and_signature() {
    let mut auth = SoftAuthenticator::new();
    let (cred, user) = register(&mut auth);
    let challenge = random_bytes(32);

    // A different authenticator claiming the same credential ID.
    let mut impostor = SoftAuthenticator::new();
    impostor.credential_id.clone_from(&auth.credential_id);
    impostor.user_handle.clone_from(&user);
    let resp = impostor.authenticate(RP_ID, ORIGIN, &challenge);
    assert_eq!(
        rejected(verify_authentication(
            &policy(),
            &challenge,
            &stored(&cred, &user),
            &resp
        )),
        Reject::SignatureInvalid
    );

    // User handle of another account.
    let mut resp = auth.authenticate(RP_ID, ORIGIN, &challenge);
    resp.response.user_handle = Some(b64::encode(&random_bytes(16)));
    assert_eq!(
        rejected(verify_authentication(
            &policy(),
            &challenge,
            &stored(&cred, &user),
            &resp
        )),
        Reject::UserHandleMismatch
    );

    // Missing user handle.
    let mut resp = auth.authenticate(RP_ID, ORIGIN, &challenge);
    resp.response.user_handle = None;
    assert_eq!(
        rejected(verify_authentication(
            &policy(),
            &challenge,
            &stored(&cred, &user),
            &resp
        )),
        Reject::UserHandleMismatch
    );

    // Tampered client data after signing.
    let mut resp = auth.authenticate(RP_ID, ORIGIN, &challenge);
    let mut cd: serde_json::Value =
        serde_json::from_slice(&b64::decode_str(&resp.response.client_data_json).unwrap()).unwrap();
    cd["extra"] = "x".into();
    resp.response.client_data_json = b64::encode(&serde_json::to_vec(&cd).unwrap());
    assert_eq!(
        rejected(verify_authentication(
            &policy(),
            &challenge,
            &stored(&cred, &user),
            &resp
        )),
        Reject::SignatureInvalid
    );
}

#[test]
fn signature_counter_rule() {
    let mut auth = SoftAuthenticator::new();
    auth.counter = Some(10);
    auth.backup_eligible = false;
    let (cred, user) = register(&mut auth);
    assert_eq!(cred.sign_count, 11);
    let mut s = stored(&cred, &user);

    let challenge = random_bytes(32);
    let resp = auth.authenticate(RP_ID, ORIGIN, &challenge);
    let ok = verify_authentication(&policy(), &challenge, &s, &resp).unwrap();
    assert_eq!(ok.sign_count, 12);
    s.sign_count = ok.sign_count;

    // A clone replaying an old counter value is rejected.
    let mut c = auth.ceremony("webauthn.get", RP_ID, ORIGIN, &challenge);
    c.sign_count = Some(12);
    let resp = auth.authenticate_with(&c);
    assert_eq!(
        rejected(verify_authentication(&policy(), &challenge, &s, &resp)),
        Reject::SignCountNotIncreasing
    );
    c.sign_count = Some(0);
    let resp = auth.authenticate_with(&c);
    assert_eq!(
        rejected(verify_authentication(&policy(), &challenge, &s, &resp)),
        Reject::SignCountNotIncreasing
    );
}

#[test]
fn android_origin_is_accepted_when_configured() {
    let mut auth = SoftAuthenticator::new();
    let challenge = random_bytes(32);
    let resp = auth.register(
        RP_ID,
        "android:apk-key-hash:abc",
        &challenge,
        &random_bytes(16),
    );
    assert!(verify_registration(&policy(), &challenge, &resp).is_ok());
}

#[test]
fn challenge_extraction_matches_client_data() {
    let mut auth = SoftAuthenticator::new();
    let challenge = random_bytes(32);
    let resp = auth.authenticate(RP_ID, ORIGIN, &challenge);
    assert_eq!(
        auth_core::webauthn::challenge_of(&resp.response.client_data_json),
        Some(challenge)
    );
}
