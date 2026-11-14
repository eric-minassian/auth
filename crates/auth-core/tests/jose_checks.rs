#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
//! Tests of the verified DPoP, access-token and refresh-token checks, including
//! the token formats the service issues (round trip through `jose`).

use auth_core::b64;
use auth_core::crypto::sha256;
use auth_core::decide::{
    ACCESS_TOKEN_TTL, AccessExpect, AccountState, DpopExpect, REFRESH_ABSOLUTE_TTL,
    REFRESH_IDLE_TTL, RefreshExpect, Reject, STEP_UP_MAX_AGE, Stage, authorize_refresh, check_dpop,
    check_refresh_token, check_resource_request, check_step_up, lifetimes, nonce_windows,
};
use auth_core::jose::{self, AccessTokenClaims, Cnf, RefreshTokenClaims};
use auth_core::testing::{DpopKey, LocalSigner, ProofParams};
use serde_json::json;

const ISS: &str = "https://auth.example.com";
const AUD: &str = "https://api.example.com";
const NOW: u64 = 1_763_000_000;
const HTU: &str = "https://api.example.com/v1/things";

fn expect(nonces: Option<Vec<&str>>, token: Option<&str>) -> DpopExpect {
    DpopExpect {
        htm: b"GET".to_vec(),
        htu: HTU.as_bytes().to_vec(),
        now: NOW,
        max_skew: 60,
        valid_nonces: nonces.map(|n| n.into_iter().map(|s| s.as_bytes().to_vec()).collect()),
        access_token: token.map(|t| t.as_bytes().to_vec()),
    }
}

fn params() -> ProofParams {
    ProofParams {
        htm: "GET".into(),
        htu: HTU.into(),
        iat: NOW,
        ..ProofParams::default()
    }
}

#[test]
fn dpop_accepts_a_correct_proof_and_returns_the_thumbprint() {
    let key = DpopKey::generate();
    let ok = check_dpop(key.proof(&params()).as_bytes(), &expect(None, None)).unwrap();
    assert_eq!(b64::encode(&ok.jkt), key.jkt());
    assert_eq!(ok.iat, NOW);
}

#[test]
fn dpop_rejections() {
    let key = DpopKey::generate();
    let other = DpopKey::generate();
    let e = expect(Some(vec!["n1", "n0"]), Some("tok"));
    let good = || ProofParams {
        nonce: Some("n1".into()),
        access_token: Some("tok".into()),
        ..params()
    };
    assert!(check_dpop(key.proof(&good()).as_bytes(), &e).is_ok());

    let header = key.header();
    let claims = key.claims(&good());
    let with = |h: serde_json::Value, c: serde_json::Value| key.sign_raw(&h, &c);
    let mut cases: Vec<(&str, String, Reject)> = Vec::new();

    let mut h = header.clone();
    h["alg"] = "ES384".into();
    cases.push(("alg", with(h, claims.clone()), Reject::JwsAlgNotAllowed));
    let mut h = header.clone();
    h["typ"] = "JWT".into();
    cases.push(("typ", with(h, claims.clone()), Reject::JwsTypMismatch));
    let mut h = header.clone();
    h["jku"] = "https://evil".into();
    cases.push(("jku", with(h, claims.clone()), Reject::JwsForbiddenHeader));
    let mut h = header.clone();
    h["jwk"]["d"] = "AAAA".into();
    cases.push((
        "private jwk",
        with(h, claims.clone()),
        Reject::DpopJwkInvalid,
    ));
    let mut h = header.clone();
    h["jwk"]["crv"] = "P-384".into();
    cases.push(("crv", with(h, claims.clone()), Reject::DpopJwkInvalid));
    let mut h = header.clone();
    h["jwk"] = other.jwk();
    cases.push((
        "jwk of another key",
        with(h, claims.clone()),
        Reject::JwsSignatureInvalid,
    ));
    let mut c = claims.clone();
    c["jti"] = "short".into();
    cases.push(("jti", with(header.clone(), c), Reject::DpopJtiInvalid));
    let mut c = claims.clone();
    c["htm"] = "POST".into();
    cases.push(("htm", with(header.clone(), c), Reject::DpopMethodMismatch));
    let mut c = claims.clone();
    c["htu"] = "https://api.example.com/v1/things?x=1".into();
    cases.push((
        "htu with query",
        with(header.clone(), c),
        Reject::DpopUriMismatch,
    ));
    let mut c = claims.clone();
    c["htu"] = "HTTPS://api.example.com/v1/things".into();
    cases.push((
        "htu not canonical",
        with(header.clone(), c),
        Reject::DpopUriMismatch,
    ));
    let mut c = claims.clone();
    c["iat"] = (NOW - 61).into();
    cases.push((
        "iat old",
        with(header.clone(), c),
        Reject::DpopIatOutOfWindow,
    ));
    let mut c = claims.clone();
    c["iat"] = (NOW + 61).into();
    cases.push((
        "iat future",
        with(header.clone(), c),
        Reject::DpopIatOutOfWindow,
    ));
    let mut c = claims.clone();
    c.as_object_mut().unwrap().remove("nonce");
    cases.push((
        "no nonce",
        with(header.clone(), c),
        Reject::DpopNonceMissing,
    ));
    let mut c = claims.clone();
    c["nonce"] = "stale".into();
    cases.push((
        "stale nonce",
        with(header.clone(), c),
        Reject::DpopNonceInvalid,
    ));
    let mut c = claims.clone();
    c.as_object_mut().unwrap().remove("ath");
    cases.push(("no ath", with(header.clone(), c), Reject::DpopAthMissing));
    let mut c = claims.clone();
    c["ath"] = b64::encode(&sha256(b"other")).into();
    cases.push((
        "wrong ath",
        with(header.clone(), c),
        Reject::DpopAthMismatch,
    ));

    for (name, proof, expected) in cases {
        assert_eq!(
            check_dpop(proof.as_bytes(), &e).err(),
            Some(expected),
            "{name}"
        );
    }

    // ath without an access token, and a mangled signature.
    let e2 = expect(None, None);
    let proof = key.proof(&ProofParams {
        access_token: Some("tok".into()),
        ..params()
    });
    assert_eq!(
        check_dpop(proof.as_bytes(), &e2).err(),
        Some(Reject::DpopAthUnexpected)
    );
    let mut proof = key.proof(&params());
    proof.push('A');
    assert!(check_dpop(proof.as_bytes(), &e2).is_err());
    assert_eq!(check_dpop(b"a.b", &e2).err(), Some(Reject::JwsMalformed));
    assert_eq!(
        check_dpop(b"a.b.c.d", &e2).err(),
        Some(Reject::JwsMalformed)
    );
}

fn access_claims(key: &DpopKey, iat: u64) -> AccessTokenClaims {
    AccessTokenClaims {
        iss: ISS.into(),
        sub: "acct".into(),
        aud: AUD.into(),
        client_id: "web".into(),
        iat,
        exp: iat + ACCESS_TOKEN_TTL,
        jti: b64::encode(&[1; 16]),
        auth_time: iat - 10,
        amr: jose::AMR.iter().map(|s| (*s).to_string()).collect(),
        cnf: Cnf { jkt: key.jkt() },
        sid: b64::encode(&[4; 16]),
        cid: b64::encode(b"credential"),
        epoch: 3,
    }
}

fn access_expect(signer: &LocalSigner) -> AccessExpect {
    AccessExpect {
        issuer: ISS.as_bytes().to_vec(),
        audience: AUD.as_bytes().to_vec(),
        keys: vec![LocalSigner::generate().verify_key(), signer.verify_key()],
        now: NOW,
        max_skew: 60,
    }
}

#[test]
fn resource_request_accepts_bound_token_and_proof() {
    let signer = LocalSigner::generate();
    let key = DpopKey::generate();
    let token = signer.sign(jose::TYP_ACCESS, &access_claims(&key, NOW - 5));
    let proof = key.proof(&ProofParams {
        access_token: Some(token.clone()),
        ..params()
    });
    let id = check_resource_request(
        token.as_bytes(),
        proof.as_bytes(),
        &access_expect(&signer),
        &expect(None, Some(&token)),
    )
    .unwrap();
    assert_eq!(id.sub, b"acct");
    assert_eq!(id.client_id, b"web");
    assert_eq!(b64::encode(&id.jkt), key.jkt());
    assert_eq!(id.cid.as_deref(), Some(&b"credential"[..]));
    assert_eq!(id.epoch, Some(3));
}

#[test]
fn session_activity_rule() {
    use auth_core::decide::check_session_active;
    let live = AccountState {
        epoch: 3,
        credential_present: true,
    };
    assert!(check_session_active(Some(3), &live));
    assert!(
        !check_session_active(Some(2), &live),
        "signed out everywhere"
    );
    assert!(
        !check_session_active(None, &live),
        "token without a session reference"
    );
    assert!(
        !check_session_active(
            Some(3),
            &AccountState {
                epoch: 3,
                credential_present: false
            }
        ),
        "passkey removed"
    );
}

#[test]
fn resource_request_rejections() {
    let signer = LocalSigner::generate();
    let key = DpopKey::generate();
    let thief = DpopKey::generate();
    let a = access_expect(&signer);
    let run = |token: &str, proof_key: &DpopKey| {
        let proof = proof_key.proof(&ProofParams {
            access_token: Some(token.to_string()),
            ..params()
        });
        check_resource_request(
            token.as_bytes(),
            proof.as_bytes(),
            &a,
            &expect(None, Some(token)),
        )
        .err()
        .map(|(_, r)| r)
    };

    // A stolen token used with the thief's own DPoP key.
    let token = signer.sign(jose::TYP_ACCESS, &access_claims(&key, NOW));
    assert_eq!(run(&token, &thief), Some(Reject::TokenKeyBindingMismatch));

    // Signed by an unknown key.
    let rogue = LocalSigner::generate();
    let token = rogue.sign(jose::TYP_ACCESS, &access_claims(&key, NOW));
    assert_eq!(run(&token, &key), Some(Reject::JwsUnknownKey));

    // Same kid as a trusted key but signed by another key.
    let mut h = json!({"alg": "ES256", "typ": "at+jwt", "kid": signer.kid()});
    let c = serde_json::to_value(access_claims(&key, NOW)).unwrap();
    let token = rogue.sign_raw(&h, &c);
    assert_eq!(run(&token, &key), Some(Reject::JwsSignatureInvalid));

    // Refresh token or DPoP-typed token presented as an access token.
    h["typ"] = "rt+jwt".into();
    assert_eq!(
        run(&signer.sign_raw(&h, &c), &key),
        Some(Reject::JwsTypMismatch)
    );
    // Embedded jwk header is never trusted in issued tokens.
    let hj = json!({"alg": "ES256", "typ": "at+jwt", "kid": signer.kid(), "jwk": key.jwk()});
    assert_eq!(
        run(&signer.sign_raw(&hj, &c), &key),
        Some(Reject::JwsUnexpectedJwk)
    );
    let hn = json!({"alg": "none", "typ": "at+jwt", "kid": signer.kid()});
    assert_eq!(
        run(&signer.sign_raw(&hn, &c), &key),
        Some(Reject::JwsAlgNotAllowed)
    );

    // Claim failures.
    let mut claims = access_claims(&key, NOW);
    claims.aud = "https://other.example.com".into();
    assert_eq!(
        run(&signer.sign(jose::TYP_ACCESS, &claims), &key),
        Some(Reject::TokenAudienceMismatch)
    );
    let mut claims = access_claims(&key, NOW);
    claims.iss = "https://evil.example.com".into();
    assert_eq!(
        run(&signer.sign(jose::TYP_ACCESS, &claims), &key),
        Some(Reject::TokenIssuerMismatch)
    );
    let claims = access_claims(&key, NOW - ACCESS_TOKEN_TTL);
    assert_eq!(
        run(&signer.sign(jose::TYP_ACCESS, &claims), &key),
        Some(Reject::TokenExpired)
    );
    let claims = access_claims(&key, NOW + 61);
    assert_eq!(
        run(&signer.sign(jose::TYP_ACCESS, &claims), &key),
        Some(Reject::TokenIssuedInFuture)
    );
    let mut claims = access_claims(&key, NOW);
    claims.exp = NOW + ACCESS_TOKEN_TTL + 1;
    assert_eq!(
        run(&signer.sign(jose::TYP_ACCESS, &claims), &key),
        Some(Reject::TokenLifetimeInvalid)
    );

    // Proof made for a different token.
    let token = signer.sign(jose::TYP_ACCESS, &access_claims(&key, NOW));
    let other_token = signer.sign(jose::TYP_ACCESS, &access_claims(&key, NOW - 1));
    let proof = key.proof(&ProofParams {
        access_token: Some(other_token),
        ..params()
    });
    assert_eq!(
        check_resource_request(
            token.as_bytes(),
            proof.as_bytes(),
            &a,
            &expect(None, Some(&token))
        )
        .err(),
        Some((Stage::Proof, Reject::DpopAthMismatch))
    );
}

fn refresh_claims(key: &DpopKey, iat: u64, auth_time: u64, epoch: u64) -> RefreshTokenClaims {
    RefreshTokenClaims {
        iss: ISS.into(),
        aud: ISS.into(),
        sub: "acct".into(),
        client_id: "web".into(),
        iat,
        exp: (iat + REFRESH_IDLE_TTL).min(auth_time + REFRESH_ABSOLUTE_TTL),
        jti: b64::encode(&[2; 16]),
        sid: b64::encode(&[3; 16]),
        auth_time,
        cid: b64::encode(b"credential"),
        epoch,
        cnf: Cnf { jkt: key.jkt() },
    }
}

fn refresh_expect(signer: &LocalSigner, now: u64) -> RefreshExpect {
    RefreshExpect {
        issuer: ISS.as_bytes().to_vec(),
        client_id: b"web".to_vec(),
        keys: vec![signer.verify_key()],
        now,
        max_skew: 120,
    }
}

#[test]
fn refresh_flow_and_revocation_rules() {
    let signer = LocalSigner::generate();
    let key = DpopKey::generate();
    let jkt = b64::decode_str(&key.jkt()).unwrap();
    let token = signer.sign(
        jose::TYP_REFRESH,
        &refresh_claims(&key, NOW - 100, NOW - 1000, 4),
    );
    let v = check_refresh_token(token.as_bytes(), &refresh_expect(&signer, NOW), &jkt).unwrap();
    assert_eq!(v.claims().cid, b"credential");

    let l = authorize_refresh(
        &v,
        &AccountState {
            epoch: 4,
            credential_present: true,
        },
    )
    .unwrap();
    assert_eq!(l.access_exp, NOW + ACCESS_TOKEN_TTL);
    assert_eq!(l.refresh_exp, NOW + REFRESH_IDLE_TTL);

    assert_eq!(
        authorize_refresh(
            &v,
            &AccountState {
                epoch: 5,
                credential_present: true
            }
        )
        .err(),
        Some(Reject::SessionEpochMismatch)
    );
    assert_eq!(
        authorize_refresh(
            &v,
            &AccountState {
                epoch: 4,
                credential_present: false
            }
        )
        .err(),
        Some(Reject::SessionCredentialRevoked)
    );

    // A stolen refresh token is useless with another DPoP key.
    let thief = b64::decode_str(&DpopKey::generate().jkt()).unwrap();
    assert_eq!(
        check_refresh_token(token.as_bytes(), &refresh_expect(&signer, NOW), &thief).err(),
        Some(Reject::TokenKeyBindingMismatch)
    );

    // Wrong client, expired, and an access token presented as a refresh token.
    let mut e = refresh_expect(&signer, NOW);
    e.client_id = b"cli".to_vec();
    assert_eq!(
        check_refresh_token(token.as_bytes(), &e, &jkt).err(),
        Some(Reject::TokenClientMismatch)
    );
    let expired = signer.sign(
        jose::TYP_REFRESH,
        &refresh_claims(&key, NOW - REFRESH_IDLE_TTL, NOW - REFRESH_IDLE_TTL, 4),
    );
    assert_eq!(
        check_refresh_token(expired.as_bytes(), &refresh_expect(&signer, NOW), &jkt).err(),
        Some(Reject::TokenExpired)
    );
    let at = signer.sign(jose::TYP_ACCESS, &refresh_claims(&key, NOW, NOW, 4));
    assert_eq!(
        check_refresh_token(at.as_bytes(), &refresh_expect(&signer, NOW), &jkt).err(),
        Some(Reject::JwsTypMismatch)
    );
}

#[test]
fn sessions_never_outlive_the_absolute_cap() {
    // Refresh every 29 days, forever: the session must end one year after auth_time.
    let auth_time = NOW;
    let mut now = NOW;
    let mut refreshes = 0;
    loop {
        match lifetimes(now, auth_time) {
            Ok(l) => {
                assert!(l.refresh_exp <= auth_time + REFRESH_ABSOLUTE_TTL);
                assert!(l.refresh_exp > now);
                now = (now + 29 * 86_400).min(l.refresh_exp - 1);
                refreshes += 1;
                if now + 1 >= auth_time + REFRESH_ABSOLUTE_TTL {
                    break;
                }
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(refreshes > 12);
    assert_eq!(
        lifetimes(auth_time + REFRESH_ABSOLUTE_TTL, auth_time).err(),
        Some(Reject::TokenExpired)
    );
    assert_eq!(
        lifetimes(NOW, NOW + 1).err(),
        Some(Reject::TokenIssuedInFuture)
    );
    assert_eq!(lifetimes(u64::MAX, NOW).err(), Some(Reject::TimeOverflow));
}

#[test]
fn step_up_and_nonce_windows() {
    assert!(check_step_up(NOW, NOW));
    assert!(check_step_up(NOW - STEP_UP_MAX_AGE, NOW));
    assert!(!check_step_up(NOW - STEP_UP_MAX_AGE - 1, NOW));
    assert!(!check_step_up(NOW + 1, NOW));
    assert_eq!(nonce_windows(600), (2, Some(1)));
    assert_eq!(nonce_windows(10), (0, None));
}
