//! The verified decision layer.
//!
//! Every security decision the service makes goes through a function in this
//! module. Each public function `check_*` is proven to accept **if and only
//! if** its specification (`*_ok`) holds, and the specifications are written
//! to be read and reviewed directly against `docs/protocol.md`.
//!
//! The specifications reference parsers and crypto only through the
//! uninterpreted functions in [`crate::axioms`], so the proofs show the checks
//! are complete and applied to the right bytes, while the correctness of the
//! primitives themselves is part of the trusted base (see
//! `docs/verification.md`).
//!
//! None of the public functions has a precondition, so calling them from
//! unverified code cannot invalidate their guarantees.

// Verus-verified code follows the subset of Rust that Verus supports: explicit
// `match` instead of `let ... else`, `&Vec` parameters (their views are used in
// specifications), `as` casts with proven ranges, and glob imports of spec items.
#![allow(
    clippy::manual_let_else,
    clippy::ptr_arg,
    clippy::ref_option,
    clippy::too_many_arguments,
    clippy::match_like_matches_macro,
    clippy::manual_range_contains,
    clippy::many_single_char_names,
    clippy::cast_lossless,
    clippy::unreadable_literal,
    clippy::wildcard_imports,
    clippy::nonminimal_bool
)]

use crate::axioms::*;
use crate::bytes::*;
use crate::vtypes::*;
use vstd::prelude::*;

verus! {

// =================================================================== constants

/// Access token lifetime (protocol §4).
pub const ACCESS_TOKEN_TTL: u64 = 300;
/// Refresh token idle lifetime.
pub const REFRESH_IDLE_TTL: u64 = 2_592_000;
/// Absolute session lifetime, measured from `auth_time`.
pub const REFRESH_ABSOLUTE_TTL: u64 = 31_536_000;
/// WebAuthn challenge lifetime.
pub const CEREMONY_TTL: u64 = 300;
/// DPoP nonce window length.
pub const DPOP_NONCE_WINDOW: u64 = 300;
/// Allowed DPoP `iat` skew at the auth server.
pub const DPOP_MAX_IAT_SKEW_AUTH_SERVER: u64 = 120;
/// Default allowed DPoP `iat` skew at resource servers.
pub const DPOP_MAX_IAT_SKEW_RESOURCE_DEFAULT: u64 = 60;
/// Maximum age of `auth_time` for step-up protected operations.
pub const STEP_UP_MAX_AGE: u64 = 300;
/// Maximum passkeys per account.
pub const MAX_PASSKEYS_PER_ACCOUNT: u64 = 20;
/// WebAuthn challenge length in bytes.
pub const CHALLENGE_LEN: usize = 32;
/// Maximum credential ID length (WebAuthn §5.1).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// Minimum DPoP `jti` length.
pub const DPOP_JTI_MIN_LEN: usize = 16;
/// Maximum DPoP `jti` length.
pub const DPOP_JTI_MAX_LEN: usize = 128;

/// Authenticator data flag: user present.
pub const FLAG_UP: u8 = 0x01;
/// Authenticator data flag: user verified.
pub const FLAG_UV: u8 = 0x04;
/// Authenticator data flag: backup eligible.
pub const FLAG_BE: u8 = 0x08;
/// Authenticator data flag: backup state.
pub const FLAG_BS: u8 = 0x10;
/// Authenticator data flag: attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Authenticator data flag: extension data included.
pub const FLAG_ED: u8 = 0x80;

// =================================================================== results

/// Why a check failed. Variants are coarse on purpose; the HTTP layer maps
/// them to protocol error codes without leaking detail to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    ClientDataMalformed,
    ClientDataWrongType,
    ChallengeMismatch,
    OriginNotAllowed,
    CrossOrigin,
    TopOriginPresent,
    AttestationMalformed,
    AttestationUnsupported,
    AttestationSignatureInvalid,
    AuthDataMalformed,
    RpIdMismatch,
    UserNotPresent,
    UserNotVerified,
    BackupStateInvalid,
    BackupEligibilityChanged,
    AttestedDataMissing,
    AttestedDataUnexpected,
    CredentialIdInvalid,
    CredentialIdMismatch,
    PublicKeyInvalid,
    AlgorithmNotAllowed,
    ExtensionsMalformed,
    UserHandleMismatch,
    SignatureInvalid,
    SignCountNotIncreasing,
    JwsMalformed,
    JwsAlgNotAllowed,
    JwsTypMismatch,
    JwsForbiddenHeader,
    JwsUnexpectedJwk,
    JwsUnknownKey,
    JwsSignatureInvalid,
    DpopJwkInvalid,
    DpopJtiInvalid,
    DpopMethodMismatch,
    DpopUriMismatch,
    DpopIatOutOfWindow,
    DpopNonceMissing,
    DpopNonceInvalid,
    DpopAthMissing,
    DpopAthMismatch,
    DpopAthUnexpected,
    TokenIssuerMismatch,
    TokenAudienceMismatch,
    TokenClientMismatch,
    TokenExpired,
    TokenIssuedInFuture,
    TokenLifetimeInvalid,
    TokenKeyBindingMismatch,
    SessionEpochMismatch,
    SessionCredentialRevoked,
    TimeOverflow,
}

// =================================================================== literals

pub open spec fn lit_es256() -> Seq<u8> { seq![69u8, 83u8, 50u8, 53u8, 54u8] }
pub open spec fn lit_dpop_jwt() -> Seq<u8> { seq![100u8, 112u8, 111u8, 112u8, 43u8, 106u8, 119u8, 116u8] }
pub open spec fn lit_at_jwt() -> Seq<u8> { seq![97u8, 116u8, 43u8, 106u8, 119u8, 116u8] }
pub open spec fn lit_rt_jwt() -> Seq<u8> { seq![114u8, 116u8, 43u8, 106u8, 119u8, 116u8] }
pub open spec fn lit_ec() -> Seq<u8> { seq![69u8, 67u8] }
pub open spec fn lit_p256() -> Seq<u8> { seq![80u8, 45u8, 50u8, 53u8, 54u8] }

fn is_es256(x: &[u8]) -> (r: bool)
    ensures r == (x@ == lit_es256()),
{
    let lit: [u8; 5] = [69, 83, 50, 53, 54];
    assert(lit@ =~= lit_es256());
    bytes_eq(x, &lit)
}

fn is_dpop_jwt(x: &[u8]) -> (r: bool)
    ensures r == (x@ == lit_dpop_jwt()),
{
    let lit: [u8; 8] = [100, 112, 111, 112, 43, 106, 119, 116];
    assert(lit@ =~= lit_dpop_jwt());
    bytes_eq(x, &lit)
}

fn is_at_jwt(x: &[u8]) -> (r: bool)
    ensures r == (x@ == lit_at_jwt()),
{
    let lit: [u8; 6] = [97, 116, 43, 106, 119, 116];
    assert(lit@ =~= lit_at_jwt());
    bytes_eq(x, &lit)
}

fn is_rt_jwt(x: &[u8]) -> (r: bool)
    ensures r == (x@ == lit_rt_jwt()),
{
    let lit: [u8; 6] = [114, 116, 43, 106, 119, 116];
    assert(lit@ =~= lit_rt_jwt());
    bytes_eq(x, &lit)
}

fn is_ec(x: &[u8]) -> (r: bool)
    ensures r == (x@ == lit_ec()),
{
    let lit: [u8; 2] = [69, 67];
    assert(lit@ =~= lit_ec());
    bytes_eq(x, &lit)
}

fn is_p256(x: &[u8]) -> (r: bool)
    ensures r == (x@ == lit_p256()),
{
    let lit: [u8; 5] = [80, 45, 50, 53, 54];
    assert(lit@ =~= lit_p256());
    bytes_eq(x, &lit)
}

fn opt_is(x: &Option<Vec<u8>>, lit_kind: u8) -> (r: bool)
    requires lit_kind <= 2,
    ensures
        lit_kind == 0 ==> r == (opt_view(*x) == Some(lit_dpop_jwt())),
        lit_kind == 1 ==> r == (opt_view(*x) == Some(lit_at_jwt())),
        lit_kind == 2 ==> r == (opt_view(*x) == Some(lit_rt_jwt())),
{
    match x {
        Some(v) => {
            if lit_kind == 0 { is_dpop_jwt(v.as_slice()) }
            else if lit_kind == 1 { is_at_jwt(v.as_slice()) }
            else { is_rt_jwt(v.as_slice()) }
        }
        None => false,
    }
}

// =================================================================== policies

/// WebAuthn relying-party policy.
#[derive(Debug)]
pub struct RpPolicy {
    /// SHA-256 of the RP ID.
    pub rp_id_hash: Vec<u8>,
    /// Allowed origins, matched exactly.
    pub origins: Vec<Vec<u8>>,
}

// =================================================================== client data

pub open spec fn client_data_fields_ok(cd: ClientDataV, typ: CdType, challenge: Seq<u8>, origins: Seq<Vec<u8>>) -> bool {
    &&& cd.typ == typ
    &&& cd.challenge == challenge
    &&& seq_in(cd.origin, origins)
    &&& !cd.cross_origin
    &&& !cd.top_origin_present
}

/// `clientDataJSON` is acceptable for a ceremony of type `typ` with the
/// expected challenge (WebAuthn §7.1 steps 7–10, §7.2 steps 11–14).
pub open spec fn client_data_ok(raw: Seq<u8>, typ: CdType, challenge: Seq<u8>, origins: Seq<Vec<u8>>) -> bool {
    match spec_parse_client_data(raw) {
        Some(cd) => client_data_fields_ok(cd, typ, challenge, origins),
        None => false,
    }
}

fn same_type(a: CdType, b: CdType) -> (r: bool)
    ensures r == (a == b),
{
    match (a, b) {
        (CdType::Create, CdType::Create) => true,
        (CdType::Get, CdType::Get) => true,
        (CdType::Other, CdType::Other) => true,
        _ => false,
    }
}

fn check_client_data(raw: &[u8], typ: CdType, challenge: &[u8], origins: &Vec<Vec<u8>>) -> (r: Result<(), Reject>)
    ensures r is Ok <==> client_data_ok(raw@, typ, challenge@, origins@),
{
    let cd = match parse_client_data(raw) {
        Some(cd) => cd,
        None => return Err(Reject::ClientDataMalformed),
    };
    if !same_type(cd.typ, typ) {
        return Err(Reject::ClientDataWrongType);
    }
    if !bytes_eq(cd.challenge.as_slice(), challenge) {
        return Err(Reject::ChallengeMismatch);
    }
    if !contains(origins, cd.origin.as_slice()) {
        return Err(Reject::OriginNotAllowed);
    }
    if cd.cross_origin {
        return Err(Reject::CrossOrigin);
    }
    if cd.top_origin_present {
        return Err(Reject::TopOriginPresent);
    }
    Ok(())
}

// =================================================================== authenticator data

pub open spec fn flag(flags: u8, f: u8) -> bool { flags & f != 0 }

/// Flags common to every ceremony: user present, user verified, and backup
/// state only when backup eligible (WebAuthn §6.1.3).
pub open spec fn flags_ok(flags: u8) -> bool {
    &&& flag(flags, FLAG_UP)
    &&& flag(flags, FLAG_UV)
    &&& (flag(flags, FLAG_BS) ==> flag(flags, FLAG_BE))
}

/// The bytes after the fixed or attested part: an extensions map iff ED is set.
pub open spec fn extensions_ok(flags: u8, rest: Seq<u8>) -> bool {
    if flag(flags, FLAG_ED) { spec_cbor_single_map(rest) } else { rest.len() == 0 }
}

pub open spec fn alg_allowed(alg: i64) -> bool {
    alg == -7 || alg == -8 || alg == -257
}

fn check_flags(flags: u8) -> (r: Result<(), Reject>)
    ensures r is Ok <==> flags_ok(flags),
{
    if flags & FLAG_UP == 0 {
        return Err(Reject::UserNotPresent);
    }
    if flags & FLAG_UV == 0 {
        return Err(Reject::UserNotVerified);
    }
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(Reject::BackupStateInvalid);
    }
    Ok(())
}

fn check_extensions(flags: u8, ad: &[u8], start: usize) -> (r: Result<(), Reject>)
    requires start <= ad@.len(),
    ensures r is Ok <==> extensions_ok(flags, ad@.subrange(start as int, ad@.len() as int)),
{
    if flags & FLAG_ED != 0 {
        let rest = copy_range(ad, start, ad.len());
        if cbor_single_map(rest.as_slice()) { Ok(()) } else { Err(Reject::ExtensionsMalformed) }
    } else if start == ad.len() {
        Ok(())
    } else {
        Err(Reject::ExtensionsMalformed)
    }
}

// =================================================================== registration

/// Offset of the credential public key in attested authenticator data.
pub open spec fn cose_start(ad: Seq<u8>) -> int { 55 + be_u16(ad, 53) as int }

/// The COSE_Key at the start of the credential public key position.
pub open spec fn cose_info(ad: Seq<u8>) -> Option<(i64, nat)> {
    spec_cose_prefix(ad.subrange(cose_start(ad), ad.len() as int))
}

/// Authenticator data acceptable for registration (WebAuthn §7.1 steps 13–20).
pub open spec fn reg_auth_data_ok(ad: Seq<u8>, rp_id_hash: Seq<u8>, raw_id: Seq<u8>) -> bool {
    &&& ad.len() >= 55
    &&& ad.subrange(0, 32) == rp_id_hash
    &&& flags_ok(ad[32])
    &&& flag(ad[32], FLAG_AT)
    &&& 1 <= be_u16(ad, 53) <= 1023
    &&& cose_start(ad) <= ad.len()
    &&& ad.subrange(55, cose_start(ad)) == raw_id
    &&& match cose_info(ad) {
        Some((alg, n)) => alg_allowed(alg) && extensions_ok(ad[32], ad.subrange(cose_start(ad) + n, ad.len() as int)),
        None => false,
    }
}

/// The attestation statement is `none`, or `packed` self attestation signed by
/// the new credential key with the credential's algorithm (WebAuthn §8.2, §8.7).
pub open spec fn att_stmt_ok(stmt: AttStmtV, alg: i64, cose: Seq<u8>, msg: Seq<u8>) -> bool {
    match stmt {
        AttStmtV::NoneFmt => true,
        AttStmtV::PackedSelf { alg: a, sig } => a == alg && spec_verify_cose(cose, msg, sig),
        AttStmtV::Unsupported => false,
    }
}

/// Full registration acceptance condition.
pub open spec fn registration_ok(p: RpPolicy, challenge: Seq<u8>, cdj: Seq<u8>, att: Seq<u8>, raw_id: Seq<u8>) -> bool {
    &&& client_data_ok(cdj, CdType::Create, challenge, p.origins@)
    &&& match spec_parse_att_obj(att) {
        Some(a) => {
            &&& reg_auth_data_ok(a.auth_data, p.rp_id_hash@, raw_id)
            &&& match cose_info(a.auth_data) {
                Some((alg, n)) => att_stmt_ok(
                    a.stmt,
                    alg,
                    a.auth_data.subrange(cose_start(a.auth_data), cose_start(a.auth_data) + n),
                    a.auth_data + spec_sha256(cdj),
                ),
                None => false,
            }
        }
        None => false,
    }
}

/// A newly registered credential.
#[derive(Debug)]
pub struct NewCredential {
    pub credential_id: Vec<u8>,
    /// The COSE_Key exactly as the authenticator encoded it.
    pub cose_key: Vec<u8>,
    pub alg: i64,
    pub sign_count: u32,
    pub aaguid: Vec<u8>,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// The outputs of a successful registration are read from the right offsets.
pub open spec fn new_credential_matches(c: NewCredential, ad: Seq<u8>, raw_id: Seq<u8>) -> bool {
    &&& c.credential_id@ == raw_id
    &&& cose_info(ad) matches Some((alg, n))
        && c.alg == alg
        && c.cose_key@ == ad.subrange(cose_start(ad), cose_start(ad) + n)
    &&& c.sign_count as nat == be_u32(ad, 33)
    &&& c.aaguid@ == ad.subrange(37, 53)
    &&& c.backup_eligible == flag(ad[32], FLAG_BE)
    &&& c.backup_state == flag(ad[32], FLAG_BS)
}

/// Verifies a registration response (`navigator.credentials.create`).
pub fn check_registration(p: &RpPolicy, challenge: &[u8], cdj: &[u8], att: &[u8], raw_id: &[u8]) -> (r: Result<NewCredential, Reject>)
    ensures
        r is Ok <==> registration_ok(*p, challenge@, cdj@, att@, raw_id@),
        r matches Ok(c) ==> (spec_parse_att_obj(att@) matches Some(a) && new_credential_matches(c, a.auth_data, raw_id@)),
{
    check_client_data(cdj, CdType::Create, challenge, &p.origins)?;
    let a = match parse_att_obj(att) {
        Some(a) => a,
        None => return Err(Reject::AttestationMalformed),
    };
    let ad = a.auth_data.as_slice();
    if ad.len() < 55 {
        return Err(Reject::AuthDataMalformed);
    }
    let rp_hash = copy_range(ad, 0, 32);
    if !bytes_eq(rp_hash.as_slice(), p.rp_id_hash.as_slice()) {
        return Err(Reject::RpIdMismatch);
    }
    let flags = ad[32];
    check_flags(flags)?;
    if flags & FLAG_AT == 0 {
        return Err(Reject::AttestedDataMissing);
    }
    let id_len = read_be_u16(ad, 53);
    if id_len < 1 || id_len > MAX_CREDENTIAL_ID_LEN {
        return Err(Reject::CredentialIdInvalid);
    }
    let start = 55 + id_len;
    if start > ad.len() {
        return Err(Reject::AuthDataMalformed);
    }
    let cred_id = copy_range(ad, 55, start);
    if !bytes_eq(cred_id.as_slice(), raw_id) {
        return Err(Reject::CredentialIdMismatch);
    }
    let rest = copy_range(ad, start, ad.len());
    let (alg, n) = match cose_prefix(rest.as_slice()) {
        Some(x) => x,
        None => return Err(Reject::PublicKeyInvalid),
    };
    assert(cose_start(ad@) == start as int);
    assert(rest@ == ad@.subrange(cose_start(ad@), ad@.len() as int));
    if !(alg == -7 || alg == -8 || alg == -257) {
        return Err(Reject::AlgorithmNotAllowed);
    }
    let key_end = start + n;
    check_extensions(flags, ad, key_end)?;
    let cose_key = copy_range(ad, start, key_end);
    let cd_hash = sha256(cdj);
    let msg = concat(ad, cd_hash.as_slice());
    match &a.stmt {
        AttStmt::NoneFmt => {}
        AttStmt::PackedSelf { alg: att_alg, sig } => {
            if *att_alg != alg {
                return Err(Reject::AttestationUnsupported);
            }
            if !verify_cose(cose_key.as_slice(), msg.as_slice(), sig.as_slice()) {
                return Err(Reject::AttestationSignatureInvalid);
            }
        }
        AttStmt::Unsupported => return Err(Reject::AttestationUnsupported),
    }
    let aaguid = copy_range(ad, 37, 53);
    Ok(NewCredential {
        credential_id: copy_all(raw_id),
        cose_key,
        alg,
        sign_count: read_be_u32(ad, 33),
        aaguid,
        backup_eligible: flags & FLAG_BE != 0,
        backup_state: flags & FLAG_BS != 0,
    })
}

// =================================================================== authentication

/// A credential as stored by the service.
#[derive(Debug)]
pub struct StoredCredential {
    pub account_id: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub cose_key: Vec<u8>,
    pub sign_count: u32,
    pub backup_eligible: bool,
}

/// Signature counter rule (protocol §8): both zero, or strictly increasing.
pub open spec fn sign_count_ok(stored: u32, received: nat) -> bool {
    (stored == 0 && received == 0) || received > stored as nat
}

/// Full authentication acceptance condition (WebAuthn §7.2).
pub open spec fn assertion_ok(
    p: RpPolicy,
    challenge: Seq<u8>,
    s: StoredCredential,
    cdj: Seq<u8>,
    ad: Seq<u8>,
    sig: Seq<u8>,
    raw_id: Seq<u8>,
    user_handle: Option<Seq<u8>>,
) -> bool {
    &&& raw_id == s.credential_id@
    &&& user_handle == Some(s.account_id@)
    &&& client_data_ok(cdj, CdType::Get, challenge, p.origins@)
    &&& ad.len() >= 37
    &&& ad.subrange(0, 32) == p.rp_id_hash@
    &&& flags_ok(ad[32])
    &&& !flag(ad[32], FLAG_AT)
    &&& flag(ad[32], FLAG_BE) == s.backup_eligible
    &&& extensions_ok(ad[32], ad.subrange(37, ad.len() as int))
    &&& sign_count_ok(s.sign_count, be_u32(ad, 33))
    &&& spec_verify_cose(s.cose_key@, ad + spec_sha256(cdj), sig)
}

/// Result of a successful authentication.
#[derive(Debug)]
pub struct AssertionOk {
    /// The counter to store.
    pub sign_count: u32,
    /// The current backup state to store.
    pub backup_state: bool,
}

/// Verifies an authentication response (`navigator.credentials.get`).
pub fn check_assertion(
    p: &RpPolicy,
    challenge: &[u8],
    s: &StoredCredential,
    cdj: &[u8],
    ad: &[u8],
    sig: &[u8],
    raw_id: &[u8],
    user_handle: &Option<Vec<u8>>,
) -> (r: Result<AssertionOk, Reject>)
    ensures
        r is Ok <==> assertion_ok(*p, challenge@, *s, cdj@, ad@, sig@, raw_id@, opt_view(*user_handle)),
        r matches Ok(o) ==> o.sign_count as nat == be_u32(ad@, 33) && o.backup_state == flag(ad@[32], FLAG_BS),
{
    if !bytes_eq(raw_id, s.credential_id.as_slice()) {
        return Err(Reject::CredentialIdMismatch);
    }
    match user_handle {
        Some(uh) => {
            if !bytes_eq(uh.as_slice(), s.account_id.as_slice()) {
                return Err(Reject::UserHandleMismatch);
            }
        }
        None => return Err(Reject::UserHandleMismatch),
    }
    check_client_data(cdj, CdType::Get, challenge, &p.origins)?;
    if ad.len() < 37 {
        return Err(Reject::AuthDataMalformed);
    }
    let rp_hash = copy_range(ad, 0, 32);
    if !bytes_eq(rp_hash.as_slice(), p.rp_id_hash.as_slice()) {
        return Err(Reject::RpIdMismatch);
    }
    let flags = ad[32];
    check_flags(flags)?;
    if flags & FLAG_AT != 0 {
        return Err(Reject::AttestedDataUnexpected);
    }
    if (flags & FLAG_BE != 0) != s.backup_eligible {
        return Err(Reject::BackupEligibilityChanged);
    }
    check_extensions(flags, ad, 37)?;
    let count = read_be_u32(ad, 33);
    if !((s.sign_count == 0 && count == 0) || count > s.sign_count) {
        return Err(Reject::SignCountNotIncreasing);
    }
    let cd_hash = sha256(cdj);
    let msg = concat(ad, cd_hash.as_slice());
    if !verify_cose(s.cose_key.as_slice(), msg.as_slice(), sig) {
        return Err(Reject::SignatureInvalid);
    }
    Ok(AssertionOk { sign_count: count, backup_state: flags & FLAG_BS != 0 })
}

// =================================================================== JOSE helpers

/// `i` is the first key whose `kid` equals `kid`.
pub open spec fn first_key(keys: Seq<VerifyKey>, kid: Seq<u8>, i: int) -> bool {
    &&& 0 <= i < keys.len()
    &&& keys[i].kid@ == kid
    &&& forall|j: int| #![trigger keys[j]] 0 <= j < i ==> keys[j].kid@ != kid
}

/// The signature verifies under the first key with a matching `kid`.
pub open spec fn signed_by_key(keys: Seq<VerifyKey>, kid: Seq<u8>, input: Seq<u8>, sig: Seq<u8>) -> bool {
    exists|i: int| #[trigger] first_key(keys, kid, i) && spec_verify_es256(keys[i].x@, keys[i].y@, input, sig)
}

fn find_key(keys: &Vec<VerifyKey>, kid: &[u8]) -> (r: Option<usize>)
    ensures
        r matches Some(i) ==> first_key(keys@, kid@, i as int),
        r is None ==> forall|j: int| #![trigger keys@[j]] 0 <= j < keys@.len() ==> keys@[j].kid@ != kid@,
{
    let mut i: usize = 0;
    while i < keys.len()
        invariant
            i <= keys@.len(),
            forall|j: int| #![trigger keys@[j]] 0 <= j < i ==> keys@[j].kid@ != kid@,
        decreases keys.len() - i,
    {
        if bytes_eq(keys[i].kid.as_slice(), kid) {
            return Some(i);
        }
        i += 1;
    }
    None
}

proof fn lemma_first_key_unique(keys: Seq<VerifyKey>, kid: Seq<u8>, i: int, j: int)
    requires first_key(keys, kid, i), first_key(keys, kid, j),
    ensures i == j,
{
}

/// Header of a token issued by this service: `alg`, `typ`, a `kid`, and no
/// embedded or remote keys (RFC 8725 §3.1, §3.11).
pub open spec fn issued_header_ok(h: JwsHeaderV, typ: Seq<u8>) -> bool {
    &&& h.alg == lit_es256()
    &&& h.typ == Some(typ)
    &&& !h.has_forbidden
    &&& h.jwk is None
    &&& h.kid is Some
}

/// Checks the header and signature of a token issued by this service.
fn check_issued_jws(parts: &JwsParts, keys: &Vec<VerifyKey>, typ_kind: u8) -> (r: Result<JwsHeader, Reject>)
    requires typ_kind == 1 || typ_kind == 2,
    ensures
        r is Ok <==> (spec_parse_jws_header(parts.header@) matches Some(h)
            && issued_header_ok(h, if typ_kind == 1 { lit_at_jwt() } else { lit_rt_jwt() })
            && signed_by_key(keys@, h.kid->Some_0, parts.signing_input@, parts.signature@)),
        r matches Ok(h) ==> spec_parse_jws_header(parts.header@) == Some(h@),
{
    let h = match parse_jws_header(parts.header.as_slice()) {
        Some(h) => h,
        None => return Err(Reject::JwsMalformed),
    };
    if !is_es256(h.alg.as_slice()) {
        return Err(Reject::JwsAlgNotAllowed);
    }
    if !opt_is(&h.typ, typ_kind) {
        return Err(Reject::JwsTypMismatch);
    }
    if h.has_forbidden {
        return Err(Reject::JwsForbiddenHeader);
    }
    if h.jwk.is_some() {
        return Err(Reject::JwsUnexpectedJwk);
    }
    let kid = match &h.kid {
        Some(k) => k,
        None => return Err(Reject::JwsUnknownKey),
    };
    let i = match find_key(keys, kid.as_slice()) {
        Some(i) => i,
        None => return Err(Reject::JwsUnknownKey),
    };
    let key = &keys[i];
    if !verify_es256(key.x.as_slice(), key.y.as_slice(), parts.signing_input.as_slice(), parts.signature.as_slice()) {
        proof {
            assert forall|j: int| #[trigger] first_key(keys@, kid@, j) implies !spec_verify_es256(keys@[j].x@, keys@[j].y@, parts.signing_input@, parts.signature@) by {
                lemma_first_key_unique(keys@, kid@, i as int, j);
            }
        }
        return Err(Reject::JwsSignatureInvalid);
    }
    Ok(h)
}

/// `|iat - now| <= skew`, in mathematical integers.
pub open spec fn iat_in_window(iat: u64, now: u64, skew: u64) -> bool {
    &&& iat as int <= now as int + skew as int
    &&& now as int <= iat as int + skew as int
}

fn check_iat_window(iat: u64, now: u64, skew: u64) -> (r: bool)
    ensures r == iat_in_window(iat, now, skew),
{
    if iat <= now { now - iat <= skew } else { iat - now <= skew }
}

// =================================================================== DPoP

/// What the server expects of a DPoP proof on this request.
#[derive(Debug)]
pub struct DpopExpect {
    /// HTTP method, e.g. `POST`.
    pub htm: Vec<u8>,
    /// Canonical request URI without query or fragment.
    pub htu: Vec<u8>,
    /// Server time.
    pub now: u64,
    /// Allowed `iat` skew.
    pub max_skew: u64,
    /// Currently valid nonces, or `None` when nonces are not required.
    pub valid_nonces: Option<Vec<Vec<u8>>>,
    /// The access token presented with the proof, if any.
    pub access_token: Option<Vec<u8>>,
}

pub open spec fn dpop_header_ok(h: JwsHeaderV) -> bool {
    &&& h.alg == lit_es256()
    &&& h.typ == Some(lit_dpop_jwt())
    &&& !h.has_forbidden
    &&& h.jwk matches Some(j)
        && j.kty == lit_ec()
        && j.crv == lit_p256()
        && j.x.len() == 32
        && j.y.len() == 32
        && !j.has_private
}

pub open spec fn nonce_ok(nonce: Option<Seq<u8>>, valid: Option<Vec<Vec<u8>>>) -> bool {
    match valid {
        None => true,
        Some(set) => nonce matches Some(n) && seq_in(n, set@),
    }
}

pub open spec fn ath_ok(ath: Option<Seq<u8>>, token: Option<Vec<u8>>) -> bool {
    match token {
        None => ath is None,
        Some(t) => ath == Some(spec_sha256(t@)),
    }
}

pub open spec fn dpop_claims_ok(c: DpopClaimsV, e: DpopExpect) -> bool {
    &&& DPOP_JTI_MIN_LEN <= c.jti.len() <= DPOP_JTI_MAX_LEN
    &&& c.htm == e.htm@
    &&& c.htu == e.htu@
    &&& iat_in_window(c.iat, e.now, e.max_skew)
    &&& nonce_ok(c.nonce, e.valid_nonces)
    &&& ath_ok(c.ath, e.access_token)
}

/// Full DPoP proof acceptance condition (RFC 9449 §4.3).
pub open spec fn dpop_ok(raw: Seq<u8>, e: DpopExpect) -> bool {
    match spec_split_jws(raw) {
        Some(parts) => match (spec_parse_jws_header(parts.header), spec_parse_dpop_claims(parts.claims)) {
            (Some(h), Some(c)) => {
                &&& dpop_header_ok(h)
                &&& spec_verify_es256(h.jwk->Some_0.x, h.jwk->Some_0.y, parts.signing_input, parts.signature)
                &&& dpop_claims_ok(c, e)
            }
            _ => false,
        },
        None => false,
    }
}

/// The key thumbprint of an accepted proof.
pub open spec fn dpop_jkt(raw: Seq<u8>) -> Seq<u8> {
    let h = spec_parse_jws_header(spec_split_jws(raw)->Some_0.header)->Some_0;
    spec_jkt(h.jwk->Some_0.x, h.jwk->Some_0.y)
}

/// An accepted DPoP proof.
#[derive(Debug)]
pub struct DpopOk {
    /// RFC 7638 thumbprint of the proof key.
    pub jkt: Vec<u8>,
    /// The proof's `jti`, for replay tracking.
    pub jti: Vec<u8>,
    /// The proof's `iat`.
    pub iat: u64,
}

/// Verifies a DPoP proof.
pub fn check_dpop(raw: &[u8], e: &DpopExpect) -> (r: Result<DpopOk, Reject>)
    ensures
        r is Ok <==> dpop_ok(raw@, *e),
        r matches Ok(o) ==> o.jkt@ == dpop_jkt(raw@),
{
    let parts = match split_jws(raw) {
        Some(p) => p,
        None => return Err(Reject::JwsMalformed),
    };
    let h = match parse_jws_header(parts.header.as_slice()) {
        Some(h) => h,
        None => return Err(Reject::JwsMalformed),
    };
    let c = match parse_dpop_claims(parts.claims.as_slice()) {
        Some(c) => c,
        None => return Err(Reject::JwsMalformed),
    };
    if !is_es256(h.alg.as_slice()) {
        return Err(Reject::JwsAlgNotAllowed);
    }
    if !opt_is(&h.typ, 0) {
        return Err(Reject::JwsTypMismatch);
    }
    if h.has_forbidden {
        return Err(Reject::JwsForbiddenHeader);
    }
    let jwk = match &h.jwk {
        Some(j) => j,
        None => return Err(Reject::DpopJwkInvalid),
    };
    if !is_ec(jwk.kty.as_slice()) || !is_p256(jwk.crv.as_slice()) || jwk.x.len() != 32 || jwk.y.len() != 32 || jwk.has_private {
        return Err(Reject::DpopJwkInvalid);
    }
    if !verify_es256(jwk.x.as_slice(), jwk.y.as_slice(), parts.signing_input.as_slice(), parts.signature.as_slice()) {
        return Err(Reject::JwsSignatureInvalid);
    }
    if c.jti.len() < DPOP_JTI_MIN_LEN || c.jti.len() > DPOP_JTI_MAX_LEN {
        return Err(Reject::DpopJtiInvalid);
    }
    if !bytes_eq(c.htm.as_slice(), e.htm.as_slice()) {
        return Err(Reject::DpopMethodMismatch);
    }
    if !bytes_eq(c.htu.as_slice(), e.htu.as_slice()) {
        return Err(Reject::DpopUriMismatch);
    }
    if !check_iat_window(c.iat, e.now, e.max_skew) {
        return Err(Reject::DpopIatOutOfWindow);
    }
    match &e.valid_nonces {
        None => {}
        Some(set) => match &c.nonce {
            Some(n) => {
                if !contains(set, n.as_slice()) {
                    return Err(Reject::DpopNonceInvalid);
                }
            }
            None => return Err(Reject::DpopNonceMissing),
        },
    }
    match &e.access_token {
        None => {
            if c.ath.is_some() {
                return Err(Reject::DpopAthUnexpected);
            }
        }
        Some(t) => {
            let expected = sha256(t.as_slice());
            match &c.ath {
                Some(a) => {
                    if !bytes_eq(a.as_slice(), expected.as_slice()) {
                        return Err(Reject::DpopAthMismatch);
                    }
                }
                None => return Err(Reject::DpopAthMissing),
            }
        }
    }
    let jkt = jkt(jwk.x.as_slice(), jwk.y.as_slice());
    Ok(DpopOk { jkt, jti: copy_all(c.jti.as_slice()), iat: c.iat })
}

// =================================================================== access tokens

/// What a resource server expects of an access token.
#[derive(Debug)]
pub struct AccessExpect {
    pub issuer: Vec<u8>,
    pub audience: Vec<u8>,
    pub keys: Vec<VerifyKey>,
    pub now: u64,
    pub max_skew: u64,
}

pub open spec fn access_claims_ok(c: AccessClaimsV, e: AccessExpect) -> bool {
    &&& c.iss == e.issuer@
    &&& c.aud == e.audience@
    &&& (e.now as int) < (c.exp as int)
    &&& c.iat as int <= e.now as int + e.max_skew as int
    &&& c.iat as int <= c.exp as int
    &&& c.exp as int <= c.iat as int + ACCESS_TOKEN_TTL as int
    &&& c.auth_time as int <= c.iat as int
    &&& c.jkt.len() == 32
}

/// Full access-token acceptance condition (RFC 9068 §4, protocol §6.1).
pub open spec fn access_ok(raw: Seq<u8>, e: AccessExpect) -> bool {
    match spec_split_jws(raw) {
        Some(parts) => match (spec_parse_jws_header(parts.header), spec_parse_access_claims(parts.claims)) {
            (Some(h), Some(c)) => {
                &&& issued_header_ok(h, lit_at_jwt())
                &&& signed_by_key(e.keys@, h.kid->Some_0, parts.signing_input, parts.signature)
                &&& access_claims_ok(c, e)
            }
            _ => false,
        },
        None => false,
    }
}

pub open spec fn access_claims_of(raw: Seq<u8>) -> AccessClaimsV {
    spec_parse_access_claims(spec_split_jws(raw)->Some_0.claims)->Some_0
}

fn check_access_token(raw: &[u8], e: &AccessExpect) -> (r: Result<AccessClaims, Reject>)
    ensures
        r is Ok <==> access_ok(raw@, *e),
        r matches Ok(c) ==> c@ == access_claims_of(raw@),
{
    let parts = match split_jws(raw) {
        Some(p) => p,
        None => return Err(Reject::JwsMalformed),
    };
    let c = match parse_access_claims(parts.claims.as_slice()) {
        Some(c) => c,
        None => return Err(Reject::JwsMalformed),
    };
    let _h = check_issued_jws(&parts, &e.keys, 1)?;
    if !bytes_eq(c.iss.as_slice(), e.issuer.as_slice()) {
        return Err(Reject::TokenIssuerMismatch);
    }
    if !bytes_eq(c.aud.as_slice(), e.audience.as_slice()) {
        return Err(Reject::TokenAudienceMismatch);
    }
    if e.now >= c.exp {
        return Err(Reject::TokenExpired);
    }
    if c.iat > e.now && c.iat - e.now > e.max_skew {
        return Err(Reject::TokenIssuedInFuture);
    }
    if c.iat > c.exp || c.exp - c.iat > ACCESS_TOKEN_TTL || c.auth_time > c.iat {
        return Err(Reject::TokenLifetimeInvalid);
    }
    if c.jkt.len() != 32 {
        return Err(Reject::TokenKeyBindingMismatch);
    }
    Ok(c)
}

/// Which part of a resource request failed, so the HTTP layer can choose the
/// RFC 9449 error code (`invalid_token`, `invalid_dpop_proof`, `use_dpop_nonce`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// The access token itself.
    AccessToken,
    /// The DPoP proof.
    Proof,
    /// The binding between them (`ath`, `cnf.jkt`).
    Binding,
}

/// An authenticated caller, as established by an access token and its DPoP proof.
#[derive(Debug)]
pub struct Identity {
    pub sub: Vec<u8>,
    pub client_id: Vec<u8>,
    pub auth_time: u64,
    pub exp: u64,
    pub jkt: Vec<u8>,
    /// The proof's `jti`, for replay tracking.
    pub dpop_jti: Vec<u8>,
    /// The passkey that started the session (`cid`), if the token carries it.
    pub cid: Option<Vec<u8>>,
    /// The registration ID of that passkey (`rid`), if the token carries it.
    pub rid: Option<Vec<u8>>,
    /// The session's epoch (`epoch`), if the token carries it.
    pub epoch: Option<u64>,
}

/// A resource request is accepted iff the access token is valid, the DPoP
/// proof is valid for this request and covers this token (`ath`), and the
/// proof key is the key the token is bound to (`cnf.jkt`). See the
/// postcondition of [`check_resource_request`].
pub fn check_resource_request(token: &[u8], proof: &[u8], a: &AccessExpect, d: &DpopExpect) -> (r: Result<Identity, (Stage, Reject)>)
    ensures
        r is Ok <==> (opt_view(d.access_token) == Some(token@)
            && access_ok(token@, *a)
            && dpop_ok(proof@, *d)
            && access_claims_of(token@).jkt == dpop_jkt(proof@)),
        r matches Ok(id) ==> id.sub@ == access_claims_of(token@).sub
            && id.client_id@ == access_claims_of(token@).client_id
            && id.auth_time == access_claims_of(token@).auth_time
            && id.jkt@ == dpop_jkt(proof@)
            && opt_view(id.cid) == access_claims_of(token@).cid
            && opt_view(id.rid) == access_claims_of(token@).rid
            && id.epoch == access_claims_of(token@).epoch,
{
    match &d.access_token {
        Some(t) => {
            if !bytes_eq(t.as_slice(), token) {
                return Err((Stage::Binding, Reject::DpopAthMismatch));
            }
        }
        None => return Err((Stage::Binding, Reject::DpopAthMissing)),
    }
    let c = match check_access_token(token, a) {
        Ok(c) => c,
        Err(e) => return Err((Stage::AccessToken, e)),
    };
    let p = match check_dpop(proof, d) {
        Ok(p) => p,
        Err(e) => return Err((Stage::Proof, e)),
    };
    if !bytes_eq(c.jkt.as_slice(), p.jkt.as_slice()) {
        return Err((Stage::Binding, Reject::TokenKeyBindingMismatch));
    }
    Ok(Identity {
        sub: c.sub,
        client_id: c.client_id,
        auth_time: c.auth_time,
        exp: c.exp,
        jkt: p.jkt,
        dpop_jti: p.jti,
        cid: c.cid,
        rid: c.rid,
        epoch: c.epoch,
    })
}

// =================================================================== refresh tokens

/// What the token endpoint expects of a refresh token.
#[derive(Debug)]
pub struct RefreshExpect {
    pub issuer: Vec<u8>,
    pub client_id: Vec<u8>,
    pub keys: Vec<VerifyKey>,
    pub now: u64,
    pub max_skew: u64,
}

pub open spec fn refresh_claims_ok(c: RefreshClaimsV, e: RefreshExpect, dpop_jkt: Seq<u8>) -> bool {
    &&& c.iss == e.issuer@
    &&& c.aud == e.issuer@
    &&& c.client_id == e.client_id@
    &&& (e.now as int) < (c.exp as int)
    &&& c.iat as int <= e.now as int + e.max_skew as int
    &&& c.auth_time as int <= c.iat as int
    &&& c.exp as int <= c.auth_time as int + REFRESH_ABSOLUTE_TTL as int
    &&& c.jkt == dpop_jkt
}

/// Stateless refresh-token acceptance condition (protocol §6.2 rules 1–4).
pub open spec fn refresh_token_ok(raw: Seq<u8>, e: RefreshExpect, dpop_jkt: Seq<u8>) -> bool {
    match spec_split_jws(raw) {
        Some(parts) => match (spec_parse_jws_header(parts.header), spec_parse_refresh_claims(parts.claims)) {
            (Some(h), Some(c)) => {
                &&& issued_header_ok(h, lit_rt_jwt())
                &&& signed_by_key(e.keys@, h.kid->Some_0, parts.signing_input, parts.signature)
                &&& refresh_claims_ok(c, e, dpop_jkt)
            }
            _ => false,
        },
        None => false,
    }
}

pub open spec fn refresh_claims_of(raw: Seq<u8>) -> RefreshClaimsV {
    spec_parse_refresh_claims(spec_split_jws(raw)->Some_0.claims)->Some_0
}

/// A refresh token that passed every stateless check. It can only be created by
/// [`check_refresh_token`], so [`authorize_refresh`] can only ever be applied to
/// a verified token.
#[derive(Debug)]
pub struct VerifiedRefresh {
    claims: RefreshClaims,
    now: u64,
}

impl VerifiedRefresh {
    /// Ghost view of the verified claims.
    pub closed spec fn spec_claims(&self) -> RefreshClaimsV {
        self.claims@
    }

    /// The server time at which the token was verified.
    pub closed spec fn spec_now(&self) -> u64 {
        self.now
    }

    /// The verified claims.
    pub fn claims(&self) -> (r: &RefreshClaims)
        ensures r@ == self.spec_claims(),
    {
        &self.claims
    }
}

/// Verifies a refresh token presented with an accepted DPoP proof whose key
/// thumbprint is `dpop_jkt`.
pub fn check_refresh_token(raw: &[u8], e: &RefreshExpect, dpop_jkt: &[u8]) -> (r: Result<VerifiedRefresh, Reject>)
    ensures
        r is Ok <==> refresh_token_ok(raw@, *e, dpop_jkt@),
        r matches Ok(v) ==> v.spec_claims() == refresh_claims_of(raw@) && v.spec_now() == e.now,
{
    let parts = match split_jws(raw) {
        Some(p) => p,
        None => return Err(Reject::JwsMalformed),
    };
    let c = match parse_refresh_claims(parts.claims.as_slice()) {
        Some(c) => c,
        None => return Err(Reject::JwsMalformed),
    };
    let _h = check_issued_jws(&parts, &e.keys, 2)?;
    if !bytes_eq(c.iss.as_slice(), e.issuer.as_slice()) || !bytes_eq(c.aud.as_slice(), e.issuer.as_slice()) {
        return Err(Reject::TokenIssuerMismatch);
    }
    if !bytes_eq(c.client_id.as_slice(), e.client_id.as_slice()) {
        return Err(Reject::TokenClientMismatch);
    }
    if e.now >= c.exp {
        return Err(Reject::TokenExpired);
    }
    if c.iat > e.now && c.iat - e.now > e.max_skew {
        return Err(Reject::TokenIssuedInFuture);
    }
    if c.auth_time > c.iat || (c.exp > c.auth_time && c.exp - c.auth_time > REFRESH_ABSOLUTE_TTL) {
        return Err(Reject::TokenLifetimeInvalid);
    }
    if !bytes_eq(c.jkt.as_slice(), dpop_jkt) {
        return Err(Reject::TokenKeyBindingMismatch);
    }
    Ok(VerifiedRefresh { claims: c, now: e.now })
}

/// Account state read (strongly consistently) for the refresh's `sub` and `cid`.
#[derive(Debug)]
pub struct AccountState {
    /// The account's current session epoch.
    pub epoch: u64,
    /// The registration ID stored for the passkey `cid`, or `None` if that
    /// passkey is no longer registered on the account.
    pub registration: Option<Vec<u8>>,
}

/// Lifetimes of the tokens issued on a successful sign-in or refresh.
#[derive(Debug, Clone, Copy)]
pub struct Lifetimes {
    pub access_exp: u64,
    pub refresh_exp: u64,
}

/// `min(now + REFRESH_IDLE_TTL, auth_time + REFRESH_ABSOLUTE_TTL)`.
pub open spec fn next_refresh_exp(now: u64, auth_time: u64) -> int {
    let idle = now as int + REFRESH_IDLE_TTL as int;
    let abs = auth_time as int + REFRESH_ABSOLUTE_TTL as int;
    if idle <= abs { idle } else { abs }
}

/// Lifetimes for a session started (or refreshed) at `now` whose passkey
/// ceremony happened at `auth_time`. Fails if the session can no longer be
/// extended or on arithmetic overflow.
pub open spec fn lifetimes_ok(now: u64, auth_time: u64) -> bool {
    &&& auth_time <= now
    &&& now as int + REFRESH_IDLE_TTL as int <= u64::MAX as int
    &&& auth_time as int + REFRESH_ABSOLUTE_TTL as int <= u64::MAX as int
    &&& (now as int) < next_refresh_exp(now, auth_time)
}

/// Computes token lifetimes. Proven: the access token lives exactly
/// `ACCESS_TOKEN_TTL`, the refresh token expires after `now` but never later
/// than `auth_time + REFRESH_ABSOLUTE_TTL`, so no chain of refreshes can extend
/// a session past one year.
pub fn lifetimes(now: u64, auth_time: u64) -> (r: Result<Lifetimes, Reject>)
    ensures
        r is Ok <==> lifetimes_ok(now, auth_time),
        r matches Ok(l) ==> l.access_exp as int == now as int + ACCESS_TOKEN_TTL as int
            && l.refresh_exp as int == next_refresh_exp(now, auth_time)
            && (now as int) < l.refresh_exp as int
            && l.refresh_exp as int <= auth_time as int + REFRESH_ABSOLUTE_TTL as int,
{
    if auth_time > now {
        return Err(Reject::TokenIssuedInFuture);
    }
    if now > u64::MAX - REFRESH_IDLE_TTL || auth_time > u64::MAX - REFRESH_ABSOLUTE_TTL {
        return Err(Reject::TimeOverflow);
    }
    let idle = now + REFRESH_IDLE_TTL;
    let abs = auth_time + REFRESH_ABSOLUTE_TTL;
    let refresh_exp = if idle <= abs { idle } else { abs };
    if refresh_exp <= now {
        return Err(Reject::TokenExpired);
    }
    Ok(Lifetimes { access_exp: now + ACCESS_TOKEN_TTL, refresh_exp })
}

/// The stateful refresh rules (protocol §6.2 rules 5–6) plus lifetimes.
pub open spec fn refresh_authorized(c: RefreshClaimsV, s: AccountState, now: u64) -> bool {
    &&& opt_view(s.registration) == Some(c.rid)
    &&& s.epoch == c.epoch
    &&& lifetimes_ok(now, c.auth_time)
}

/// Decides a refresh after the account state was read.
pub fn authorize_refresh(v: &VerifiedRefresh, s: &AccountState) -> (r: Result<Lifetimes, Reject>)
    ensures
        r is Ok <==> refresh_authorized(v.spec_claims(), *s, v.spec_now()),
        r matches Ok(l) ==> l.access_exp as int == v.spec_now() as int + ACCESS_TOKEN_TTL as int
            && l.refresh_exp as int == next_refresh_exp(v.spec_now(), v.spec_claims().auth_time)
            && l.refresh_exp as int <= v.spec_claims().auth_time as int + REFRESH_ABSOLUTE_TTL as int,
{
    match &s.registration {
        Some(stored) => {
            if !bytes_eq(stored.as_slice(), v.claims.rid.as_slice()) {
                return Err(Reject::SessionCredentialRevoked);
            }
        }
        None => return Err(Reject::SessionCredentialRevoked),
    }
    if s.epoch != v.claims.epoch {
        return Err(Reject::SessionEpochMismatch);
    }
    lifetimes(v.now, v.claims.auth_time)
}

// =================================================================== small rules

/// A session is still active iff it carries a session reference, its passkey
/// is still registered with the same registration ID, and the account's epoch
/// is unchanged (protocol §10.7). Used by the account API so revocation takes
/// effect there immediately rather than when access tokens expire.
pub open spec fn session_active(epoch: Option<u64>, rid: Option<Seq<u8>>, s: AccountState) -> bool {
    &&& epoch matches Some(e) && e == s.epoch
    &&& rid is Some
    &&& opt_view(s.registration) == rid
}

pub fn check_session_active(epoch: Option<u64>, rid: &Option<Vec<u8>>, s: &AccountState) -> (r: bool)
    ensures r == session_active(epoch, opt_view(*rid), *s),
{
    let epoch_ok = match epoch {
        Some(e) => e == s.epoch,
        None => false,
    };
    if !epoch_ok {
        return false;
    }
    match (rid, &s.registration) {
        (Some(r), Some(stored)) => bytes_eq(r.as_slice(), stored.as_slice()),
        _ => false,
    }
}

/// Step-up rule (protocol §10.7): the passkey ceremony happened at most
/// `STEP_UP_MAX_AGE` seconds ago (and not in the future).
pub open spec fn step_up_ok(auth_time: u64, now: u64) -> bool {
    auth_time <= now && now as int <= auth_time as int + STEP_UP_MAX_AGE as int
}

pub fn check_step_up(auth_time: u64, now: u64) -> (r: bool)
    ensures r == step_up_ok(auth_time, now),
{
    auth_time <= now && now - auth_time <= STEP_UP_MAX_AGE
}

/// A stored ceremony (challenge) is usable iff its kind matches, the request
/// is signed by the device key the ceremony was bound to at the options step
/// (protocol §8), and it has not expired. DynamoDB deletes expired items
/// lazily, so expiry is always checked.
pub open spec fn ceremony_ok(kind_matches: bool, bound_jkt: Seq<u8>, proof_jkt: Seq<u8>, expires_at: u64, now: u64) -> bool {
    &&& kind_matches
    &&& bound_jkt == proof_jkt
    &&& now < expires_at
}

pub fn check_ceremony(kind_matches: bool, bound_jkt: &[u8], proof_jkt: &[u8], expires_at: u64, now: u64) -> (r: bool)
    ensures r == ceremony_ok(kind_matches, bound_jkt@, proof_jkt@, expires_at, now),
{
    kind_matches && bytes_eq(bound_jkt, proof_jkt) && now < expires_at
}

/// The DPoP nonce windows that are currently valid: the current one and, if it
/// exists, the previous one (protocol §7.2).
pub fn nonce_windows(now: u64) -> (r: (u64, Option<u64>))
    ensures
        r.0 == now / DPOP_NONCE_WINDOW,
        r.1 == if r.0 > 0 { Some((r.0 - 1) as u64) } else { None::<u64> },
{
    let w = now / DPOP_NONCE_WINDOW;
    (w, if w > 0 { Some(w - 1) } else { None })
}

} // verus!
