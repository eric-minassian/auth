//! The trusted boundary of the verified core.
//!
//! Each function here wraps a parser or cryptographic primitive implemented in
//! ordinary Rust (`wire`, `cose`, `cbor`, `b64`, `crypto`). Verus does not look
//! inside them (`external_body`); instead each one states a contract in terms
//! of an *uninterpreted* specification function. "Uninterpreted" means the
//! proofs assume nothing about the function except that it is a function: the
//! same input always gives the same output, and the explicitly stated bounds
//! hold.
//!
//! What this buys: the decision layer is proven to call these primitives on
//! exactly the right bytes and to act on every result correctly. What it does
//! not prove: that the primitives themselves are correct. Those are covered by
//! AWS-LC (cryptography), Kani harnesses for the parsers' stated bounds and
//! panic freedom, unit and property tests, and fuzzing. See
//! `docs/verification.md` for the full trusted computing base.

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

use crate::vtypes::*;
use vstd::prelude::*;

verus! {

// ------------------------------------------------------------- crypto

/// SHA-256.
pub uninterp spec fn spec_sha256(m: Seq<u8>) -> Seq<u8>;

/// `true` iff `sig` is a valid WebAuthn signature over `msg` under the stored
/// COSE_Key `cose`.
pub uninterp spec fn spec_verify_cose(cose: Seq<u8>, msg: Seq<u8>, sig: Seq<u8>) -> bool;

/// `true` iff `sig` is a valid JWS ES256 signature (fixed `r || s`) over
/// `input` under the P-256 key `(x, y)`.
pub uninterp spec fn spec_verify_es256(x: Seq<u8>, y: Seq<u8>, input: Seq<u8>, sig: Seq<u8>) -> bool;

/// RFC 7638 thumbprint of the P-256 key `(x, y)`.
pub uninterp spec fn spec_jkt(x: Seq<u8>, y: Seq<u8>) -> Seq<u8>;

#[verifier::external_body]
pub fn sha256(m: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == spec_sha256(m@),
        r@.len() == 32,
{
    crate::crypto::sha256(m).to_vec()
}

#[verifier::external_body]
pub fn verify_cose(cose: &[u8], msg: &[u8], sig: &[u8]) -> (r: bool)
    ensures
        r == spec_verify_cose(cose@, msg@, sig@),
{
    crate::crypto::verify_cose(cose, msg, sig)
}

#[verifier::external_body]
pub fn verify_es256(x: &[u8], y: &[u8], input: &[u8], sig: &[u8]) -> (r: bool)
    ensures
        r == spec_verify_es256(x@, y@, input@, sig@),
{
    crate::crypto::verify_es256_jws(x, y, input, sig)
}

#[verifier::external_body]
pub fn jkt(x: &[u8], y: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == spec_jkt(x@, y@),
{
    crate::crypto::jwk_thumbprint_p256(x, y).to_vec()
}

// ------------------------------------------------------------- encodings

/// Strict base64url decoding (`None` for non-canonical input).
pub uninterp spec fn spec_b64_decode(s: Seq<u8>) -> Option<Seq<u8>>;

#[verifier::external_body]
pub fn b64_decode(s: &[u8]) -> (r: Option<Vec<u8>>)
    ensures
        opt_view(r) == spec_b64_decode(s@),
{
    crate::b64::decode(s)
}

// ------------------------------------------------------------- WebAuthn parsers

/// `clientDataJSON` → [`ClientDataV`].
pub uninterp spec fn spec_parse_client_data(raw: Seq<u8>) -> Option<ClientDataV>;

#[verifier::external_body]
pub fn parse_client_data(raw: &[u8]) -> (r: Option<ClientData>)
    ensures
        r is Some <==> spec_parse_client_data(raw@) is Some,
        r matches Some(cd) ==> spec_parse_client_data(raw@) == Some(cd@),
{
    crate::wire::parse_client_data(raw)
}

/// `attestationObject` → [`AttObjV`].
pub uninterp spec fn spec_parse_att_obj(raw: Seq<u8>) -> Option<AttObjV>;

#[verifier::external_body]
pub fn parse_att_obj(raw: &[u8]) -> (r: Option<AttObj>)
    ensures
        r is Some <==> spec_parse_att_obj(raw@) is Some,
        r matches Some(a) ==> spec_parse_att_obj(raw@) == Some(a@),
{
    crate::wire::parse_att_obj(raw)
}

/// COSE_Key at the start of `b`: its algorithm and encoded length.
pub uninterp spec fn spec_cose_prefix(b: Seq<u8>) -> Option<(i64, nat)>;

/// Contract checked by Kani (`cose_prefix_within_bounds`): a reported length is
/// non-zero and never exceeds the input.
#[verifier::external_body]
pub fn cose_prefix(b: &[u8]) -> (r: Option<(i64, usize)>)
    ensures
        r is Some <==> spec_cose_prefix(b@) is Some,
        r matches Some((alg, n)) ==> spec_cose_prefix(b@) == Some((alg, n as nat)) && 0 < n <= b@.len(),
{
    crate::cose::parse_prefix(b).map(|(k, n)| (k.alg(), n))
}

/// `true` iff `b` is exactly one CBOR map.
pub uninterp spec fn spec_cbor_single_map(b: Seq<u8>) -> bool;

#[verifier::external_body]
pub fn cbor_single_map(b: &[u8]) -> (r: bool)
    ensures
        r == spec_cbor_single_map(b@),
{
    crate::cbor::is_single_map(b)
}

// ------------------------------------------------------------- JOSE parsers

/// Compact JWS → its decoded parts.
pub uninterp spec fn spec_split_jws(raw: Seq<u8>) -> Option<JwsPartsV>;

/// Contract checked by Kani (`split_jws_signing_input`): the signing input is
/// the exact prefix of `raw` before the second of exactly two `.` separators.
#[verifier::external_body]
pub fn split_jws(raw: &[u8]) -> (r: Option<JwsParts>)
    ensures
        r is Some <==> spec_split_jws(raw@) is Some,
        r matches Some(p) ==> spec_split_jws(raw@) == Some(p@),
{
    crate::wire::split_jws(raw)
}

/// JWS protected header JSON → [`JwsHeaderV`].
pub uninterp spec fn spec_parse_jws_header(json: Seq<u8>) -> Option<JwsHeaderV>;

#[verifier::external_body]
pub fn parse_jws_header(json: &[u8]) -> (r: Option<JwsHeader>)
    ensures
        r is Some <==> spec_parse_jws_header(json@) is Some,
        r matches Some(h) ==> spec_parse_jws_header(json@) == Some(h@),
{
    crate::wire::parse_jws_header(json)
}

/// DPoP claims JSON → [`DpopClaimsV`].
pub uninterp spec fn spec_parse_dpop_claims(json: Seq<u8>) -> Option<DpopClaimsV>;

#[verifier::external_body]
pub fn parse_dpop_claims(json: &[u8]) -> (r: Option<DpopClaims>)
    ensures
        r is Some <==> spec_parse_dpop_claims(json@) is Some,
        r matches Some(c) ==> spec_parse_dpop_claims(json@) == Some(c@),
{
    crate::wire::parse_dpop_claims(json)
}

/// Access-token claims JSON → [`AccessClaimsV`].
pub uninterp spec fn spec_parse_access_claims(json: Seq<u8>) -> Option<AccessClaimsV>;

#[verifier::external_body]
pub fn parse_access_claims(json: &[u8]) -> (r: Option<AccessClaims>)
    ensures
        r is Some <==> spec_parse_access_claims(json@) is Some,
        r matches Some(c) ==> spec_parse_access_claims(json@) == Some(c@),
{
    crate::wire::parse_access_claims(json)
}

/// Refresh-token claims JSON → [`RefreshClaimsV`].
pub uninterp spec fn spec_parse_refresh_claims(json: Seq<u8>) -> Option<RefreshClaimsV>;

#[verifier::external_body]
pub fn parse_refresh_claims(json: &[u8]) -> (r: Option<RefreshClaims>)
    ensures
        r is Some <==> spec_parse_refresh_claims(json@) is Some,
        r matches Some(c) ==> spec_parse_refresh_claims(json@) == Some(c@),
{
    crate::wire::parse_refresh_claims(json)
}

} // verus!
