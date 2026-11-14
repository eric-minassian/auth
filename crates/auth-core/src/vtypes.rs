//! Data types shared by the trusted parsers and the verified decision layer,
//! with their ghost views (the mathematical values the proofs talk about).

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
// Ghost view types only exist for proofs and hold `Seq`s, which have no `Debug`.
#![allow(missing_debug_implementations)]

use vstd::prelude::*;

verus! {

/// Ghost view of an optional byte string.
pub open spec fn opt_view(o: Option<Vec<u8>>) -> Option<Seq<u8>> {
    match o {
        Some(v) => Some(v@),
        None => None,
    }
}

// ---------------------------------------------------------------- WebAuthn

/// `CollectedClientData.type`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CdType {
    /// `"webauthn.create"`
    Create,
    /// `"webauthn.get"`
    Get,
    /// Anything else.
    Other,
}

/// Parsed `clientDataJSON` (WebAuthn §5.8.1).
#[derive(Debug)]
pub struct ClientData {
    /// `type`.
    pub typ: CdType,
    /// `challenge`, base64url-decoded.
    pub challenge: Vec<u8>,
    /// `origin`, as UTF-8 bytes.
    pub origin: Vec<u8>,
    /// `crossOrigin` (absent means false).
    pub cross_origin: bool,
    /// Whether `topOrigin` is present.
    pub top_origin_present: bool,
}

/// Ghost view of [`ClientData`].
pub ghost struct ClientDataV {
    pub typ: CdType,
    pub challenge: Seq<u8>,
    pub origin: Seq<u8>,
    pub cross_origin: bool,
    pub top_origin_present: bool,
}

impl View for ClientData {
    type V = ClientDataV;

    open spec fn view(&self) -> ClientDataV {
        ClientDataV {
            typ: self.typ,
            challenge: self.challenge@,
            origin: self.origin@,
            cross_origin: self.cross_origin,
            top_origin_present: self.top_origin_present,
        }
    }
}

/// The attestation statement of a registration response, classified.
#[derive(Debug)]
pub enum AttStmt {
    /// `fmt = "none"` with an empty `attStmt`.
    NoneFmt,
    /// `fmt = "packed"` self attestation: `attStmt = {alg, sig}` without `x5c`.
    PackedSelf { alg: i64, sig: Vec<u8> },
    /// Any other format or statement shape.
    Unsupported,
}

/// Ghost view of [`AttStmt`].
pub ghost enum AttStmtV {
    NoneFmt,
    PackedSelf { alg: i64, sig: Seq<u8> },
    Unsupported,
}

impl View for AttStmt {
    type V = AttStmtV;

    open spec fn view(&self) -> AttStmtV {
        match self {
            AttStmt::NoneFmt => AttStmtV::NoneFmt,
            AttStmt::PackedSelf { alg, sig } => AttStmtV::PackedSelf { alg: *alg, sig: sig@ },
            AttStmt::Unsupported => AttStmtV::Unsupported,
        }
    }
}

/// Parsed `attestationObject` (WebAuthn §6.5.4).
#[derive(Debug)]
pub struct AttObj {
    /// Classified attestation statement.
    pub stmt: AttStmt,
    /// Raw authenticator data.
    pub auth_data: Vec<u8>,
}

/// Ghost view of [`AttObj`].
pub ghost struct AttObjV {
    pub stmt: AttStmtV,
    pub auth_data: Seq<u8>,
}

impl View for AttObj {
    type V = AttObjV;

    open spec fn view(&self) -> AttObjV {
        AttObjV { stmt: self.stmt@, auth_data: self.auth_data@ }
    }
}

// --------------------------------------------------------------------- JOSE

/// A public JWK as it appears in a DPoP proof header.
#[derive(Debug)]
pub struct Jwk {
    /// `kty`.
    pub kty: Vec<u8>,
    /// `crv`.
    pub crv: Vec<u8>,
    /// `x`, base64url-decoded.
    pub x: Vec<u8>,
    /// `y`, base64url-decoded.
    pub y: Vec<u8>,
    /// Whether any private-key member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) is present.
    pub has_private: bool,
}

/// Ghost view of [`Jwk`].
pub ghost struct JwkV {
    pub kty: Seq<u8>,
    pub crv: Seq<u8>,
    pub x: Seq<u8>,
    pub y: Seq<u8>,
    pub has_private: bool,
}

impl View for Jwk {
    type V = JwkV;

    open spec fn view(&self) -> JwkV {
        JwkV { kty: self.kty@, crv: self.crv@, x: self.x@, y: self.y@, has_private: self.has_private }
    }
}

/// A JWS protected header.
#[derive(Debug)]
pub struct JwsHeader {
    /// `alg`.
    pub alg: Vec<u8>,
    /// `typ`.
    pub typ: Option<Vec<u8>>,
    /// `kid`.
    pub kid: Option<Vec<u8>>,
    /// `jwk`.
    pub jwk: Option<Jwk>,
    /// Whether `jku`, `x5u`, `x5c`, `x5t`, `x5t#S256` or `crit` is present.
    pub has_forbidden: bool,
}

/// Ghost view of [`JwsHeader`].
pub ghost struct JwsHeaderV {
    pub alg: Seq<u8>,
    pub typ: Option<Seq<u8>>,
    pub kid: Option<Seq<u8>>,
    pub jwk: Option<JwkV>,
    pub has_forbidden: bool,
}

impl View for JwsHeader {
    type V = JwsHeaderV;

    open spec fn view(&self) -> JwsHeaderV {
        JwsHeaderV {
            alg: self.alg@,
            typ: opt_view(self.typ),
            kid: opt_view(self.kid),
            jwk: match self.jwk {
                Some(j) => Some(j@),
                None => None,
            },
            has_forbidden: self.has_forbidden,
        }
    }
}

/// Claims of a DPoP proof (RFC 9449 §4.2).
#[derive(Debug)]
pub struct DpopClaims {
    /// `jti`.
    pub jti: Vec<u8>,
    /// `htm`.
    pub htm: Vec<u8>,
    /// `htu`.
    pub htu: Vec<u8>,
    /// `iat`.
    pub iat: u64,
    /// `nonce`.
    pub nonce: Option<Vec<u8>>,
    /// `ath`, base64url-decoded.
    pub ath: Option<Vec<u8>>,
}

/// Ghost view of [`DpopClaims`].
pub ghost struct DpopClaimsV {
    pub jti: Seq<u8>,
    pub htm: Seq<u8>,
    pub htu: Seq<u8>,
    pub iat: u64,
    pub nonce: Option<Seq<u8>>,
    pub ath: Option<Seq<u8>>,
}

impl View for DpopClaims {
    type V = DpopClaimsV;

    open spec fn view(&self) -> DpopClaimsV {
        DpopClaimsV {
            jti: self.jti@,
            htm: self.htm@,
            htu: self.htu@,
            iat: self.iat,
            nonce: opt_view(self.nonce),
            ath: opt_view(self.ath),
        }
    }
}

/// Claims of an access token (protocol §6.1) that verifiers check.
#[derive(Debug)]
pub struct AccessClaims {
    pub iss: Vec<u8>,
    pub sub: Vec<u8>,
    pub aud: Vec<u8>,
    pub client_id: Vec<u8>,
    pub iat: u64,
    pub exp: u64,
    pub jti: Vec<u8>,
    pub auth_time: u64,
    /// `cnf.jkt`, base64url-decoded.
    pub jkt: Vec<u8>,
    /// `cid`, base64url-decoded: the passkey that started the session.
    pub cid: Option<Vec<u8>>,
    /// `epoch`: the account's session epoch when the session started.
    pub epoch: Option<u64>,
}

/// Ghost view of [`AccessClaims`].
pub ghost struct AccessClaimsV {
    pub iss: Seq<u8>,
    pub sub: Seq<u8>,
    pub aud: Seq<u8>,
    pub client_id: Seq<u8>,
    pub iat: u64,
    pub exp: u64,
    pub jti: Seq<u8>,
    pub auth_time: u64,
    pub jkt: Seq<u8>,
    pub cid: Option<Seq<u8>>,
    pub epoch: Option<u64>,
}

impl View for AccessClaims {
    type V = AccessClaimsV;

    open spec fn view(&self) -> AccessClaimsV {
        AccessClaimsV {
            iss: self.iss@,
            sub: self.sub@,
            aud: self.aud@,
            client_id: self.client_id@,
            iat: self.iat,
            exp: self.exp,
            jti: self.jti@,
            auth_time: self.auth_time,
            jkt: self.jkt@,
            cid: opt_view(self.cid),
            epoch: self.epoch,
        }
    }
}

/// Claims of a refresh token (protocol §6.2).
#[derive(Debug)]
pub struct RefreshClaims {
    pub iss: Vec<u8>,
    pub aud: Vec<u8>,
    pub sub: Vec<u8>,
    pub client_id: Vec<u8>,
    pub iat: u64,
    pub exp: u64,
    pub jti: Vec<u8>,
    pub sid: Vec<u8>,
    pub auth_time: u64,
    /// `cid`, base64url-decoded credential ID.
    pub cid: Vec<u8>,
    pub epoch: u64,
    /// `cnf.jkt`, base64url-decoded.
    pub jkt: Vec<u8>,
}

/// Ghost view of [`RefreshClaims`].
pub ghost struct RefreshClaimsV {
    pub iss: Seq<u8>,
    pub aud: Seq<u8>,
    pub sub: Seq<u8>,
    pub client_id: Seq<u8>,
    pub iat: u64,
    pub exp: u64,
    pub jti: Seq<u8>,
    pub sid: Seq<u8>,
    pub auth_time: u64,
    pub cid: Seq<u8>,
    pub epoch: u64,
    pub jkt: Seq<u8>,
}

impl View for RefreshClaims {
    type V = RefreshClaimsV;

    open spec fn view(&self) -> RefreshClaimsV {
        RefreshClaimsV {
            iss: self.iss@,
            aud: self.aud@,
            sub: self.sub@,
            client_id: self.client_id@,
            iat: self.iat,
            exp: self.exp,
            jti: self.jti@,
            sid: self.sid@,
            auth_time: self.auth_time,
            cid: self.cid@,
            epoch: self.epoch,
            jkt: self.jkt@,
        }
    }
}

/// A compact JWS split into its parts (RFC 7515 §7.1).
#[derive(Debug)]
pub struct JwsParts {
    /// Decoded protected header (JSON bytes).
    pub header: Vec<u8>,
    /// Decoded payload (JSON bytes).
    pub claims: Vec<u8>,
    /// `BASE64URL(header) || '.' || BASE64URL(payload)`, exactly as received.
    pub signing_input: Vec<u8>,
    /// Decoded signature.
    pub signature: Vec<u8>,
}

/// Ghost view of [`JwsParts`].
pub ghost struct JwsPartsV {
    pub header: Seq<u8>,
    pub claims: Seq<u8>,
    pub signing_input: Seq<u8>,
    pub signature: Seq<u8>,
}

impl View for JwsParts {
    type V = JwsPartsV;

    open spec fn view(&self) -> JwsPartsV {
        JwsPartsV {
            header: self.header@,
            claims: self.claims@,
            signing_input: self.signing_input@,
            signature: self.signature@,
        }
    }
}

/// A P-256 verification key with its `kid`.
#[derive(Debug, Clone)]
pub struct VerifyKey {
    pub kid: Vec<u8>,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// Ghost view of [`VerifyKey`].
pub ghost struct VerifyKeyV {
    pub kid: Seq<u8>,
    pub x: Seq<u8>,
    pub y: Seq<u8>,
}

impl View for VerifyKey {
    type V = VerifyKeyV;

    open spec fn view(&self) -> VerifyKeyV {
        VerifyKeyV { kid: self.kid@, x: self.x@, y: self.y@ }
    }
}

} // verus!
