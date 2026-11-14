//! Trusted parsers for JSON and CBOR wire formats.
//!
//! These functions only *extract facts*; they make no security decisions. For
//! example, the DPoP header parser reports the `typ` it found and whether
//! forbidden members were present, and the verified decision layer decides what
//! to do with that. Structural problems (not JSON, wrong member types, duplicate
//! members, invalid base64url) make a parser return `None`.
//!
//! JSON parsing uses `serde_json` with derived structs, which rejects duplicate
//! members. Unknown members are ignored (forward compatibility), except where
//! their mere presence matters, which is reported explicitly.

use crate::cbor::{self, Value};
use crate::vtypes::{
    AccessClaims, AttObj, AttStmt, CdType, ClientData, DpopClaims, Jwk, JwsHeader, JwsParts,
    RefreshClaims,
};
use serde::{Deserialize, Deserializer};

/// Records whether a member was present at all, whatever its value (including
/// `null`).
#[derive(Debug, Default, Clone, Copy)]
struct Present(bool);

impl<'de> Deserialize<'de> for Present {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(d)?;
        Ok(Present(true))
    }
}

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    crate::b64::decode_str(s)
}

// ------------------------------------------------------------- clientDataJSON

#[derive(Deserialize)]
struct RawClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin", default)]
    top_origin: Present,
}

/// Parses `clientDataJSON` (WebAuthn §5.8.1).
pub fn parse_client_data(raw: &[u8]) -> Option<ClientData> {
    let cd: RawClientData = serde_json::from_slice(raw).ok()?;
    let typ = match cd.typ.as_str() {
        "webauthn.create" => CdType::Create,
        "webauthn.get" => CdType::Get,
        _ => CdType::Other,
    };
    Some(ClientData {
        typ,
        challenge: decode_b64(&cd.challenge)?,
        origin: cd.origin.into_bytes(),
        cross_origin: cd.cross_origin.unwrap_or(false),
        top_origin_present: cd.top_origin.0,
    })
}

// ------------------------------------------------------------- attestationObject

fn classify_att_stmt(fmt: &str, stmt: &Value<'_>) -> AttStmt {
    let Value::Map(entries) = stmt else {
        return AttStmt::Unsupported;
    };
    match fmt {
        "none" if entries.is_empty() => AttStmt::NoneFmt,
        "packed" if entries.len() == 2 => {
            let alg = stmt.map_get_text("alg").and_then(Value::as_i64);
            let sig = match stmt.map_get_text("sig") {
                Some(Value::Bytes(b)) => Some(b.to_vec()),
                _ => None,
            };
            match (alg, sig) {
                (Some(alg), Some(sig)) => AttStmt::PackedSelf { alg, sig },
                _ => AttStmt::Unsupported,
            }
        }
        _ => AttStmt::Unsupported,
    }
}

/// Parses an `attestationObject` (WebAuthn §6.5.4): a CBOR map with exactly the
/// members `fmt`, `attStmt` and `authData`.
pub fn parse_att_obj(raw: &[u8]) -> Option<AttObj> {
    let obj = cbor::decode_exact(raw)?;
    let Value::Map(entries) = &obj else {
        return None;
    };
    if entries.len() != 3 {
        return None;
    }
    let Value::Text(fmt) = obj.map_get_text("fmt")? else {
        return None;
    };
    let stmt = obj.map_get_text("attStmt")?;
    let Value::Bytes(auth_data) = obj.map_get_text("authData")? else {
        return None;
    };
    Some(AttObj {
        stmt: classify_att_stmt(fmt, stmt),
        auth_data: auth_data.to_vec(),
    })
}

// ------------------------------------------------------------- JOSE

/// Positions of the two `.` separators of a compact JWS, if there are exactly
/// two. Allocation-free core checked by Kani.
pub(crate) fn dot_positions(raw: &[u8]) -> Option<(usize, usize)> {
    let mut first = None;
    let mut second = None;
    for (i, b) in raw.iter().enumerate() {
        if *b == b'.' {
            match (first, second) {
                (None, _) => first = Some(i),
                (Some(_), None) => second = Some(i),
                (Some(_), Some(_)) => return None,
            }
        }
    }
    Some((first?, second?))
}

/// Splits a compact JWS into exactly three base64url parts and decodes them.
/// The signing input is the exact received prefix before the second `.`.
pub fn split_jws(raw: &[u8]) -> Option<JwsParts> {
    let (first, second) = dot_positions(raw)?;
    Some(JwsParts {
        header: crate::b64::decode(raw.get(..first)?)?,
        claims: crate::b64::decode(raw.get(first + 1..second)?)?,
        signing_input: raw.get(..second)?.to_vec(),
        signature: crate::b64::decode(raw.get(second + 1..)?)?,
    })
}

#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    d: Present,
    #[serde(default)]
    p: Present,
    #[serde(default)]
    q: Present,
    #[serde(default)]
    dp: Present,
    #[serde(default)]
    dq: Present,
    #[serde(default)]
    qi: Present,
    #[serde(default)]
    oth: Present,
    #[serde(default)]
    k: Present,
}

#[derive(Deserialize)]
struct RawHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    jwk: Option<RawJwk>,
    #[serde(default)]
    jku: Present,
    #[serde(default)]
    x5u: Present,
    #[serde(default)]
    x5c: Present,
    #[serde(default)]
    x5t: Present,
    #[serde(rename = "x5t#S256", default)]
    x5t_s256: Present,
    #[serde(default)]
    crit: Present,
    #[serde(default)]
    b64: Present,
}

fn opt_b64(s: Option<&String>) -> Option<Vec<u8>> {
    match s {
        Some(s) => decode_b64(s),
        None => Some(Vec::new()),
    }
}

/// Parses a JWS protected header (RFC 7515 §4).
pub fn parse_jws_header(json: &[u8]) -> Option<JwsHeader> {
    let h: RawHeader = serde_json::from_slice(json).ok()?;
    let jwk = match &h.jwk {
        Some(j) => Some(Jwk {
            kty: j.kty.clone().into_bytes(),
            crv: j.crv.clone().unwrap_or_default().into_bytes(),
            x: opt_b64(j.x.as_ref())?,
            y: opt_b64(j.y.as_ref())?,
            has_private: [j.d, j.p, j.q, j.dp, j.dq, j.qi, j.oth, j.k]
                .iter()
                .any(|p| p.0),
        }),
        None => None,
    };
    let has_forbidden = [h.jku, h.x5u, h.x5c, h.x5t, h.x5t_s256, h.crit, h.b64]
        .iter()
        .any(|p| p.0);
    Some(JwsHeader {
        alg: h.alg.into_bytes(),
        typ: h.typ.map(String::into_bytes),
        kid: h.kid.map(String::into_bytes),
        jwk,
        has_forbidden,
    })
}

#[derive(Deserialize)]
struct RawDpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    ath: Option<String>,
}

/// Parses DPoP proof claims (RFC 9449 §4.2).
pub fn parse_dpop_claims(json: &[u8]) -> Option<DpopClaims> {
    let c: RawDpopClaims = serde_json::from_slice(json).ok()?;
    let ath = match &c.ath {
        Some(a) => Some(decode_b64(a)?),
        None => None,
    };
    Some(DpopClaims {
        jti: c.jti.into_bytes(),
        htm: c.htm.into_bytes(),
        htu: c.htu.into_bytes(),
        iat: c.iat,
        nonce: c.nonce.map(String::into_bytes),
        ath,
    })
}

#[derive(Deserialize)]
struct RawCnf {
    jkt: String,
}

#[derive(Deserialize)]
struct RawAccessClaims {
    iss: String,
    sub: String,
    aud: String,
    client_id: String,
    iat: u64,
    exp: u64,
    jti: String,
    auth_time: u64,
    cnf: RawCnf,
}

/// Parses access-token claims (protocol §6.1). `aud` must be a single string.
pub fn parse_access_claims(json: &[u8]) -> Option<AccessClaims> {
    let c: RawAccessClaims = serde_json::from_slice(json).ok()?;
    Some(AccessClaims {
        iss: c.iss.into_bytes(),
        sub: c.sub.into_bytes(),
        aud: c.aud.into_bytes(),
        client_id: c.client_id.into_bytes(),
        iat: c.iat,
        exp: c.exp,
        jti: c.jti.into_bytes(),
        auth_time: c.auth_time,
        jkt: decode_b64(&c.cnf.jkt)?,
    })
}

#[derive(Deserialize)]
struct RawRefreshClaims {
    iss: String,
    aud: String,
    sub: String,
    client_id: String,
    iat: u64,
    exp: u64,
    jti: String,
    sid: String,
    auth_time: u64,
    cid: String,
    epoch: u64,
    cnf: RawCnf,
}

/// Parses refresh-token claims (protocol §6.2).
pub fn parse_refresh_claims(json: &[u8]) -> Option<RefreshClaims> {
    let c: RawRefreshClaims = serde_json::from_slice(json).ok()?;
    Some(RefreshClaims {
        iss: c.iss.into_bytes(),
        aud: c.aud.into_bytes(),
        sub: c.sub.into_bytes(),
        client_id: c.client_id.into_bytes(),
        iat: c.iat,
        exp: c.exp,
        jti: c.jti.into_bytes(),
        sid: c.sid.into_bytes(),
        auth_time: c.auth_time,
        cid: decode_b64(&c.cid)?,
        epoch: c.epoch,
        jkt: decode_b64(&c.cnf.jkt)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_data_fields() {
        let cd = parse_client_data(
            br#"{"type":"webauthn.get","challenge":"AAEC","origin":"https://a.example","crossOrigin":false,"other_keys_can_be_added_here":"x"}"#,
        )
        .unwrap();
        assert_eq!(cd.typ, CdType::Get);
        assert_eq!(cd.challenge, vec![0, 1, 2]);
        assert_eq!(cd.origin, b"https://a.example");
        assert!(!cd.cross_origin && !cd.top_origin_present);

        let cd = parse_client_data(
            br#"{"type":"webauthn.create","challenge":"AAEC","origin":"o","topOrigin":null}"#,
        )
        .unwrap();
        assert!(
            cd.top_origin_present,
            "a null topOrigin still counts as present"
        );
    }

    #[test]
    fn client_data_rejects_malformed() {
        for bad in [
            &br#"{"type":"webauthn.get","challenge":"AAE=","origin":"o"}"#[..], // padded
            br#"{"type":"webauthn.get","challenge":"AAEC"}"#,                   // no origin
            br#"{"type":"webauthn.get","type":"webauthn.create","challenge":"AAEC","origin":"o"}"#,
            br#"{"type":"webauthn.get","challenge":"AAEC","origin":"o","crossOrigin":"no"}"#,
            br"[]",
            b"\xff",
        ] {
            assert!(
                parse_client_data(bad).is_none(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn header_reports_forbidden_and_private_members() {
        let h = parse_jws_header(br#"{"alg":"ES256","typ":"dpop+jwt","jwk":{"kty":"EC","crv":"P-256","x":"AA","y":"AQ","d":"AA"},"jku":"https://x"}"#).unwrap();
        assert!(h.has_forbidden);
        assert!(h.jwk.as_ref().unwrap().has_private);
        let h = parse_jws_header(br#"{"alg":"ES256"}"#).unwrap();
        assert!(!h.has_forbidden && h.typ.is_none() && h.jwk.is_none());
    }

    #[test]
    fn numeric_claims_must_be_unsigned_integers() {
        assert!(parse_dpop_claims(br#"{"jti":"a","htm":"GET","htu":"u","iat":1}"#).is_some());
        assert!(parse_dpop_claims(br#"{"jti":"a","htm":"GET","htu":"u","iat":-1}"#).is_none());
        assert!(parse_dpop_claims(br#"{"jti":"a","htm":"GET","htu":"u","iat":1.5}"#).is_none());
        assert!(parse_dpop_claims(br#"{"jti":"a","htm":"GET","htu":"u","iat":"1"}"#).is_none());
    }

    #[test]
    fn access_claims_require_single_audience() {
        let ok = br#"{"iss":"i","sub":"s","aud":"a","client_id":"c","iat":1,"exp":2,"jti":"j","auth_time":1,"cnf":{"jkt":"AA"}}"#;
        assert!(parse_access_claims(ok).is_some());
        let arr = br#"{"iss":"i","sub":"s","aud":["a"],"client_id":"c","iat":1,"exp":2,"jti":"j","auth_time":1,"cnf":{"jkt":"AA"}}"#;
        assert!(parse_access_claims(arr).is_none());
    }
}
