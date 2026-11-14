//! Test support: a software passkey authenticator, a DPoP client key and a
//! local token signer. Compiled only for tests or with the `test-support`
//! feature; never part of a production build.
#![allow(
    clippy::missing_panics_doc,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]

use crate::b64;
use crate::cbor::encode::Item;
use crate::cose::{self, PublicKey};
use crate::decide::{FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV};
use crate::jose;
use crate::vtypes::VerifyKey;
use crate::webauthn::{
    AssertionResponseJson, AttestationResponseJson, AuthenticationResponseJson,
    RegistrationResponseJson,
};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
};
use serde::Serialize;

/// Random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    SystemRandom::new().fill(&mut v).expect("rng");
    v
}

/// Passkey algorithm for the software authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// COSE -7.
    Es256,
    /// COSE -8.
    Ed25519,
    /// COSE -257.
    Rs256,
}

enum Key {
    Es256(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rs256(RsaKeyPair),
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// Everything that goes into `clientDataJSON`. Tests mutate fields to build
/// invalid responses.
#[derive(Debug, Clone)]
pub struct ClientDataSpec {
    /// `type`.
    pub typ: String,
    /// Challenge bytes.
    pub challenge: Vec<u8>,
    /// `origin`.
    pub origin: String,
    /// `crossOrigin`.
    pub cross_origin: Option<bool>,
    /// `topOrigin`.
    pub top_origin: Option<String>,
}

impl ClientDataSpec {
    /// Serializes the client data like a browser does.
    pub fn to_json(&self) -> Vec<u8> {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), self.typ.clone().into());
        m.insert("challenge".into(), b64::encode(&self.challenge).into());
        m.insert("origin".into(), self.origin.clone().into());
        if let Some(c) = self.cross_origin {
            m.insert("crossOrigin".into(), c.into());
        }
        if let Some(t) = &self.top_origin {
            m.insert("topOrigin".into(), t.clone().into());
        }
        serde_json::to_vec(&m).expect("json")
    }
}

/// Knobs for one ceremony.
#[derive(Debug, Clone)]
pub struct Ceremony {
    /// Client data.
    pub client_data: ClientDataSpec,
    /// RP ID whose hash goes into the authenticator data.
    pub rp_id: String,
    /// Authenticator data flags.
    pub flags: u8,
    /// Extension bytes appended when `FLAG_ED` is set.
    pub extensions: Vec<u8>,
    /// Attestation statement format for registration.
    pub attestation: AttestationKind,
    /// Override the signature counter (otherwise the authenticator's counter).
    pub sign_count: Option<u32>,
}

/// Which attestation statement to produce at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationKind {
    /// `fmt: "none"`, empty statement.
    None,
    /// `fmt: "packed"` self attestation.
    PackedSelf,
    /// `fmt: "packed"` self attestation with a wrong `alg`.
    PackedWrongAlg,
    /// `fmt: "fido-u2f"` (unsupported).
    FidoU2f,
}

/// A software passkey authenticator holding one discoverable credential.
#[derive(Debug)]
pub struct SoftAuthenticator {
    key: Key,
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// User handle stored with the credential (set at registration).
    pub user_handle: Vec<u8>,
    /// Signature counter; `None` behaves like synced passkeys (always 0).
    pub counter: Option<u32>,
    /// Whether the credential is backup eligible (synced passkey).
    pub backup_eligible: bool,
}

impl SoftAuthenticator {
    /// A new synced (backup-eligible, counter-less) ES256 passkey.
    pub fn new() -> Self {
        Self::with_alg(Alg::Es256)
    }

    /// A new synced passkey with the given algorithm.
    pub fn with_alg(alg: Alg) -> Self {
        let rng = SystemRandom::new();
        let key = match alg {
            Alg::Es256 => {
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .expect("keygen");
                Key::Es256(
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
                        .expect("key"),
                )
            }
            Alg::Ed25519 => {
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
                Key::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key"))
            }
            Alg::Rs256 => Key::Rs256(RsaKeyPair::generate(KeySize::Rsa2048).expect("keygen")),
        };
        Self {
            key,
            credential_id: random_bytes(16),
            user_handle: Vec::new(),
            counter: None,
            backup_eligible: true,
        }
    }

    /// The credential public key.
    pub fn public_key(&self) -> PublicKey {
        match &self.key {
            Key::Es256(k) => {
                let p = k.public_key().as_ref();
                PublicKey::Es256 {
                    x: p[1..33].try_into().expect("x"),
                    y: p[33..65].try_into().expect("y"),
                }
            }
            Key::Ed25519(k) => PublicKey::Ed25519 {
                x: k.public_key().as_ref().try_into().expect("ed25519"),
            },
            Key::Rs256(k) => PublicKey::Rs256 {
                n: k.public_key()
                    .modulus()
                    .big_endian_without_leading_zero()
                    .to_vec(),
                e: k.public_key()
                    .exponent()
                    .big_endian_without_leading_zero()
                    .to_vec(),
            },
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.key {
            Key::Es256(k) => k.sign(&rng, msg).expect("sign").as_ref().to_vec(),
            Key::Ed25519(k) => k.sign(msg).as_ref().to_vec(),
            Key::Rs256(k) => {
                let mut sig = vec![0u8; k.public_modulus_len()];
                k.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig)
                    .expect("sign");
                sig
            }
        }
    }

    fn default_flags(&self, attested: bool) -> u8 {
        let mut f = FLAG_UP | FLAG_UV;
        if self.backup_eligible {
            f |= FLAG_BE | FLAG_BS;
        }
        if attested {
            f |= FLAG_AT;
        }
        f
    }

    /// A ceremony description with correct defaults.
    pub fn ceremony(&self, typ: &str, rp_id: &str, origin: &str, challenge: &[u8]) -> Ceremony {
        Ceremony {
            client_data: ClientDataSpec {
                typ: typ.into(),
                challenge: challenge.to_vec(),
                origin: origin.into(),
                cross_origin: Some(false),
                top_origin: None,
            },
            rp_id: rp_id.into(),
            flags: self.default_flags(typ == "webauthn.create"),
            extensions: Vec::new(),
            attestation: AttestationKind::None,
            sign_count: None,
        }
    }

    fn next_count(&mut self, c: &Ceremony) -> u32 {
        if let Some(n) = c.sign_count {
            return n;
        }
        match &mut self.counter {
            Some(n) => {
                *n += 1;
                *n
            }
            None => 0,
        }
    }

    fn auth_data(&mut self, c: &Ceremony, attested: Option<&[u8]>) -> Vec<u8> {
        let mut ad = crate::crypto::sha256(c.rp_id.as_bytes()).to_vec();
        ad.push(c.flags);
        ad.extend_from_slice(&self.next_count(c).to_be_bytes());
        if let Some(cose_key) = attested {
            ad.extend_from_slice(&[0u8; 16]); // AAGUID
            ad.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .expect("len")
                    .to_be_bytes(),
            );
            ad.extend_from_slice(&self.credential_id);
            ad.extend_from_slice(cose_key);
        }
        if c.flags & FLAG_ED != 0 || !c.extensions.is_empty() {
            ad.extend_from_slice(&c.extensions);
        }
        ad
    }

    /// Performs `navigator.credentials.create` for `user_id`.
    pub fn register_with(&mut self, c: &Ceremony, user_id: &[u8]) -> RegistrationResponseJson {
        self.user_handle = user_id.to_vec();
        let cdj = c.client_data.to_json();
        let cose_key = cose::encode(&self.public_key());
        let ad = self.auth_data(c, Some(&cose_key));
        let mut msg = ad.clone();
        msg.extend_from_slice(&crate::crypto::sha256(&cdj));
        let alg = self.public_key().alg();
        let (fmt, stmt) = match c.attestation {
            AttestationKind::None => ("none", Item::Map(vec![])),
            AttestationKind::PackedSelf => (
                "packed",
                Item::Map(vec![
                    (Item::Text("alg".into()), Item::Int(alg)),
                    (Item::Text("sig".into()), Item::Bytes(self.sign(&msg))),
                ]),
            ),
            AttestationKind::PackedWrongAlg => (
                "packed",
                Item::Map(vec![
                    (
                        Item::Text("alg".into()),
                        Item::Int(if alg == -7 { -8 } else { -7 }),
                    ),
                    (Item::Text("sig".into()), Item::Bytes(self.sign(&msg))),
                ]),
            ),
            AttestationKind::FidoU2f => (
                "fido-u2f",
                Item::Map(vec![
                    (Item::Text("sig".into()), Item::Bytes(self.sign(&msg))),
                    (
                        Item::Text("x5c".into()),
                        Item::Array(vec![Item::Bytes(vec![0x30])]),
                    ),
                ]),
            ),
        };
        let att = Item::Map(vec![
            (Item::Text("fmt".into()), Item::Text(fmt.into())),
            (Item::Text("attStmt".into()), stmt),
            (Item::Text("authData".into()), Item::Bytes(ad)),
        ])
        .to_vec();
        let id = b64::encode(&self.credential_id);
        RegistrationResponseJson {
            id: id.clone(),
            raw_id: id,
            typ: "public-key".into(),
            response: AttestationResponseJson {
                client_data_json: b64::encode(&cdj),
                attestation_object: b64::encode(&att),
                transports: vec!["internal".into(), "hybrid".into()],
            },
        }
    }

    /// Registers with correct defaults.
    pub fn register(
        &mut self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
        user_id: &[u8],
    ) -> RegistrationResponseJson {
        let c = self.ceremony("webauthn.create", rp_id, origin, challenge);
        self.register_with(&c, user_id)
    }

    /// Performs `navigator.credentials.get`.
    pub fn authenticate_with(&mut self, c: &Ceremony) -> AuthenticationResponseJson {
        let cdj = c.client_data.to_json();
        let ad = self.auth_data(c, None);
        let mut msg = ad.clone();
        msg.extend_from_slice(&crate::crypto::sha256(&cdj));
        let sig = self.sign(&msg);
        let id = b64::encode(&self.credential_id);
        AuthenticationResponseJson {
            id: id.clone(),
            raw_id: id,
            typ: "public-key".into(),
            response: AssertionResponseJson {
                client_data_json: b64::encode(&cdj),
                authenticator_data: b64::encode(&ad),
                signature: b64::encode(&sig),
                user_handle: Some(b64::encode(&self.user_handle)),
            },
        }
    }

    /// Authenticates with correct defaults.
    pub fn authenticate(
        &mut self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
    ) -> AuthenticationResponseJson {
        let c = self.ceremony("webauthn.get", rp_id, origin, challenge);
        self.authenticate_with(&c)
    }
}

impl Default for SoftAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

/// A DPoP client key (what the SDK keeps as a non-extractable WebCrypto key).
#[derive(Debug)]
pub struct DpopKey {
    kp: EcdsaKeyPair,
    /// X coordinate.
    pub x: [u8; 32],
    /// Y coordinate.
    pub y: [u8; 32],
}

/// Inputs of one DPoP proof.
#[derive(Debug, Clone, Default)]
pub struct ProofParams {
    /// `htm`.
    pub htm: String,
    /// `htu`.
    pub htu: String,
    /// `iat`.
    pub iat: u64,
    /// `jti` (random if `None`).
    pub jti: Option<String>,
    /// `nonce`.
    pub nonce: Option<String>,
    /// Access token whose hash goes into `ath`.
    pub access_token: Option<String>,
}

impl DpopKey {
    /// Generates a new key.
    pub fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("keygen");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("key");
        let p = kp.public_key().as_ref();
        let x = p[1..33].try_into().expect("x");
        let y = p[33..65].try_into().expect("y");
        Self { kp, x, y }
    }

    /// RFC 7638 thumbprint, base64url.
    pub fn jkt(&self) -> String {
        jose::kid_for(&self.x, &self.y)
    }

    /// The public JWK as a JSON value.
    pub fn jwk(&self) -> serde_json::Value {
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": b64::encode(&self.x), "y": b64::encode(&self.y)})
    }

    /// Signs arbitrary header and claims JSON (for negative tests).
    pub fn sign_raw(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let si = format!(
            "{}.{}",
            b64::encode(&serde_json::to_vec(header).expect("json")),
            b64::encode(&serde_json::to_vec(claims).expect("json"))
        );
        let sig = self
            .kp
            .sign(&SystemRandom::new(), si.as_bytes())
            .expect("sign");
        format!("{si}.{}", b64::encode(sig.as_ref()))
    }

    /// The standard proof header.
    pub fn header(&self) -> serde_json::Value {
        serde_json::json!({"typ": jose::TYP_DPOP, "alg": jose::ALG, "jwk": self.jwk()})
    }

    /// The standard proof claims.
    pub fn claims(&self, p: &ProofParams) -> serde_json::Value {
        let mut c = serde_json::json!({
            "jti": p.jti.clone().unwrap_or_else(|| b64::encode(&random_bytes(16))),
            "htm": p.htm,
            "htu": p.htu,
            "iat": p.iat,
        });
        if let Some(n) = &p.nonce {
            c["nonce"] = n.clone().into();
        }
        if let Some(t) = &p.access_token {
            c["ath"] = b64::encode(&crate::crypto::sha256(t.as_bytes())).into();
        }
        c
    }

    /// A correct proof.
    pub fn proof(&self, p: &ProofParams) -> String {
        self.sign_raw(&self.header(), &self.claims(p))
    }
}

/// An in-process ES256 token signer standing in for KMS.
#[derive(Debug)]
pub struct LocalSigner {
    kp: EcdsaKeyPair,
    /// X coordinate.
    pub x: [u8; 32],
    /// Y coordinate.
    pub y: [u8; 32],
}

impl LocalSigner {
    /// Generates a new signing key.
    pub fn generate() -> Self {
        let k = DpopKey::generate();
        Self {
            kp: k.kp,
            x: k.x,
            y: k.y,
        }
    }

    /// The verification key with its `kid`.
    pub fn verify_key(&self) -> VerifyKey {
        jose::verify_key(&self.x, &self.y)
    }

    /// The `kid`.
    pub fn kid(&self) -> String {
        jose::kid_for(&self.x, &self.y)
    }

    /// Signs claims as a JWT of type `typ`.
    pub fn sign<C: Serialize>(&self, typ: &str, claims: &C) -> String {
        let si = jose::signing_input(typ, &self.kid(), claims).expect("json");
        let sig = self
            .kp
            .sign(&SystemRandom::new(), si.as_bytes())
            .expect("sign");
        let fixed: [u8; 64] = sig.as_ref().try_into().expect("fixed");
        jose::compact(&si, &fixed)
    }

    /// Signs arbitrary header/claims JSON (for negative tests).
    pub fn sign_raw(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let si = format!(
            "{}.{}",
            b64::encode(&serde_json::to_vec(header).expect("json")),
            b64::encode(&serde_json::to_vec(claims).expect("json"))
        );
        let sig = self
            .kp
            .sign(&SystemRandom::new(), si.as_bytes())
            .expect("sign");
        format!("{si}.{}", b64::encode(sig.as_ref()))
    }
}
