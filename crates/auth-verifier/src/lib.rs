//! Verifies requests made with DPoP-bound access tokens issued by the passkey
//! auth service (protocol §6.1, §7).
//!
//! Every accept/reject decision is made by
//! [`auth_core::decide::check_resource_request`], which is formally verified to
//! accept a request **if and only if**:
//!
//! - the access token is an `at+jwt` signed with `ES256` by a key in the
//!   issuer's JWKS (matched by `kid`), from the expected issuer, for this
//!   audience, unexpired, not issued in the future, with a sane lifetime;
//! - the DPoP proof is a `dpop+jwt` signed by the public key in its own header,
//!   for this exact method and URI, recent, carrying `ath` = SHA-256 of this
//!   access token (and a valid nonce when nonces are required);
//! - the proof key's thumbprint equals the token's `cnf.jkt`.
//!
//! This crate adds the plumbing around that check: header parsing, JWKS
//! loading and caching, DPoP replay tracking, error responses
//! (RFC 9449 §7.1, RFC 9470), and an optional axum extractor.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use auth_verifier::{RequestParts, Verifier, VerifierConfig};
//! let verifier = Verifier::with_static_jwks(
//!     VerifierConfig::new("https://auth.example.com", "https://api.example.com", "https://api.example.com"),
//!     br#"{"keys":[]}"#,
//! )?;
//! let identity = verifier
//!     .verify(&RequestParts {
//!         method: "GET",
//!         path: "/v1/things",
//!         authorization: Some("DPoP eyJ..."),
//!         dpop: Some("eyJ..."),
//!     })
//!     .await?;
//! println!("account {}", identity.subject);
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

mod error;
pub mod jwks;
pub mod policy;

#[cfg(feature = "axum")]
pub mod extract;

use auth_core::b64;
use auth_core::decide::{
    self, AccessExpect, DPOP_MAX_IAT_SKEW_RESOURCE_DEFAULT, DpopExpect, Reject, Stage,
};
use auth_core::vtypes::VerifyKey;
use std::sync::Arc;

pub use error::VerifyError;
pub use policy::{BoxFuture, DpopPolicy, InMemoryReplayCache, NoReplayProtection, PolicyError};

/// Configuration of a verifier.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// The auth service's issuer (`iss`), e.g. `https://auth.example.com`.
    pub issuer: String,
    /// This resource server's audience (`aud`), e.g. `https://api.example.com`.
    pub audience: String,
    /// The public base URL clients use to reach this server, without a trailing
    /// slash. The DPoP `htu` is this value followed by the request path. Taken
    /// from configuration, never from the `Host` header.
    pub resource_base_url: String,
    /// Allowed DPoP `iat` skew in seconds.
    pub dpop_max_skew: u64,
    /// Allowed access-token `iat` skew in seconds.
    pub access_token_max_skew: u64,
    /// Accept `http://localhost` and `http://127.0.0.1` URLs. Local development
    /// only; never enable in a deployed service.
    pub allow_insecure_localhost: bool,
}

impl VerifierConfig {
    /// A configuration with the protocol's default skews.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        resource_base_url: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            resource_base_url: resource_base_url.into(),
            dpop_max_skew: DPOP_MAX_IAT_SKEW_RESOURCE_DEFAULT,
            access_token_max_skew: DPOP_MAX_IAT_SKEW_RESOURCE_DEFAULT,
            allow_insecure_localhost: false,
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (name, url) in [
            ("issuer", &self.issuer),
            ("resource_base_url", &self.resource_base_url),
        ] {
            let local = self.allow_insecure_localhost
                && (url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1"));
            let ok = (url.starts_with("https://") || local)
                && !url.ends_with('/')
                && !url.contains(['?', '#'])
                && url.len() > "https://".len();
            if !ok {
                return Err(ConfigError(format!(
                    "{name} must be an https URL without a trailing slash, query or fragment"
                )));
            }
        }
        if self.audience.is_empty() {
            return Err(ConfigError("audience must not be empty".into()));
        }
        Ok(())
    }
}

/// A configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid verifier configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// The parts of an HTTP request the verifier needs.
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'a> {
    /// Request method, e.g. `GET`.
    pub method: &'a str,
    /// Request path (without query), starting with `/`.
    pub path: &'a str,
    /// The single `Authorization` header value, if any.
    pub authorization: Option<&'a str>,
    /// The single `DPoP` header value, if any.
    pub dpop: Option<&'a str>,
}

impl<'a> RequestParts<'a> {
    /// Extracts the request parts from an [`http::request::Parts`]. More than one
    /// `Authorization` or `DPoP` header is rejected (RFC 9449 §4.3).
    pub fn from_http(parts: &'a http::request::Parts, path: &'a str) -> Result<Self, VerifyError> {
        let single = |name: &str| -> Result<Option<&'a str>, VerifyError> {
            let mut values = parts.headers.get_all(name).iter();
            let first = values.next();
            if values.next().is_some() {
                return Err(if name == "dpop" {
                    VerifyError::InvalidDpopProof { reason: None }
                } else {
                    VerifyError::InvalidToken { reason: None }
                });
            }
            first
                .map(|v| {
                    v.to_str()
                        .map_err(|_| VerifyError::InvalidToken { reason: None })
                })
                .transpose()
        };
        Ok(Self {
            method: parts.method.as_str(),
            path,
            authorization: single("authorization")?,
            dpop: single("dpop")?,
        })
    }
}

/// An authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The account ID (`sub`).
    pub subject: String,
    /// The client the session belongs to (`client_id`).
    pub client_id: String,
    /// When the passkey ceremony that started the session happened.
    pub auth_time: u64,
    /// When the access token expires.
    pub expires_at: u64,
    /// base64url thumbprint of the caller's DPoP key.
    pub key_thumbprint: String,
    /// The session the token belongs to, if the token carries a reference
    /// (tokens from this auth service always do).
    pub session: Option<SessionRef>,
}

/// The session an access token belongs to: the passkey that started it and the
/// account epoch at that time. A resource server that wants revocation to take
/// effect immediately (rather than within the access token lifetime) can check
/// these against the account state, as the auth service's account API does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRef {
    /// base64url credential ID of the passkey that started the session.
    pub credential_id: String,
    /// base64url registration ID of that passkey. A session is only active
    /// while the credential is registered with this registration ID.
    pub registration_id: String,
    /// The account's session epoch when the session started.
    pub epoch: u64,
}

impl Identity {
    /// Step-up rule (protocol §10.7, RFC 9470): the passkey ceremony happened
    /// within the last [`decide::STEP_UP_MAX_AGE`] seconds.
    pub fn require_recent_authentication(&self, now: u64) -> Result<(), VerifyError> {
        if decide::check_step_up(self.auth_time, now) {
            Ok(())
        } else {
            Err(VerifyError::InsufficientUserAuthentication)
        }
    }
}

/// Where verification keys come from.
#[derive(Debug)]
enum KeySource {
    Static(Arc<Vec<VerifyKey>>),
    #[cfg(feature = "fetch")]
    Remote(jwks::RemoteJwks),
}

/// Verifies DPoP-bound access tokens.
#[derive(Debug)]
pub struct Verifier {
    config: VerifierConfig,
    keys: KeySource,
    policy: Arc<dyn DpopPolicy>,
}

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Characters allowed in a `token68` (RFC 9110 §11.2).
fn is_token68(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

/// Extracts the access token from `Authorization: DPoP <token>`. The scheme is
/// case-insensitive (RFC 9110 §11.1). `Bearer` is rejected: DPoP-bound tokens
/// must never be accepted as bearer tokens (RFC 9449 §7.2).
fn access_token(authorization: Option<&str>) -> Result<&str, VerifyError> {
    let value = authorization.ok_or(VerifyError::InvalidToken { reason: None })?;
    let (scheme, rest) = value
        .split_once(' ')
        .ok_or(VerifyError::InvalidToken { reason: None })?;
    let token = rest.trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("DPoP") || !is_token68(token) {
        return Err(VerifyError::InvalidToken { reason: None });
    }
    Ok(token)
}

impl Verifier {
    /// A verifier with a fixed JWKS document (for example loaded from
    /// configuration), without replay protection. Prefer
    /// [`Verifier::with_policy`] with an [`InMemoryReplayCache`] or a shared
    /// store in production.
    pub fn with_static_jwks(config: VerifierConfig, jwks_json: &[u8]) -> Result<Self, ConfigError> {
        config.validate()?;
        let keys = jwks::parse_jwks(jwks_json).map_err(|e| ConfigError(e.to_string()))?;
        Ok(Self {
            config,
            keys: KeySource::Static(Arc::new(keys)),
            policy: Arc::new(NoReplayProtection),
        })
    }

    /// A verifier with fixed verification keys.
    pub fn with_static_keys(
        config: VerifierConfig,
        keys: Vec<VerifyKey>,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            keys: KeySource::Static(Arc::new(keys)),
            policy: Arc::new(NoReplayProtection),
        })
    }

    /// A verifier that fetches and caches the issuer's JWKS from
    /// `<issuer>/.well-known/jwks.json`.
    #[cfg(feature = "fetch")]
    pub fn with_remote_jwks(config: VerifierConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let url = format!("{}/.well-known/jwks.json", config.issuer);
        Ok(Self {
            keys: KeySource::Remote(jwks::RemoteJwks::new(url)?),
            config,
            policy: Arc::new(NoReplayProtection),
        })
    }

    /// Replaces the DPoP nonce and replay policy.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<dyn DpopPolicy>) -> Self {
        self.policy = policy;
        self
    }

    /// The configuration.
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }

    // Only awaits when JWKS fetching is compiled in.
    #[cfg_attr(
        not(feature = "fetch"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn keys(&self) -> Result<Arc<Vec<VerifyKey>>, VerifyError> {
        match &self.keys {
            KeySource::Static(k) => Ok(Arc::clone(k)),
            #[cfg(feature = "fetch")]
            KeySource::Remote(r) => r.keys().await,
        }
    }

    // Only awaits when JWKS fetching is compiled in.
    #[cfg_attr(
        not(feature = "fetch"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    async fn refresh_keys(&self) -> Result<bool, VerifyError> {
        match &self.keys {
            KeySource::Static(_) => Ok(false),
            #[cfg(feature = "fetch")]
            KeySource::Remote(r) => r.refresh_for_unknown_kid().await,
        }
    }

    /// Verifies a request using the current time.
    pub async fn verify(&self, req: &RequestParts<'_>) -> Result<Identity, VerifyError> {
        self.verify_at(req, unix_now()).await
    }

    /// Verifies a request at time `now`.
    pub async fn verify_at(
        &self,
        req: &RequestParts<'_>,
        now: u64,
    ) -> Result<Identity, VerifyError> {
        let token = access_token(req.authorization)?;
        let proof = req
            .dpop
            .ok_or(VerifyError::InvalidDpopProof { reason: None })?;
        if !req.path.starts_with('/') {
            return Err(VerifyError::InvalidDpopProof { reason: None });
        }
        let htu = format!("{}{}", self.config.resource_base_url, req.path);
        let nonces = self
            .policy
            .valid_nonces(now)
            .await
            .map_err(VerifyError::from)?;

        let mut keys = self.keys().await?;
        let mut retried = false;
        let id = loop {
            let a = AccessExpect {
                issuer: self.config.issuer.as_bytes().to_vec(),
                audience: self.config.audience.as_bytes().to_vec(),
                keys: keys.as_ref().clone(),
                now,
                max_skew: self.config.access_token_max_skew,
            };
            let d = DpopExpect {
                htm: req.method.as_bytes().to_vec(),
                htu: htu.as_bytes().to_vec(),
                now,
                max_skew: self.config.dpop_max_skew,
                valid_nonces: nonces.clone(),
                access_token: Some(token.as_bytes().to_vec()),
            };
            match decide::check_resource_request(token.as_bytes(), proof.as_bytes(), &a, &d) {
                Ok(id) => break id,
                Err((Stage::AccessToken, Reject::JwsUnknownKey))
                    if !retried && self.refresh_keys().await? =>
                {
                    retried = true;
                    keys = self.keys().await?;
                }
                Err((stage, reason)) => return Err(self.rejection(stage, reason, now).await),
            }
        };

        let fresh = self
            .policy
            .record_jti(&id.jkt, &id.dpop_jti, now)
            .await
            .map_err(VerifyError::from)?;
        if !fresh {
            return Err(VerifyError::InvalidDpopProof { reason: None });
        }
        let utf8 = |v: Vec<u8>| {
            String::from_utf8(v).map_err(|_| VerifyError::InvalidToken { reason: None })
        };
        Ok(Identity {
            subject: utf8(id.sub)?,
            client_id: utf8(id.client_id)?,
            auth_time: id.auth_time,
            expires_at: id.exp,
            key_thumbprint: b64::encode(&id.jkt),
            session: match (id.cid, id.rid, id.epoch) {
                (Some(cid), Some(rid), Some(epoch)) => Some(SessionRef {
                    credential_id: b64::encode(&cid),
                    registration_id: b64::encode(&rid),
                    epoch,
                }),
                _ => None,
            },
        })
    }

    async fn rejection(&self, stage: Stage, reason: Reject, now: u64) -> VerifyError {
        match (stage, reason) {
            (Stage::Proof, Reject::DpopNonceMissing | Reject::DpopNonceInvalid) => {
                VerifyError::UseDpopNonce {
                    nonce: self.policy.fresh_nonce(now).await.ok().flatten(),
                }
            }
            (Stage::AccessToken, r) => VerifyError::InvalidToken { reason: Some(r) },
            (Stage::Proof | Stage::Binding, r) => VerifyError::InvalidDpopProof { reason: Some(r) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_header_parsing() {
        assert_eq!(
            access_token(Some("DPoP abc.def.ghi")).ok(),
            Some("abc.def.ghi")
        );
        assert_eq!(access_token(Some("dpop abc")).ok(), Some("abc"));
        assert_eq!(access_token(Some("DPoP   abc")).ok(), Some("abc"));
        for bad in [
            "Bearer abc",
            "DPoP",
            "DPoP ",
            "DPoPabc",
            "DPoP a b",
            "DPoP a\"b",
            "Basic abc",
        ] {
            assert!(access_token(Some(bad)).is_err(), "{bad:?}");
        }
        assert!(access_token(None).is_err());
    }

    #[test]
    fn config_validation() {
        let ok = VerifierConfig::new("https://auth.example.com", "aud", "https://api.example.com");
        assert!(ok.validate().is_ok());
        for (iss, base) in [
            ("http://auth.example.com", "https://api.example.com"),
            ("https://auth.example.com/", "https://api.example.com"),
            ("https://auth.example.com", "https://api.example.com?x"),
            ("https://", "https://api.example.com"),
        ] {
            assert!(
                VerifierConfig::new(iss, "aud", base).validate().is_err(),
                "{iss} {base}"
            );
        }
        assert!(
            VerifierConfig::new("https://a.example", "", "https://b.example")
                .validate()
                .is_err()
        );
    }
}
