//! JWK Set (RFC 7517) loading.
//!
//! Only `EC` / `P-256` keys usable for `ES256` signatures are kept. A key is
//! accepted only if its point is valid and its `kid` equals its RFC 7638
//! thumbprint, which is how the auth service names its keys; this rules out
//! `kid` confusion between keys.

use auth_core::cose::PublicKey;
use auth_core::vtypes::VerifyKey;
use auth_core::{b64, crypto, jose};
use serde::Deserialize;

/// Why a JWKS document was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksError {
    /// Not a JSON object with a `keys` array.
    Malformed,
    /// No usable key.
    NoUsableKey,
}

impl core::fmt::Display for JwksError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JwksError::Malformed => f.write_str("JWKS is malformed"),
            JwksError::NoUsableKey => f.write_str("JWKS contains no usable ES256 key"),
        }
    }
}

impl std::error::Error for JwksError {}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
    #[serde(default)]
    d: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<serde_json::Value>,
}

fn usable(jwk: &Jwk) -> Option<VerifyKey> {
    if jwk.kty != "EC"
        || jwk.crv.as_deref() != Some("P-256")
        || jwk.alg.as_deref().is_some_and(|a| a != "ES256")
        || jwk.use_.as_deref().is_some_and(|u| u != "sig")
        || jwk.d.is_some()
    {
        return None;
    }
    let x = <[u8; 32]>::try_from(b64::decode_str(jwk.x.as_deref()?)?).ok()?;
    let y = <[u8; 32]>::try_from(b64::decode_str(jwk.y.as_deref()?)?).ok()?;
    if !crypto::public_key_is_valid(&PublicKey::Es256 { x, y }) {
        return None;
    }
    if jwk.kid.as_deref() != Some(jose::kid_for(&x, &y).as_str()) {
        return None;
    }
    Some(jose::verify_key(&x, &y))
}

/// Parses a JWKS document into verification keys.
pub fn parse_jwks(json: &[u8]) -> Result<Vec<VerifyKey>, JwksError> {
    let set: Jwks = serde_json::from_slice(json).map_err(|_| JwksError::Malformed)?;
    let keys: Vec<VerifyKey> = set
        .keys
        .into_iter()
        .filter_map(|v| serde_json::from_value::<Jwk>(v).ok())
        .filter_map(|j| usable(&j))
        .collect();
    if keys.is_empty() {
        return Err(JwksError::NoUsableKey);
    }
    Ok(keys)
}

#[cfg(feature = "fetch")]
pub use remote::RemoteJwks;

#[cfg(feature = "fetch")]
mod remote {
    use super::parse_jwks;
    use crate::{ConfigError, VerifyError};
    use auth_core::vtypes::VerifyKey;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{Mutex, RwLock};

    const MAX_BODY: usize = 64 * 1024;
    const DEFAULT_TTL: Duration = Duration::from_secs(300);
    const MIN_TTL: Duration = Duration::from_secs(60);
    const MAX_TTL: Duration = Duration::from_secs(3600);
    const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

    #[derive(Debug)]
    struct Cached {
        keys: Arc<Vec<VerifyKey>>,
        fetched_at: Instant,
        ttl: Duration,
    }

    /// A JWKS fetched over HTTPS and cached according to `Cache-Control`
    /// (clamped to 1 minute – 1 hour). An unknown `kid` triggers a refresh at
    /// most every 30 seconds, so key rotation is picked up quickly without
    /// letting clients force unbounded fetches.
    #[derive(Debug)]
    pub struct RemoteJwks {
        url: String,
        client: reqwest::Client,
        cached: RwLock<Option<Cached>>,
        fetch_lock: Mutex<()>,
    }

    fn max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
        let cc = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
        cc.split(',').find_map(|d| {
            let d = d.trim();
            d.strip_prefix("max-age=")
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs)
        })
    }

    impl RemoteJwks {
        /// A cache for `url`, which must be `https`.
        pub fn new(url: String) -> Result<Self, ConfigError> {
            if !url.starts_with("https://") {
                return Err(ConfigError("JWKS URL must be https".into()));
            }
            let client = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .https_only(true)
                .build()
                .map_err(|e| ConfigError(format!("HTTP client: {e}")))?;
            Ok(Self {
                url,
                client,
                cached: RwLock::new(None),
                fetch_lock: Mutex::new(()),
            })
        }

        async fn fetch(&self) -> Result<Cached, VerifyError> {
            let unavailable = |detail: String| VerifyError::Unavailable { detail };
            let mut resp = self
                .client
                .get(&self.url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|e| unavailable(format!("JWKS fetch: {e}")))?;
            if !resp.status().is_success() {
                return Err(unavailable(format!("JWKS fetch: HTTP {}", resp.status())));
            }
            let ttl = max_age(resp.headers())
                .unwrap_or(DEFAULT_TTL)
                .clamp(MIN_TTL, MAX_TTL);
            let mut body = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| unavailable(format!("JWKS read: {e}")))?
            {
                if body.len() + chunk.len() > MAX_BODY {
                    return Err(unavailable("JWKS too large".into()));
                }
                body.extend_from_slice(&chunk);
            }
            let keys = parse_jwks(&body).map_err(|e| unavailable(format!("JWKS: {e}")))?;
            Ok(Cached {
                keys: Arc::new(keys),
                fetched_at: Instant::now(),
                ttl,
            })
        }

        async fn refresh(&self, force_after: Duration) -> Result<Arc<Vec<VerifyKey>>, VerifyError> {
            let _guard = self.fetch_lock.lock().await;
            // Another task may have refreshed while we waited.
            if let Some(c) = self.cached.read().await.as_ref()
                && c.fetched_at.elapsed() < force_after.min(c.ttl)
            {
                return Ok(Arc::clone(&c.keys));
            }
            let fresh = self.fetch().await?;
            let keys = Arc::clone(&fresh.keys);
            *self.cached.write().await = Some(fresh);
            Ok(keys)
        }

        /// The current keys, fetching if the cache is empty or stale.
        pub async fn keys(&self) -> Result<Arc<Vec<VerifyKey>>, VerifyError> {
            if let Some(c) = self.cached.read().await.as_ref()
                && c.fetched_at.elapsed() < c.ttl
            {
                return Ok(Arc::clone(&c.keys));
            }
            self.refresh(Duration::ZERO).await
        }

        /// Refreshes after an unknown `kid` unless the cache is very recent.
        /// Returns whether a fetch happened.
        pub async fn refresh_for_unknown_kid(&self) -> Result<bool, VerifyError> {
            let recent = self
                .cached
                .read()
                .await
                .as_ref()
                .is_some_and(|c| c.fetched_at.elapsed() < MIN_REFRESH_INTERVAL);
            if recent {
                return Ok(false);
            }
            self.refresh(MIN_REFRESH_INTERVAL).await?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth_core::testing::LocalSigner;

    fn jwk(s: &LocalSigner) -> serde_json::Value {
        jose::public_jwk(&s.x, &s.y)
    }

    #[test]
    fn keeps_only_valid_es256_keys_named_by_thumbprint() {
        let a = LocalSigner::generate();
        let b = LocalSigner::generate();
        let mut wrong_kid = jwk(&b);
        wrong_kid["kid"] = "other".into();
        let mut private = jwk(&b);
        private["d"] = "AAAA".into();
        let mut bad_point = jwk(&b);
        bad_point["y"] = b64::encode(&[0u8; 32]).into();
        let rsa = serde_json::json!({"kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "r"});
        let doc = serde_json::json!({"keys": [jwk(&a), wrong_kid, private, bad_point, rsa]});
        let keys = parse_jwks(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, a.kid().into_bytes());
    }

    #[test]
    fn rejects_empty_or_malformed_sets() {
        assert_eq!(
            parse_jwks(br#"{"keys":[]}"#).err(),
            Some(JwksError::NoUsableKey)
        );
        assert_eq!(parse_jwks(br"[]").err(), Some(JwksError::Malformed));
        assert_eq!(parse_jwks(b"not json").err(), Some(JwksError::Malformed));
    }
}
