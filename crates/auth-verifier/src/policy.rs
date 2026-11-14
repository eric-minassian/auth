//! DPoP nonce and replay policies (RFC 9449 §9, §11.1).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A policy failure (for example the replay store is unreachable). Requests
/// fail closed with `503`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

/// How a resource server handles DPoP nonces and proof replay.
pub trait DpopPolicy: Send + Sync + fmt::Debug {
    /// The nonces currently accepted, or `None` if nonces are not required.
    fn valid_nonces(&self, now: u64) -> BoxFuture<'_, Result<Option<Vec<Vec<u8>>>, PolicyError>>;

    /// A nonce to hand out with `use_dpop_nonce`, if nonces are used.
    fn fresh_nonce(&self, now: u64) -> BoxFuture<'_, Result<Option<String>, PolicyError>>;

    /// Records a proof `jti` for key `jkt`. Returns `false` if it was already
    /// seen (a replay).
    fn record_jti<'a>(
        &'a self,
        jkt: &'a [u8],
        jti: &'a [u8],
        now: u64,
    ) -> BoxFuture<'a, Result<bool, PolicyError>>;
}

/// No nonces and no replay tracking. A captured proof could be replayed within
/// the `iat` window for the same method and URI. Acceptable only where TLS
/// interception is out of scope; prefer [`InMemoryReplayCache`] or a shared
/// store.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoReplayProtection;

impl DpopPolicy for NoReplayProtection {
    fn valid_nonces(&self, _now: u64) -> BoxFuture<'_, Result<Option<Vec<Vec<u8>>>, PolicyError>> {
        Box::pin(async { Ok(None) })
    }

    fn fresh_nonce(&self, _now: u64) -> BoxFuture<'_, Result<Option<String>, PolicyError>> {
        Box::pin(async { Ok(None) })
    }

    fn record_jti<'a>(
        &'a self,
        _jkt: &'a [u8],
        _jti: &'a [u8],
        _now: u64,
    ) -> BoxFuture<'a, Result<bool, PolicyError>> {
        Box::pin(async { Ok(true) })
    }
}

/// A bounded in-memory replay cache for a single server instance. Entries live
/// for `ttl` seconds, which must cover the full `iat` window (twice the skew).
#[derive(Debug)]
pub struct InMemoryReplayCache {
    ttl: u64,
    capacity: usize,
    seen: Mutex<HashMap<[u8; 32], u64>>,
}

impl InMemoryReplayCache {
    /// A cache holding at most `capacity` live entries for `ttl` seconds each.
    pub fn new(ttl: u64, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            seen: Mutex::new(HashMap::new()),
        }
    }

    fn key(jkt: &[u8], jti: &[u8]) -> [u8; 32] {
        let mut m = Vec::with_capacity(jkt.len() + 1 + jti.len());
        m.extend_from_slice(jkt);
        m.push(0);
        m.extend_from_slice(jti);
        auth_core::crypto::sha256(&m)
    }

    fn insert(&self, jkt: &[u8], jti: &[u8], now: u64) -> Result<bool, PolicyError> {
        let key = Self::key(jkt, jti);
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| PolicyError("replay cache lock poisoned".into()))?;
        if seen.get(&key).is_some_and(|exp| *exp > now) {
            return Ok(false);
        }
        if seen.len() >= self.capacity {
            seen.retain(|_, exp| *exp > now);
            if seen.len() >= self.capacity {
                return Err(PolicyError("replay cache full".into()));
            }
        }
        seen.insert(key, now.saturating_add(self.ttl));
        Ok(true)
    }
}

impl DpopPolicy for InMemoryReplayCache {
    fn valid_nonces(&self, _now: u64) -> BoxFuture<'_, Result<Option<Vec<Vec<u8>>>, PolicyError>> {
        Box::pin(async { Ok(None) })
    }

    fn fresh_nonce(&self, _now: u64) -> BoxFuture<'_, Result<Option<String>, PolicyError>> {
        Box::pin(async { Ok(None) })
    }

    fn record_jti<'a>(
        &'a self,
        jkt: &'a [u8],
        jti: &'a [u8],
        now: u64,
    ) -> BoxFuture<'a, Result<bool, PolicyError>> {
        let r = self.insert(jkt, jti, now);
        Box::pin(async move { r })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replay_cache_rejects_reuse_until_expiry_and_bounds_memory() {
        let c = InMemoryReplayCache::new(10, 2);
        assert_eq!(c.record_jti(b"k", b"a", 100).await, Ok(true));
        assert_eq!(c.record_jti(b"k", b"a", 105).await, Ok(false));
        assert_eq!(c.record_jti(b"other", b"a", 105).await, Ok(true));
        assert!(
            c.record_jti(b"k", b"b", 105).await.is_err(),
            "full of live entries"
        );
        assert_eq!(
            c.record_jti(b"k", b"a", 111).await,
            Ok(true),
            "expired entries are pruned"
        );
    }
}
