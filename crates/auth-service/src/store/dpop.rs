use serde::{Deserialize, Serialize};

use super::{Store, StoreError, map_sdk_err, now, s};
use crate::crypto::{b64u_decode, random_b64u};

/// How long a consumed DPoP proof's `jti` is remembered to reject replays. Must
/// be ≥ the proof acceptance window (`oidc::dpop::PROOF_MAX_AGE_SECS`) so a
/// proof can't be replayed after its own record has been GC'd but while it would
/// still pass the `iat` check.
const JTI_RETENTION_SECS: i64 = 600;

#[derive(Serialize, Deserialize)]
struct DpopJtiItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    ttl: i64,
}

impl Store {
    /// Record a DPoP proof's `jti` (scoped to its key thumbprint). Returns
    /// `true` if the proof is fresh, `false` if this exact proof was already
    /// seen — a replay. One-time-use via a conditional put on
    /// `attribute_not_exists(PK)`.
    pub async fn record_dpop_jti(&self, jkt: &str, jti: &str) -> Result<bool, StoreError> {
        let item = serde_dynamo::to_item(DpopJtiItem {
            pk: format!("DPOPJTI#{jkt}#{jti}"),
            sk: "DPOPJTI".to_string(),
            ttl: now() + JTI_RETENTION_SECS,
        })?;
        let result = self
            .db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(e) => match map_sdk_err(e) {
                StoreError::ConditionFailed => Ok(false),
                other => Err(other),
            },
        }
    }

    /// Get-or-create the server-wide DPoP nonce key (RFC 9449 §8). Created
    /// exactly once via a conditional put; every Lambda instance derives
    /// identical time-bucketed nonces from the same key. Callers cache the
    /// result for the process lifetime (see `AppState::dpop_nonce_key`).
    pub async fn get_or_create_dpop_nonce_key(&self) -> Result<[u8; 32], StoreError> {
        let pk = "SERVERKEY#dpop_nonce";
        let candidate = random_b64u(32);
        let put = self
            .db
            .put_item()
            .table_name(&self.table)
            .item("PK", s(pk.to_string()))
            .item("SK", s("KEY"))
            .item("key_b64u", s(candidate.clone()))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await;
        let key_b64u = match put {
            Ok(_) => candidate,
            Err(e) => match map_sdk_err(e) {
                // Lost the race (or the key already exists): read the winner.
                StoreError::ConditionFailed => {
                    let result = self
                        .db
                        .get_item()
                        .table_name(&self.table)
                        .key("PK", s(pk.to_string()))
                        .key("SK", s("KEY"))
                        .send()
                        .await
                        .map_err(map_sdk_err)?;
                    result
                        .item
                        .and_then(|item| item.get("key_b64u").cloned())
                        .and_then(|v| v.as_s().ok().cloned())
                        .ok_or_else(|| StoreError::Sdk("dpop nonce key missing".to_string()))?
                }
                other => return Err(other),
            },
        };
        let bytes =
            b64u_decode(&key_b64u).ok_or_else(|| StoreError::Sdk("dpop nonce key b64".into()))?;
        bytes
            .try_into()
            .map_err(|_| StoreError::Sdk("dpop nonce key length".into()))
    }
}
