use serde::{Deserialize, Serialize};

use super::{Store, StoreError, map_sdk_err, now};

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
}
