use serde::{Deserialize, Serialize};

use super::{Store, StoreError, map_sdk_err, now, s};
use crate::crypto::random_b64u;

/// Difficulty (leading zero bits) required of a signup proof-of-work. ~2^16
/// hashes is well under a second in a browser — a soft cost that raises the
/// price of mass automated signup without gating legitimate users. PoW is not
/// a Sybil proof; it complements per-IP/ASN rate limiting. Tune higher if abused.
pub const POW_DIFFICULTY_BITS: u32 = 16;
const POW_TTL_SECS: i64 = 10 * 60;

#[derive(Serialize, Deserialize)]
struct PowItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    ttl: i64,
    difficulty: u32,
    expires_at: i64,
}

fn pow_pk(challenge: &str) -> String {
    format!("POW#{challenge}")
}

impl Store {
    /// Issue a one-time PoW challenge. Returns `(challenge, difficulty)`.
    pub async fn issue_pow_challenge(&self) -> Result<(String, u32), StoreError> {
        let challenge = random_b64u(16);
        let ts = now();
        let item = serde_dynamo::to_item(PowItem {
            pk: pow_pk(&challenge),
            sk: "POW".to_string(),
            ttl: ts + POW_TTL_SECS + 3600,
            difficulty: POW_DIFFICULTY_BITS,
            expires_at: ts + POW_TTL_SECS,
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok((challenge, POW_DIFFICULTY_BITS))
    }

    /// Atomically consume a PoW challenge (one-time-use via conditional delete
    /// with `ALL_OLD`). Returns the required difficulty if the challenge
    /// existed and is unexpired; `None` otherwise.
    pub async fn consume_pow_challenge(
        &self,
        challenge: &str,
    ) -> Result<Option<u32>, StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(pow_pk(challenge)))
            .key("SK", s("POW"))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(map_sdk_err)?;
        let Some(attributes) = result.attributes else {
            return Ok(None);
        };
        let item: PowItem = serde_dynamo::from_item(attributes)?;
        if item.expires_at <= now() {
            return Ok(None);
        }
        Ok(Some(item.difficulty))
    }
}
