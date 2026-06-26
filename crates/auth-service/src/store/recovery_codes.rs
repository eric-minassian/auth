use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, StoreError, map_sdk_err, now, s, schema::GSI1};
use crate::crypto::{generate_recovery_code, random_b64u, sha256_b64u};

/// Codes issued per generation.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// A leaked-but-unredeemed code's hard lifetime (`expires_at`, re-checked on
/// redeem). `ttl` adds a GC grace period on top.
const RECOVERY_CODE_TTL_SECS: i64 = 2 * 365 * 24 * 3600;

#[derive(Serialize, Deserialize)]
struct RecoveryCodeItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    #[serde(rename = "GSI1PK")]
    gsi1pk: String,
    #[serde(rename = "GSI1SK")]
    gsi1sk: String,
    user_id: Uuid,
    generation: String,
    created_at: i64,
    expires_at: i64,
    ttl: i64,
}

fn rc_pk(hash: &str) -> String {
    format!("RC#{hash}")
}

impl Store {
    /// Generate a fresh set of recovery codes, invalidating any previous set.
    /// Write-new-before-delete-old: the new codes are persisted (and returned
    /// for one-time display) BEFORE the previous generation is swept, so a
    /// crash can never leave the user with zero valid codes. Returns the
    /// plaintext display codes — caller must reveal them exactly once.
    pub async fn generate_recovery_codes(&self, user_id: Uuid) -> Result<Vec<String>, StoreError> {
        // Snapshot existing codes to sweep after the new set is durable.
        let stale = self.list_recovery_code_pks(user_id).await?;

        let ts = now();
        let generation = random_b64u(12);
        let mut display = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for i in 0..RECOVERY_CODE_COUNT {
            let code = generate_recovery_code();
            let item = serde_dynamo::to_item(RecoveryCodeItem {
                pk: rc_pk(&sha256_b64u(&code.canonical)),
                sk: "RC".to_string(),
                gsi1pk: format!("USER#{user_id}"),
                gsi1sk: format!("RC#{generation}#{ts}#{i:02}"),
                user_id,
                generation: generation.clone(),
                created_at: ts,
                expires_at: ts + RECOVERY_CODE_TTL_SECS,
                ttl: ts + RECOVERY_CODE_TTL_SECS + 7 * 24 * 3600,
            })?;
            self.db
                .put_item()
                .table_name(&self.table)
                .set_item(Some(item))
                .send()
                .await
                .map_err(map_sdk_err)?;
            display.push(code.display);
        }

        for pk in stale {
            self.delete_rc(&pk).await?;
        }
        Ok(display)
    }

    /// Count live (unexpired) recovery codes for a user (readiness display).
    pub async fn count_recovery_codes(&self, user_id: Uuid) -> Result<usize, StoreError> {
        let ts = now();
        let result = self.query_recovery_codes(user_id).await?;
        Ok(result.into_iter().filter(|c| c.expires_at > ts).count())
    }

    /// Delete every recovery code for a user (account-deletion cascade).
    pub async fn delete_all_recovery_codes(&self, user_id: Uuid) -> Result<(), StoreError> {
        for pk in self.list_recovery_code_pks(user_id).await? {
            self.delete_rc(&pk).await?;
        }
        Ok(())
    }

    /// Redeem (consume) a recovery code by its canonical-form hash. Atomic
    /// one-shot: conditional `DeleteItem` with `ReturnValues=ALL_OLD` — the
    /// same one-time-use primitive used for ceremonies. Returns the owning
    /// `user_id`, or `None` if absent or expired (caller responds uniformly).
    pub async fn redeem_recovery_code(
        &self,
        canonical_hash: &str,
    ) -> Result<Option<Uuid>, StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(rc_pk(canonical_hash)))
            .key("SK", s("RC"))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(map_sdk_err)?;
        let Some(attributes) = result.attributes else {
            return Ok(None);
        };
        let item: RecoveryCodeItem = serde_dynamo::from_item(attributes)?;
        // TTL is GC, not enforcement — re-check expiry on read.
        if item.expires_at <= now() {
            return Ok(None);
        }
        Ok(Some(item.user_id))
    }

    async fn query_recovery_codes(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<RecoveryCodeItem>, StoreError> {
        let result = self
            .db
            .query()
            .table_name(&self.table)
            .index_name(GSI1)
            .key_condition_expression("GSI1PK = :pk AND begins_with(GSI1SK, :prefix)")
            .expression_attribute_values(":pk", s(format!("USER#{user_id}")))
            .expression_attribute_values(":prefix", s("RC#"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        let mut items = Vec::new();
        for item in result.items.unwrap_or_default() {
            items.push(serde_dynamo::from_item(item)?);
        }
        Ok(items)
    }

    async fn list_recovery_code_pks(&self, user_id: Uuid) -> Result<Vec<String>, StoreError> {
        Ok(self
            .query_recovery_codes(user_id)
            .await?
            .into_iter()
            .map(|c| c.pk)
            .collect())
    }

    async fn delete_rc(&self, pk: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(pk))
            .key("SK", s("RC"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }
}
