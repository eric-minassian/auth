use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use super::{Store, StoreError, map_sdk_err, now, s};
use crate::crypto::random_b64u;

pub const CEREMONY_TTL_SECS: i64 = 5 * 60;

/// WebAuthn ceremony state parked between start and finish. Stored
/// server-side only — the safety condition for webauthn-rs's
/// `danger-allow-state-serialisation` feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyPurpose {
    Registration,
    Login,
    /// First-passkey registration during signup, against a pending account.
    /// Distinct from `Registration` so an unauthenticated signup ceremony can
    /// never be cross-consumed by an authenticated add-passkey flow.
    Signup,
    /// Step-up re-authentication on an existing full session.
    Reauth,
}

#[derive(Serialize, Deserialize)]
struct CeremonyItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    ttl: i64,
    purpose: CeremonyPurpose,
    /// Owning user for registration ceremonies (None for login: the user is
    /// only known after the authenticator responds).
    user_id: Option<Uuid>,
    state_json: String,
    expires_at: i64,
}

impl Store {
    pub async fn put_ceremony<S: Serialize>(
        &self,
        purpose: CeremonyPurpose,
        user_id: Option<Uuid>,
        state: &S,
    ) -> Result<String, StoreError> {
        let ceremony_id = random_b64u(16);
        let ts = now();
        let item = serde_dynamo::to_item(CeremonyItem {
            pk: format!("WAC#{ceremony_id}"),
            sk: "WAC".to_string(),
            ttl: ts + 15 * 60,
            purpose,
            user_id,
            state_json: serde_json::to_string(state).map_err(|e| StoreError::Sdk(e.to_string()))?,
            expires_at: ts + CEREMONY_TTL_SECS,
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(ceremony_id)
    }

    /// Atomic one-shot consume: DeleteItem with ReturnValues=ALL_OLD. Absent
    /// or expired → None (restart the ceremony).
    pub async fn consume_ceremony<T: DeserializeOwned>(
        &self,
        ceremony_id: &str,
        purpose: CeremonyPurpose,
    ) -> Result<Option<(Option<Uuid>, T)>, StoreError> {
        let result = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(format!("WAC#{ceremony_id}")))
            .key("SK", s("WAC"))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(map_sdk_err)?;
        let Some(attributes) = result.attributes else {
            return Ok(None);
        };
        let item: CeremonyItem = serde_dynamo::from_item(attributes)?;
        if item.purpose != purpose || item.expires_at <= now() {
            return Ok(None);
        }
        let state: T = serde_json::from_str(&item.state_json)
            .map_err(|e| StoreError::Sdk(format!("corrupt ceremony state: {e}")))?;
        Ok(Some((item.user_id, state)))
    }
}
