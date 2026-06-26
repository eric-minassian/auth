use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, StoreError, map_sdk_err, now, s};
use crate::domain::user::{AccountStatus, User};

/// How long a pending (not-yet-completed) signup row lives before GC.
pub const PENDING_USER_TTL_SECS: i64 = 15 * 60;

#[derive(Serialize, Deserialize)]
struct UserItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    #[serde(flatten)]
    user: User,
    /// Present only while pending (signup not yet completed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
}

pub(crate) fn user_pk(user_id: Uuid) -> String {
    format!("USER#{user_id}")
}

impl Store {
    /// Create a new *pending* user. The account is unusable until
    /// [`Store::activate_user_with_first_credential`] flips it to Active
    /// alongside its first passkey; until then it carries a short TTL and is
    /// GC'd if signup is abandoned. There is no uniqueness pointer — accounts
    /// have no email/username, only the opaque `user_id`.
    pub async fn create_user(&self, nickname: &str) -> Result<User, StoreError> {
        let ts = now();
        let user = User {
            user_id: Uuid::now_v7(),
            nickname: nickname.to_string(),
            status: AccountStatus::Pending,
            created_at: ts,
            updated_at: ts,
        };
        let item = serde_dynamo::to_item(UserItem {
            pk: user_pk(user.user_id),
            sk: "PROFILE".to_string(),
            user: user.clone(),
            ttl: Some(ts + PENDING_USER_TTL_SECS),
            expires_at: Some(ts + PENDING_USER_TTL_SECS),
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(user)
    }

    pub async fn get_user(&self, user_id: Uuid) -> Result<Option<User>, StoreError> {
        let result = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("PK", s(user_pk(user_id)))
            .key("SK", s("PROFILE"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        match result.item {
            Some(item) => {
                let item: UserItem = serde_dynamo::from_item(item)?;
                // TTL is GC, not enforcement: a pending row past its expiry is
                // treated as absent even before DynamoDB reaps it.
                if item.user.status == AccountStatus::Pending
                    && item.expires_at.is_some_and(|e| e <= now())
                {
                    return Ok(None);
                }
                Ok(Some(item.user))
            }
            None => Ok(None),
        }
    }

    /// Permanently delete the user profile. Callers handle dependent items
    /// (credentials, sessions, refresh families, recovery codes) — see
    /// [`crate::api::account::delete_account`].
    pub async fn delete_user(&self, user: &User) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(user_pk(user.user_id)))
            .key("SK", s("PROFILE"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }
}
