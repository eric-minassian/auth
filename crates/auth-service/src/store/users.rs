use aws_sdk_dynamodb::types::{Delete, Put, TransactWriteItem};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, StoreError, map_sdk_err, now, s};
use crate::domain::user::User;

#[derive(Serialize, Deserialize)]
struct UserItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    #[serde(flatten)]
    user: User,
}

#[derive(Serialize, Deserialize)]
struct EmailPointerItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    user_id: Uuid,
}

fn user_pk(user_id: Uuid) -> String {
    format!("USER#{user_id}")
}

fn email_pk(email: &str) -> String {
    format!("EMAIL#{}", email.to_lowercase())
}

impl Store {
    /// Create a user and its email-uniqueness pointer atomically. Returns
    /// `StoreError::ConditionFailed` if the email is already taken.
    pub async fn create_user(&self, email: &str) -> Result<User, StoreError> {
        let ts = now();
        let user = User {
            user_id: Uuid::now_v7(),
            email: email.to_lowercase(),
            email_verified: true,
            created_at: ts,
            updated_at: ts,
        };
        let user_item = serde_dynamo::to_item(UserItem {
            pk: user_pk(user.user_id),
            sk: "PROFILE".to_string(),
            user: user.clone(),
        })?;
        let pointer_item = serde_dynamo::to_item(EmailPointerItem {
            pk: email_pk(&user.email),
            sk: "EMAIL".to_string(),
            user_id: user.user_id,
        })?;
        let put = |item| {
            Put::builder()
                .table_name(&self.table)
                .set_item(Some(item))
                .condition_expression("attribute_not_exists(PK)")
                .build()
                .map_err(|e| StoreError::Sdk(e.to_string()))
        };
        self.db
            .transact_write_items()
            .transact_items(TransactWriteItem::builder().put(put(user_item)?).build())
            .transact_items(TransactWriteItem::builder().put(put(pointer_item)?).build())
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
                Ok(Some(item.user))
            }
            None => Ok(None),
        }
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        let result = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("PK", s(email_pk(email)))
            .key("SK", s("EMAIL"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        match result.item {
            Some(item) => {
                let pointer: EmailPointerItem = serde_dynamo::from_item(item)?;
                self.get_user(pointer.user_id).await
            }
            None => Ok(None),
        }
    }

    /// Delete the user profile and the email-uniqueness pointer atomically, so
    /// a crash between the two can't orphan one (which would otherwise leave
    /// the email permanently unregisterable, or the reverse). Caller handles
    /// the dependent items (credentials, sessions, refresh families) — see
    /// [`crate::api::account::delete_account`].
    pub async fn delete_user(&self, user: &User) -> Result<(), StoreError> {
        let del = |pk: String, sk: &str| {
            Delete::builder()
                .table_name(&self.table)
                .key("PK", s(pk))
                .key("SK", s(sk))
                .build()
                .map_err(|e| StoreError::Sdk(e.to_string()))
        };
        self.db
            .transact_write_items()
            .transact_items(
                TransactWriteItem::builder()
                    .delete(del(format!("USER#{}", user.user_id), "PROFILE")?)
                    .build(),
            )
            .transact_items(
                TransactWriteItem::builder()
                    .delete(del(email_pk(&user.email), "EMAIL")?)
                    .build(),
            )
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }
}
