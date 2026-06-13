use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use super::{Store, StoreError, map_sdk_err, n, now, s, schema::GSI1};
use crate::domain::credential::StoredPasskey;

#[derive(Serialize, Deserialize)]
struct CredentialItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    #[serde(rename = "GSI1PK")]
    gsi1pk: String,
    #[serde(rename = "GSI1SK")]
    gsi1sk: String,
    /// `Passkey` serialized as JSON text — keeps the webauthn-rs wire format
    /// out of DynamoDB's type system.
    passkey_json: String,
    credential_id: String,
    user_id: Uuid,
    name: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

fn cred_pk(credential_id: &str) -> String {
    format!("CRED#{credential_id}")
}

impl CredentialItem {
    fn into_stored(self) -> Result<StoredPasskey, StoreError> {
        let passkey: Passkey = serde_json::from_str(&self.passkey_json)
            .map_err(|e| StoreError::Sdk(format!("corrupt passkey json: {e}")))?;
        Ok(StoredPasskey {
            credential_id: self.credential_id,
            user_id: self.user_id,
            passkey,
            name: self.name,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        })
    }
}

impl Store {
    pub async fn put_credential(
        &self,
        user_id: Uuid,
        credential_id: &str,
        passkey: &Passkey,
        name: &str,
    ) -> Result<StoredPasskey, StoreError> {
        let ts = now();
        let stored = StoredPasskey {
            credential_id: credential_id.to_string(),
            user_id,
            passkey: passkey.clone(),
            name: name.to_string(),
            created_at: ts,
            last_used_at: None,
        };
        let item = serde_dynamo::to_item(CredentialItem {
            pk: cred_pk(credential_id),
            sk: "CRED".to_string(),
            gsi1pk: format!("USER#{user_id}"),
            gsi1sk: format!("CRED#{ts}#{credential_id}"),
            passkey_json: serde_json::to_string(passkey)
                .map_err(|e| StoreError::Sdk(e.to_string()))?,
            credential_id: credential_id.to_string(),
            user_id,
            name: name.to_string(),
            created_at: ts,
            last_used_at: None,
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(stored)
    }

    pub async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>, StoreError> {
        let result = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("PK", s(cred_pk(credential_id)))
            .key("SK", s("CRED"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        match result.item {
            Some(item) => {
                let item: CredentialItem = serde_dynamo::from_item(item)?;
                Ok(Some(item.into_stored()?))
            }
            None => Ok(None),
        }
    }

    pub async fn list_credentials(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, StoreError> {
        let result = self
            .db
            .query()
            .table_name(&self.table)
            .index_name(GSI1)
            .key_condition_expression("GSI1PK = :pk AND begins_with(GSI1SK, :prefix)")
            .expression_attribute_values(":pk", s(format!("USER#{user_id}")))
            .expression_attribute_values(":prefix", s("CRED#"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        result
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                let item: CredentialItem = serde_dynamo::from_item(item)?;
                item.into_stored()
            })
            .collect()
    }

    /// Persist counter/backup-state changes after a successful authentication
    /// and bump last_used_at.
    pub async fn update_credential_after_auth(
        &self,
        credential_id: &str,
        passkey: &Passkey,
    ) -> Result<(), StoreError> {
        self.db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(cred_pk(credential_id)))
            .key("SK", s("CRED"))
            .update_expression("SET passkey_json = :p, last_used_at = :ts")
            .condition_expression("attribute_exists(PK)")
            .expression_attribute_values(
                ":p",
                s(serde_json::to_string(passkey).map_err(|e| StoreError::Sdk(e.to_string()))?),
            )
            .expression_attribute_values(":ts", n(now()))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }

    /// Rename, scoped to the owning user (condition prevents cross-user
    /// renames even if an id leaks).
    pub async fn rename_credential(
        &self,
        user_id: Uuid,
        credential_id: &str,
        name: &str,
    ) -> Result<(), StoreError> {
        self.db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(cred_pk(credential_id)))
            .key("SK", s("CRED"))
            .update_expression("SET #name = :name")
            .condition_expression("attribute_exists(PK) AND user_id = :uid")
            .expression_attribute_names("#name", "name")
            .expression_attribute_values(":name", s(name))
            .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }

    pub async fn delete_credential(
        &self,
        user_id: Uuid,
        credential_id: &str,
    ) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(cred_pk(credential_id)))
            .key("SK", s("CRED"))
            .condition_expression("attribute_exists(PK) AND user_id = :uid")
            .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }
}
