use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, StoreError, map_sdk_err, n, now, s, schema::GSI1};
use crate::crypto::{random_b64u, sha256_b64u};
use crate::domain::oauth::{
    AUTH_CODE_TTL_SECS, OidcClient, REFRESH_ABSOLUTE_SECS, REFRESH_IDLE_SECS,
};

// ---------------------------------------------------------------------------
// Clients

#[derive(Serialize, Deserialize)]
struct ClientItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    #[serde(flatten)]
    client: OidcClient,
}

impl Store {
    pub async fn put_client(&self, client: &OidcClient) -> Result<(), StoreError> {
        let item = serde_dynamo::to_item(ClientItem {
            pk: format!("CLIENT#{}", client.client_id),
            sk: "CLIENT".to_string(),
            client: client.clone(),
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }

    pub async fn get_client(&self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
        let result = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("PK", s(format!("CLIENT#{client_id}")))
            .key("SK", s("CLIENT"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        match result.item {
            Some(item) => {
                let item: ClientItem = serde_dynamo::from_item(item)?;
                Ok(Some(item.client))
            }
            None => Ok(None),
        }
    }

    /// All registered clients (CORS allowlist, back-channel logout fan-out).
    /// A scan is fine: the client registry is a handful of items.
    pub async fn list_clients(&self) -> Result<Vec<OidcClient>, StoreError> {
        let result = self
            .db
            .scan()
            .table_name(&self.table)
            .filter_expression("begins_with(PK, :prefix) AND SK = :sk")
            .expression_attribute_values(":prefix", s("CLIENT#"))
            .expression_attribute_values(":sk", s("CLIENT"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        result
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                let item: ClientItem = serde_dynamo::from_item(item)?;
                Ok(item.client)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Authorization codes

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeData {
    pub client_id: String,
    pub user_id: Uuid,
    pub sid_hash: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct AuthCodeItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    ttl: i64,
    created_at: i64,
    expires_at: i64,
    // Conditions test attribute_not_exists() on these two, so None must be
    // genuinely absent — serde_dynamo would otherwise write DynamoDB Nulls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    used_at: Option<i64>,
    /// Refresh-token family minted at exchange — revoked if the code is
    /// ever replayed (RFC 9700).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_family_id: Option<String>,
    #[serde(flatten)]
    data: AuthCodeData,
}

pub enum CodeConsume {
    /// First, in-window use.
    Consumed(AuthCodeData),
    /// The tombstone shows a previous use — replay attack signal.
    Replayed { issued_family_id: Option<String> },
    /// Expired, never existed, or already GC'd: indistinguishable on purpose.
    Invalid,
}

impl Store {
    /// Mint a code (plaintext returned exactly once; only its hash stored).
    pub async fn create_auth_code(&self, data: &AuthCodeData) -> Result<String, StoreError> {
        let code = random_b64u(32);
        let ts = now();
        let item = serde_dynamo::to_item(AuthCodeItem {
            pk: format!("CODE#{}", sha256_b64u(&code)),
            sk: "CODE".to_string(),
            ttl: ts + 15 * 60,
            created_at: ts,
            expires_at: ts + AUTH_CODE_TTL_SECS,
            used_at: None,
            issued_family_id: None,
            data: data.clone(),
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(code)
    }

    /// One-time consume. `family_id` is recorded on the tombstone so a later
    /// replay can revoke the refresh family minted by the first exchange.
    pub async fn consume_auth_code(
        &self,
        code: &str,
        family_id: &str,
    ) -> Result<CodeConsume, StoreError> {
        let pk = format!("CODE#{}", sha256_b64u(code));
        let ts = now();
        let updated = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(pk.clone()))
            .key("SK", s("CODE"))
            .update_expression("SET used_at = :now, issued_family_id = :fam")
            .condition_expression(
                "attribute_exists(PK) AND attribute_not_exists(used_at) AND expires_at > :now",
            )
            .expression_attribute_values(":now", n(ts))
            .expression_attribute_values(":fam", s(family_id))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await;

        match updated {
            Ok(out) => {
                let item: AuthCodeItem =
                    serde_dynamo::from_item(out.attributes.unwrap_or_default())?;
                Ok(CodeConsume::Consumed(item.data))
            }
            Err(e) => match map_sdk_err(e) {
                StoreError::ConditionFailed => {
                    // Distinguish replay (tombstone with used_at) from
                    // expiry/absence.
                    let existing = self
                        .db
                        .get_item()
                        .table_name(&self.table)
                        .key("PK", s(pk))
                        .key("SK", s("CODE"))
                        .send()
                        .await
                        .map_err(map_sdk_err)?;
                    match existing.item {
                        Some(item) => {
                            let item: AuthCodeItem = serde_dynamo::from_item(item)?;
                            if item.used_at.is_some() {
                                Ok(CodeConsume::Replayed {
                                    issued_family_id: item.issued_family_id,
                                })
                            } else {
                                Ok(CodeConsume::Invalid)
                            }
                        }
                        None => Ok(CodeConsume::Invalid),
                    }
                }
                other => Err(other),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Refresh-token families (rotation + reuse detection)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshFamily {
    pub family_id: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub sid_hash: String,
    pub scope: String,
    pub current_token_hash: String,
    pub generation: i64,
    pub created_at: i64,
    pub last_used_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
    // attribute_not_exists(revoked_at) gates rotation/revocation: None must
    // be absent, not a DynamoDB Null.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RefreshFamilyItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    #[serde(rename = "GSI1PK")]
    gsi1pk: String,
    #[serde(rename = "GSI1SK")]
    gsi1sk: String,
    ttl: i64,
    #[serde(flatten)]
    family: RefreshFamily,
}

/// Wire format: `rt_<family_id>.<secret>`.
pub fn encode_refresh_token(family_id: &str, secret: &str) -> String {
    format!("rt_{family_id}.{secret}")
}

pub fn decode_refresh_token(token: &str) -> Option<(&str, &str)> {
    token.strip_prefix("rt_")?.split_once('.')
}

pub enum RotateOutcome {
    Rotated {
        family: RefreshFamily,
        new_token: String,
    },
    /// Presented secret didn't match the live one for an unrevoked,
    /// unexpired family — token reuse. The family has been revoked.
    ReuseDetected {
        family: RefreshFamily,
    },
    Invalid,
}

impl Store {
    /// Create a new family bound to (user, client, IdP session). Returns the
    /// wire token.
    pub async fn create_refresh_family(
        &self,
        family_id: &str,
        user_id: Uuid,
        client_id: &str,
        sid_hash: &str,
        scope: &str,
    ) -> Result<String, StoreError> {
        let secret = random_b64u(32);
        let ts = now();
        let family = RefreshFamily {
            family_id: family_id.to_string(),
            user_id,
            client_id: client_id.to_string(),
            sid_hash: sid_hash.to_string(),
            scope: scope.to_string(),
            current_token_hash: sha256_b64u(&secret),
            generation: 0,
            created_at: ts,
            last_used_at: ts,
            idle_expires_at: ts + REFRESH_IDLE_SECS,
            absolute_expires_at: ts + REFRESH_ABSOLUTE_SECS,
            revoked_at: None,
            revoked_reason: None,
        };
        let item = serde_dynamo::to_item(RefreshFamilyItem {
            pk: format!("RTF#{family_id}"),
            sk: "FAMILY".to_string(),
            gsi1pk: format!("USER#{user_id}"),
            gsi1sk: format!("RTF#{ts}#{family_id}"),
            ttl: family.absolute_expires_at + 7 * 24 * 3600,
            family,
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(encode_refresh_token(family_id, &secret))
    }

    /// Atomic rotation: one conditional update keyed on the presented secret
    /// hash. A hash mismatch on a live family = reuse → revoke the family.
    pub async fn rotate_refresh_token(&self, token: &str) -> Result<RotateOutcome, StoreError> {
        let Some((family_id, secret)) = decode_refresh_token(token) else {
            return Ok(RotateOutcome::Invalid);
        };
        let presented_hash = sha256_b64u(secret);
        let new_secret = random_b64u(32);
        let ts = now();

        let updated = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(format!("RTF#{family_id}")))
            .key("SK", s("FAMILY"))
            .update_expression(
                "SET current_token_hash = :new, generation = generation + :one, \
                 last_used_at = :now, idle_expires_at = :idle",
            )
            .condition_expression(
                "attribute_exists(PK) AND current_token_hash = :h \
                 AND attribute_not_exists(revoked_at) \
                 AND idle_expires_at > :now AND absolute_expires_at > :now",
            )
            .expression_attribute_values(":new", s(sha256_b64u(&new_secret)))
            .expression_attribute_values(":one", n(1))
            .expression_attribute_values(":now", n(ts))
            .expression_attribute_values(":idle", n(ts + REFRESH_IDLE_SECS))
            .expression_attribute_values(":h", s(presented_hash.clone()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await;

        match updated {
            Ok(out) => {
                let item: RefreshFamilyItem =
                    serde_dynamo::from_item(out.attributes.unwrap_or_default())?;
                Ok(RotateOutcome::Rotated {
                    family: item.family,
                    new_token: encode_refresh_token(family_id, &new_secret),
                })
            }
            Err(e) => match map_sdk_err(e) {
                StoreError::ConditionFailed => {
                    let Some(family) = self.get_refresh_family(family_id).await? else {
                        return Ok(RotateOutcome::Invalid);
                    };
                    let live = family.revoked_at.is_none()
                        && family.idle_expires_at > ts
                        && family.absolute_expires_at > ts;
                    if live && family.current_token_hash != presented_hash {
                        self.revoke_refresh_family(family_id, "reuse").await?;
                        Ok(RotateOutcome::ReuseDetected { family })
                    } else {
                        Ok(RotateOutcome::Invalid)
                    }
                }
                other => Err(other),
            },
        }
    }

    pub async fn get_refresh_family(
        &self,
        family_id: &str,
    ) -> Result<Option<RefreshFamily>, StoreError> {
        let result = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("PK", s(format!("RTF#{family_id}")))
            .key("SK", s("FAMILY"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        match result.item {
            Some(item) => {
                let item: RefreshFamilyItem = serde_dynamo::from_item(item)?;
                Ok(Some(item.family))
            }
            None => Ok(None),
        }
    }

    pub async fn revoke_refresh_family(
        &self,
        family_id: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(format!("RTF#{family_id}")))
            .key("SK", s("FAMILY"))
            .update_expression("SET revoked_at = :now, revoked_reason = :reason")
            .condition_expression("attribute_exists(PK) AND attribute_not_exists(revoked_at)")
            .expression_attribute_values(":now", n(now()))
            .expression_attribute_values(":reason", s(reason))
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            // Already revoked or GC'd — revocation is idempotent.
            Err(e) => match map_sdk_err(e) {
                StoreError::ConditionFailed => Ok(()),
                other => Err(other),
            },
        }
    }

    /// Live refresh families for a user, optionally filtered to one IdP
    /// session (logout cascade).
    pub async fn list_refresh_families(
        &self,
        user_id: Uuid,
        sid_hash: Option<&str>,
    ) -> Result<Vec<RefreshFamily>, StoreError> {
        let ts = now();
        let result = self
            .db
            .query()
            .table_name(&self.table)
            .index_name(GSI1)
            .key_condition_expression("GSI1PK = :pk AND begins_with(GSI1SK, :prefix)")
            .expression_attribute_values(":pk", AttributeValue::S(format!("USER#{user_id}")))
            .expression_attribute_values(":prefix", s("RTF#"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        let mut families = Vec::new();
        for item in result.items.unwrap_or_default() {
            let item: RefreshFamilyItem = serde_dynamo::from_item(item)?;
            let family = item.family;
            let live = family.revoked_at.is_none() && family.absolute_expires_at > ts;
            let matches_session = sid_hash.is_none_or(|sid| family.sid_hash == sid);
            if live && matches_session {
                families.push(family);
            }
        }
        Ok(families)
    }
}
