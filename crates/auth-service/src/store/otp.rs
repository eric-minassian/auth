use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};

use super::{Store, StoreError, map_sdk_err, now, s};
use crate::crypto::{ct_eq, random_otp, sha256_b64u};
use crate::domain::otp::{OTP_MAX_ATTEMPTS, OTP_TTL_SECS, OtpPurpose};

#[derive(Serialize, Deserialize)]
struct OtpItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    ttl: i64,
    code_hash: String,
    attempts: i64,
    created_at: i64,
    expires_at: i64,
}

fn otp_pk(email: &str, purpose: OtpPurpose) -> String {
    format!(
        "OTP#{}#{}",
        sha256_b64u(email.to_lowercase()),
        purpose.as_str()
    )
}

impl Store {
    /// Issue (or re-issue, overwriting) the single active OTP for this
    /// email+purpose. Returns the plaintext code for the email body.
    pub async fn issue_otp(&self, email: &str, purpose: OtpPurpose) -> Result<String, StoreError> {
        let code = random_otp();
        let ts = now();
        let item = serde_dynamo::to_item(OtpItem {
            pk: otp_pk(email, purpose),
            sk: "OTP".to_string(),
            ttl: ts + 3600,
            code_hash: sha256_b64u(&code),
            attempts: 0,
            created_at: ts,
            expires_at: ts + OTP_TTL_SECS,
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

    /// Verify and consume an OTP. Returns false uniformly for wrong code,
    /// expired, attempt-capped, or absent — callers must not distinguish.
    ///
    /// Two atomic steps: (1) increment `attempts` conditioned on the cap and
    /// expiry (so guessing burns an attempt even on races), then (2) compare
    /// hashes in constant time and consume via a conditional delete.
    pub async fn verify_otp(
        &self,
        email: &str,
        purpose: OtpPurpose,
        code: &str,
    ) -> Result<bool, StoreError> {
        let pk = otp_pk(email, purpose);
        let ts = now();
        let updated = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(pk.clone()))
            .key("SK", s("OTP"))
            .update_expression("ADD attempts :one")
            .condition_expression("attribute_exists(PK) AND attempts < :max AND expires_at > :now")
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .expression_attribute_values(":max", AttributeValue::N(OTP_MAX_ATTEMPTS.to_string()))
            .expression_attribute_values(":now", AttributeValue::N(ts.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await;
        let attributes = match updated {
            Ok(out) => out.attributes.unwrap_or_default(),
            Err(e) => {
                return match map_sdk_err(e) {
                    StoreError::ConditionFailed => Ok(false),
                    other => Err(other),
                };
            }
        };
        let item: OtpItem = serde_dynamo::from_item(attributes)?;
        if !ct_eq(&item.code_hash, &sha256_b64u(code)) {
            return Ok(false);
        }
        // Single-use: delete conditioned on the hash so a concurrent re-issue
        // isn't consumed by an old code.
        let deleted = self
            .db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(pk))
            .key("SK", s("OTP"))
            .condition_expression("code_hash = :h")
            .expression_attribute_values(":h", AttributeValue::S(item.code_hash))
            .send()
            .await;
        match deleted {
            Ok(_) => Ok(true),
            Err(e) => match map_sdk_err(e) {
                StoreError::ConditionFailed => Ok(false),
                other => Err(other),
            },
        }
    }
}
