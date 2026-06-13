pub mod ceremonies;
pub mod credentials;
pub mod oauth;
pub mod otp;
pub mod rate_limit;
pub mod schema;
pub mod sessions;
pub mod users;

use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::types::AttributeValue;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A conditional write failed. Semantics depend on the call site (item
    /// exists / already consumed / hash mismatch) — callers map this.
    #[error("conditional check failed")]
    ConditionFailed,
    #[error("dynamodb error: {0}")]
    Sdk(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_dynamo::Error),
}

pub(crate) fn map_sdk_err<E, R>(e: SdkError<E, R>) -> StoreError
where
    E: ProvideErrorMetadata + std::fmt::Debug,
    R: std::fmt::Debug,
{
    let code = e.as_service_error().and_then(|se| se.code());
    match code {
        Some("ConditionalCheckFailedException") => StoreError::ConditionFailed,
        // TransactWriteItems reports per-item condition failures inside the
        // cancellation reasons.
        Some("TransactionCanceledException")
            if format!("{e:?}").contains("ConditionalCheckFailed") =>
        {
            StoreError::ConditionFailed
        }
        _ => StoreError::Sdk(format!("{e:?}")),
    }
}

/// Current unix time in seconds.
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// String attribute value (DynamoDB `S`).
pub(crate) fn s(v: impl Into<String>) -> AttributeValue {
    AttributeValue::S(v.into())
}

/// Number attribute value (DynamoDB `N`).
pub(crate) fn n(v: i64) -> AttributeValue {
    AttributeValue::N(v.to_string())
}

/// Single-table DynamoDB repository.
///
/// Key patterns (see CLAUDE.md / docs/research): `USER#<id>`, `EMAIL#<email>`,
/// `SESSION#<sha256(sid)>`, `CRED#<cred_id>`, `CLIENT#<id>`,
/// `CODE#<sha256(code)>`, `RTF#<family_id>`, `OTP#<sha256(email)>#<purpose>`,
/// `WAC#<id>`, `RL#<class>#<key>`, `KEYRING`. GSI1 lists long-lived child
/// entities per user. TTL attribute `ttl` is garbage collection only — every
/// read checks `expires_at`/`*_expires_at` itself.
#[derive(Clone)]
pub struct Store {
    pub(crate) db: aws_sdk_dynamodb::Client,
    pub(crate) table: String,
}

impl Store {
    pub fn new(db: aws_sdk_dynamodb::Client, table: impl Into<String>) -> Self {
        Self {
            db,
            table: table.into(),
        }
    }
}
