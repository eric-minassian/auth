use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskey {
    /// base64url credential id — also the primary key suffix.
    pub credential_id: String,
    pub user_id: Uuid,
    /// Full webauthn-rs credential (public key, counter, backup flags).
    pub passkey: Passkey,
    /// User-assigned label, e.g. "MacBook Touch ID".
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}
