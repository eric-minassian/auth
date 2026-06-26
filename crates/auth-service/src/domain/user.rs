use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Account lifecycle. A `Pending` row exists only between `signup/start` and
/// `signup/finish` (short TTL); it flips to `Active` atomically with the first
/// passkey. Only `Active` accounts may authenticate or authorize RPs — this is
/// the authoritative gate, re-checked on every read of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Pending,
    #[default]
    Active,
}

/// A user account. There is no email or other verified identifier: identity is
/// the opaque `user_id` (also the WebAuthn user handle). `nickname` is a
/// user-chosen, non-unique, mutable display label — never an identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: Uuid,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub status: AccountStatus,
    pub created_at: i64,
    pub updated_at: i64,
}

impl User {
    pub fn is_active(&self) -> bool {
        matches!(self.status, AccountStatus::Active)
    }
}
