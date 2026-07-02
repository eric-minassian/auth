use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Account lifecycle. A `Pending` row exists only between `signup/start` and
/// `signup/finish` (short TTL); it flips to `Active` atomically with the first
/// passkey. Only `Active` accounts may authenticate or authorize RPs — this is
/// the authoritative gate, re-checked on every read of a user. `Deleting` is
/// the tombstone written before account deletion cascades: if the cascade is
/// interrupted, the account is already unusable rather than half-deleted but
/// live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Pending,
    #[default]
    Active,
    Deleting,
}

impl AccountStatus {
    /// The wire/storage form (matches the serde `snake_case` renaming).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Deleting => "deleting",
        }
    }
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
    /// Set when a recovery code was redeemed while older passkeys were still
    /// registered: the account owner must review (keep or delete) each of
    /// them before `/oauth/authorize` will issue codes again — the recovery
    /// scenario is exactly the one where an existing passkey may be in a
    /// thief's hands.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending_credential_review: bool,
}

impl User {
    pub fn is_active(&self) -> bool {
        matches!(self.status, AccountStatus::Active)
    }
}
