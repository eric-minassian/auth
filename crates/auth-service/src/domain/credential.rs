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

impl StoredPasskey {
    /// Backup Eligibility (BE) flag: the credential is multi-device-capable
    /// (i.e. a *syncable* passkey) rather than bound to one device. A WebAuthn
    /// hint only — surfaced informationally, never as a security guarantee.
    pub fn backup_eligible(&self) -> Option<bool> {
        self.backup_flag("backup_eligible")
    }

    /// Backup State (BS) flag: the credential is currently backed up / synced.
    pub fn backup_state(&self) -> Option<bool> {
        self.backup_flag("backup_state")
    }

    /// Probe the serialized credential for a backup flag. Tolerant of the
    /// webauthn-rs JSON shape (`cred.<flag>` today) and of the field being
    /// absent — returns `None` rather than guessing, so this stays purely
    /// informational and version-robust.
    fn backup_flag(&self, field: &str) -> Option<bool> {
        let value = serde_json::to_value(&self.passkey).ok()?;
        value
            .get("cred")
            .and_then(|cred| cred.get(field))
            .or_else(|| value.get(field))
            .and_then(serde_json::Value::as_bool)
    }
}
