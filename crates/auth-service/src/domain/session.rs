use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `Enroll` sessions are created by OTP verification (signup/recovery) and may
/// only call passkey-registration endpoints; `Full` sessions are created by a
/// successful WebAuthn authentication (or by upgrading an enroll session when
/// its first passkey is registered).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLevel {
    Enroll,
    Full,
}

pub const SESSION_IDLE_SECS: i64 = 30 * 24 * 3600;
pub const SESSION_ABSOLUTE_SECS: i64 = 90 * 24 * 3600;
pub const ENROLL_SESSION_SECS: i64 = 30 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpSession {
    pub sid_hash: String,
    pub user_id: Uuid,
    pub level: SessionLevel,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
    /// Authentication methods, e.g. ["otp"] for enroll, ["webauthn"] for full.
    pub amr: Vec<String>,
}

impl IdpSession {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.idle_expires_at || now >= self.absolute_expires_at
    }
}
