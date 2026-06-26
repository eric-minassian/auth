use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `Enroll` sessions are created by signup (against a pending account) or by
/// recovery-code redemption, and may only call passkey-registration endpoints.
/// `Full` sessions are created *exclusively* by a successful WebAuthn assertion
/// (`login/finish`). Registering a passkey never elevates a session, so a
/// `Full` session always implies a verified, user-verified passkey assertion —
/// which is what `/oauth/authorize` relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLevel {
    Enroll,
    Full,
}

pub const SESSION_IDLE_SECS: i64 = 30 * 24 * 3600;
pub const SESSION_ABSOLUTE_SECS: i64 = 90 * 24 * 3600;
pub const ENROLL_SESSION_SECS: i64 = 30 * 60;
/// A WebAuthn step-up assertion must be at least this recent to authorize a
/// sensitive operation (generating recovery codes, or adding a passkey from an
/// already-established full session).
pub const REAUTH_FRESHNESS_SECS: i64 = 5 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpSession {
    pub sid_hash: String,
    pub user_id: Uuid,
    pub level: SessionLevel,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
    /// Authentication methods: ["pending"] / ["recovery"] for enroll sessions,
    /// ["webauthn"] for full sessions.
    pub amr: Vec<String>,
    /// Unix time of the most recent fresh WebAuthn assertion on this session
    /// (initial login or an explicit step-up). Sensitive operations such as
    /// generating recovery codes require this to be recent.
    #[serde(default)]
    pub reauth_at: i64,
    /// Coarse "Browser on OS" label derived from the User-Agent at sign-in —
    /// the only device-awareness channel in an email-free model. Display only;
    /// never an identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Coarse region (CloudFront-Viewer-Country ISO code) at sign-in. Country,
    /// not IP, to keep the anti-fingerprinting/privacy posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl IdpSession {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.idle_expires_at || now >= self.absolute_expires_at
    }
}
