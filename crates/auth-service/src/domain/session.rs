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

/// OIDC `acr` (Authentication Context Class Reference) values this provider
/// emits. A `Full` session is *always* phishing-resistant — it can only be
/// minted by a user-verified WebAuthn assertion (`login/finish`) — so
/// [`ACR_PHISHING_RESISTANT`] is the baseline reported on every issued token.
/// A session whose most recent assertion is within [`REAUTH_FRESHNESS_SECS`]
/// additionally satisfies the stepped-up level, which a relying party can demand
/// (via `acr_values`, RFC 9470) before authorizing a sensitive operation.
pub const ACR_PHISHING_RESISTANT: &str = "phr";
pub const ACR_PHISHING_RESISTANT_STEPUP: &str = "phr-stepup";

/// Result of matching a session against an RP's requested `acr_values`.
pub enum AcrOutcome {
    /// The session satisfies the request; stamp this acr on the tokens.
    Granted(&'static str),
    /// The request can only be met by a fresh assertion — route to a step-up
    /// (full re-login), exactly like `prompt=login`.
    StepUp,
}

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
    /// The credential (base64url id) whose assertion established — or most
    /// recently stepped up — this session. `None` for enroll sessions (no
    /// assertion yet) and for sessions minted before this field existed.
    /// Deleting a passkey revokes every session bound to it (CAEP
    /// credential-change semantics, applied locally).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

impl IdpSession {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.idle_expires_at || now >= self.absolute_expires_at
    }

    /// Whether the most recent user-verified assertion on this session is recent
    /// enough to count as "stepped up". The `grace` floor absorbs the
    /// sign-in → authorize redirect round-trip (a login that *just* completed
    /// must satisfy a step-up ask without bouncing back to sign-in forever).
    pub fn is_stepped_up(&self, now: i64, grace: i64) -> bool {
        now - self.reauth_at <= REAUTH_FRESHNESS_SECS || now - self.created_at <= grace
    }

    /// Resolve the RP's requested `acr_values` (space-delimited, preference
    /// order) against this session. With no request, reports the honest baseline
    /// ([`ACR_PHISHING_RESISTANT`]). Returns [`AcrOutcome::StepUp`] *only* when a
    /// fresh assertion would actually change the answer (the stepped-up level was
    /// asked for and isn't currently satisfied) — never for an `acr` we
    /// structurally cannot satisfy, which would loop the browser forever; those
    /// fall back to best-effort baseline.
    pub fn resolve_acr(&self, requested: &[&str], now: i64, grace: i64) -> AcrOutcome {
        if requested.is_empty() {
            return AcrOutcome::Granted(ACR_PHISHING_RESISTANT);
        }
        let stepped_up = self.is_stepped_up(now, grace);
        for value in requested {
            match *value {
                ACR_PHISHING_RESISTANT => return AcrOutcome::Granted(ACR_PHISHING_RESISTANT),
                ACR_PHISHING_RESISTANT_STEPUP if stepped_up => {
                    return AcrOutcome::Granted(ACR_PHISHING_RESISTANT_STEPUP);
                }
                _ => {}
            }
        }
        // Nothing satisfiable now. A fresh assertion only helps if the stepped-up
        // level was requested; otherwise honor the baseline rather than loop.
        if requested.contains(&ACR_PHISHING_RESISTANT_STEPUP) {
            AcrOutcome::StepUp
        } else {
            AcrOutcome::Granted(ACR_PHISHING_RESISTANT)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const GRACE: i64 = 60;

    fn session(created_at: i64, reauth_at: i64) -> IdpSession {
        IdpSession {
            sid_hash: "h".to_string(),
            user_id: Uuid::nil(),
            level: SessionLevel::Full,
            created_at,
            last_seen_at: created_at,
            idle_expires_at: created_at + SESSION_IDLE_SECS,
            absolute_expires_at: created_at + SESSION_ABSOLUTE_SECS,
            amr: vec!["webauthn".to_string()],
            reauth_at,
            device: None,
            region: None,
            credential_id: None,
        }
    }

    fn granted(outcome: AcrOutcome) -> Option<&'static str> {
        match outcome {
            AcrOutcome::Granted(acr) => Some(acr),
            AcrOutcome::StepUp => None,
        }
    }

    #[test]
    fn no_request_reports_phishing_resistant_baseline() {
        let stale = session(NOW - 3600, NOW - 3600);
        assert_eq!(granted(stale.resolve_acr(&[], NOW, GRACE)), Some("phr"));
    }

    #[test]
    fn phr_is_satisfied_by_any_full_session() {
        let stale = session(NOW - 3600, NOW - 3600);
        assert_eq!(
            granted(stale.resolve_acr(&["phr"], NOW, GRACE)),
            Some("phr")
        );
    }

    #[test]
    fn stepup_is_satisfied_only_when_the_assertion_is_recent() {
        let fresh = session(NOW - 3600, NOW - 60); // reauth 60s ago (< 5 min)
        assert_eq!(
            granted(fresh.resolve_acr(&["phr-stepup"], NOW, GRACE)),
            Some("phr-stepup")
        );

        let stale = session(NOW - 3600, NOW - 3600); // reauth 1h ago
        assert!(matches!(
            stale.resolve_acr(&["phr-stepup"], NOW, GRACE),
            AcrOutcome::StepUp
        ));
    }

    #[test]
    fn grace_floor_covers_a_just_completed_login() {
        // reauth old, but the session was created within the redirect round-trip.
        let just_logged_in = session(NOW - 30, NOW - 3600);
        assert_eq!(
            granted(just_logged_in.resolve_acr(&["phr-stepup"], NOW, GRACE)),
            Some("phr-stepup")
        );
    }

    #[test]
    fn prefers_an_acceptable_lower_value_over_stepping_up() {
        let stale = session(NOW - 3600, NOW - 3600);
        // `phr` is acceptable right now, so no step-up despite phr-stepup first.
        assert_eq!(
            granted(stale.resolve_acr(&["phr-stepup", "phr"], NOW, GRACE)),
            Some("phr")
        );
    }

    #[test]
    fn unknown_acr_falls_back_to_baseline_and_never_loops() {
        let stale = session(NOW - 3600, NOW - 3600);
        assert_eq!(
            granted(stale.resolve_acr(&["urn:example:unknown"], NOW, GRACE)),
            Some("phr")
        );
    }
}
