use aws_sdk_dynamodb::types::AttributeValue;

use super::{Store, StoreError, map_sdk_err, now, s};

/// Fixed-window rate-limit classes. Limits are deliberately generous for a
/// personal service; the API Gateway stage throttle is the global backstop.
///
/// IP-keyed classes are keyed on a /64 prefix for IPv6 (see
/// [`crate::api::rate_ip_key`]) so a single allocation can't rotate the key,
/// and are paired with per-ASN classes because IP-only limiting is defeated by
/// CGNAT and proxy pools. None of these are global caps — a flood can raise
/// cost but can never deny signup or recovery to the whole user base.
#[derive(Debug, Clone, Copy)]
pub enum RateClass {
    /// Signup attempts per client IP (/64).
    SignupIp,
    /// Signup attempts per origin ASN.
    SignupAsn,
    /// Recovery-code redemption attempts per client IP (/64).
    RecoveryIp,
    /// Recovery-code redemption attempts per origin ASN.
    RecoveryAsn,
    /// Failed login finishes per client IP (/64).
    LoginIp,
    /// Token endpoint per client IP (/64).
    TokenIp,
    /// Mutating account-management calls per session.
    AccountSession,
}

impl RateClass {
    fn name(self) -> &'static str {
        match self {
            Self::SignupIp => "signup-ip",
            Self::SignupAsn => "signup-asn",
            Self::RecoveryIp => "recovery-ip",
            Self::RecoveryAsn => "recovery-asn",
            Self::LoginIp => "login-ip",
            Self::TokenIp => "token-ip",
            Self::AccountSession => "account-session",
        }
    }

    /// (max requests, window seconds)
    fn limit(self) -> (i64, i64) {
        match self {
            Self::SignupIp => (30, 3600),
            Self::SignupAsn => (300, 3600),
            Self::RecoveryIp => (20, 3600),
            Self::RecoveryAsn => (200, 3600),
            Self::LoginIp => (20, 3600),
            Self::TokenIp => (60, 60),
            Self::AccountSession => (30, 3600),
        }
    }
}

impl Store {
    /// Returns true if the request is allowed. Over-limit requests still cost
    /// one cheap WCU — acceptable; the API Gateway throttle bounds the worst
    /// case.
    pub async fn rate_allow(&self, class: RateClass, key: &str) -> Result<bool, StoreError> {
        let (max, window) = class.limit();
        let ts = now();
        let window_start = ts - ts % window;
        let result = self
            .db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(format!("RL#{}#{key}", class.name())))
            .key("SK", s(format!("W#{window_start}")))
            .update_expression("ADD #count :one SET #ttl = if_not_exists(#ttl, :ttl)")
            .expression_attribute_names("#count", "count")
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(":one", AttributeValue::N("1".to_string()))
            .expression_attribute_values(
                ":ttl",
                AttributeValue::N((window_start + window + 3600).to_string()),
            )
            .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
            .send()
            .await
            .map_err(map_sdk_err)?;
        let count = result
            .attributes
            .and_then(|a| a.get("count").and_then(|v| v.as_n().ok().cloned()))
            .and_then(|n| n.parse::<i64>().ok())
            .unwrap_or(i64::MAX);
        Ok(count <= max)
    }
}
