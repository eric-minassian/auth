use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, StoreError, map_sdk_err, n, now, s, schema::GSI1};
use crate::crypto::{random_b64u, sha256_b64u};
use crate::domain::session::{
    ENROLL_SESSION_SECS, IdpSession, SESSION_ABSOLUTE_SECS, SESSION_IDLE_SECS, SessionLevel,
};

#[derive(Serialize, Deserialize)]
struct SessionItem {
    #[serde(rename = "PK")]
    pk: String,
    #[serde(rename = "SK")]
    sk: String,
    #[serde(rename = "GSI1PK")]
    gsi1pk: String,
    #[serde(rename = "GSI1SK")]
    gsi1sk: String,
    ttl: i64,
    #[serde(flatten)]
    session: IdpSession,
}

fn session_pk(sid_hash: &str) -> String {
    format!("SESSION#{sid_hash}")
}

impl Store {
    /// Create a session; returns the plaintext sid (cookie value) exactly once.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        level: SessionLevel,
        amr: Vec<String>,
        device: Option<String>,
        region: Option<String>,
    ) -> Result<(String, IdpSession), StoreError> {
        let sid = random_b64u(32);
        let sid_hash = sha256_b64u(&sid);
        let ts = now();
        let (idle, absolute) = match level {
            SessionLevel::Enroll => (ENROLL_SESSION_SECS, ENROLL_SESSION_SECS),
            SessionLevel::Full => (SESSION_IDLE_SECS, SESSION_ABSOLUTE_SECS),
        };
        let session = IdpSession {
            sid_hash: sid_hash.clone(),
            user_id,
            level,
            created_at: ts,
            last_seen_at: ts,
            idle_expires_at: ts + idle,
            absolute_expires_at: ts + absolute,
            amr,
            // Full sessions are only ever minted by a fresh login assertion, so
            // creation time is a valid "last verified" stamp. Enroll sessions
            // carry no assertion.
            reauth_at: match level {
                SessionLevel::Full => ts,
                SessionLevel::Enroll => 0,
            },
            device,
            region,
        };
        let item = serde_dynamo::to_item(SessionItem {
            pk: session_pk(&sid_hash),
            sk: "SESSION".to_string(),
            gsi1pk: format!("USER#{user_id}"),
            gsi1sk: format!("SESSION#{ts}#{sid_hash}"),
            ttl: session.absolute_expires_at + 7 * 24 * 3600,
            session: session.clone(),
        })?;
        self.db
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok((sid, session))
    }

    /// Look up by plaintext sid (from the cookie). Expired sessions are
    /// treated as absent (TTL is GC, not enforcement).
    pub async fn get_session(&self, sid: &str) -> Result<Option<IdpSession>, StoreError> {
        let session = self.get_session_by_hash(&sha256_b64u(sid)).await?;
        Ok(session.filter(|s| !s.is_expired(now())))
    }

    pub async fn get_session_by_hash(
        &self,
        sid_hash: &str,
    ) -> Result<Option<IdpSession>, StoreError> {
        let result = self
            .db
            .get_item()
            .table_name(&self.table)
            .key("PK", s(session_pk(sid_hash)))
            .key("SK", s("SESSION"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        match result.item {
            Some(item) => {
                let item: SessionItem = serde_dynamo::from_item(item)?;
                Ok(Some(item.session))
            }
            None => Ok(None),
        }
    }

    /// Rolling idle-window bump; called from authenticated request paths when
    /// the session hasn't been touched recently. Absolute expiry never moves.
    pub async fn touch_session(&self, sid_hash: &str) -> Result<(), StoreError> {
        let ts = now();
        self.db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(session_pk(sid_hash)))
            .key("SK", s("SESSION"))
            .update_expression("SET last_seen_at = :now, idle_expires_at = :idle")
            .condition_expression("attribute_exists(PK) AND absolute_expires_at > :now")
            .expression_attribute_values(":now", n(ts))
            .expression_attribute_values(":idle", n(ts + SESSION_IDLE_SECS))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }

    /// Stamp a fresh step-up assertion onto an existing (live) session. Used by
    /// the WebAuthn re-auth ceremony so subsequent sensitive operations (e.g.
    /// generating recovery codes) can require a recent assertion.
    pub async fn set_session_reauth(&self, sid_hash: &str, ts: i64) -> Result<(), StoreError> {
        self.db
            .update_item()
            .table_name(&self.table)
            .key("PK", s(session_pk(sid_hash)))
            .key("SK", s("SESSION"))
            .update_expression("SET reauth_at = :ts")
            .condition_expression("attribute_exists(PK) AND absolute_expires_at > :now")
            .expression_attribute_values(":ts", n(ts))
            .expression_attribute_values(":now", n(now()))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }

    pub async fn delete_session(&self, sid_hash: &str) -> Result<(), StoreError> {
        self.db
            .delete_item()
            .table_name(&self.table)
            .key("PK", s(session_pk(sid_hash)))
            .key("SK", s("SESSION"))
            .send()
            .await
            .map_err(map_sdk_err)?;
        Ok(())
    }

    /// All live sessions for a user (account page, logout-everywhere).
    pub async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<IdpSession>, StoreError> {
        let ts = now();
        let result = self
            .db
            .query()
            .table_name(&self.table)
            .index_name(GSI1)
            .key_condition_expression("GSI1PK = :pk AND begins_with(GSI1SK, :prefix)")
            .expression_attribute_values(":pk", AttributeValue::S(format!("USER#{user_id}")))
            .expression_attribute_values(":prefix", AttributeValue::S("SESSION#".to_string()))
            .send()
            .await
            .map_err(map_sdk_err)?;
        let mut sessions = Vec::new();
        for item in result.items.unwrap_or_default() {
            let item: SessionItem = serde_dynamo::from_item(item)?;
            if !item.session.is_expired(ts) {
                sessions.push(item.session);
            }
        }
        Ok(sessions)
    }
}
