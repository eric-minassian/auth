use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const ACCESS_TOKEN_TTL_SECS: i64 = 10 * 60;
pub const ID_TOKEN_TTL_SECS: i64 = 10 * 60;
pub const LOGOUT_TOKEN_TTL_SECS: i64 = 2 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub sid: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub auth_time: i64,
    pub sid: String,
    pub amr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// OIDC Back-Channel Logout 1.0 token. Spec: MUST contain the events claim,
/// MUST NOT contain a nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub sid: String,
    pub events: Map<String, Value>,
}

impl LogoutTokenClaims {
    pub fn backchannel_event() -> Map<String, Value> {
        let mut events = Map::new();
        events.insert(
            "http://schemas.openid.net/event/backchannel-logout".to_string(),
            Value::Object(Map::new()),
        );
        events
    }
}
