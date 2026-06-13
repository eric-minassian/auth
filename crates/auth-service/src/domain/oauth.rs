use serde::{Deserialize, Serialize};

pub const SCOPE_OPENID: &str = "openid";
pub const SCOPE_EMAIL: &str = "email";
pub const SCOPE_OFFLINE_ACCESS: &str = "offline_access";
pub const SUPPORTED_SCOPES: &[&str] = &[SCOPE_OPENID, SCOPE_EMAIL, SCOPE_OFFLINE_ACCESS];

pub const AUTH_CODE_TTL_SECS: i64 = 60;
pub const REFRESH_IDLE_SECS: i64 = 30 * 24 * 3600;
pub const REFRESH_ABSOLUTE_SECS: i64 = 90 * 24 * 3600;

/// A registered OIDC client. Public clients only (`token_endpoint_auth_method:
/// none`) — every client must use PKCE S256. Source of truth is
/// config/clients.json, seeded into DynamoDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    pub client_id: String,
    pub client_name: String,
    /// Exact-match redirect URIs (no wildcards, no fragments).
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// Origins allowed to call the token/revoke endpoints from a browser.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    pub scopes: Vec<String>,
}

impl OidcClient {
    pub fn allows_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    pub fn allows_scopes(&self, requested: &str) -> bool {
        requested
            .split_ascii_whitespace()
            .all(|s| self.scopes.iter().any(|cs| cs == s))
    }
}

/// Space-delimited scope helper.
pub fn scope_contains(scope: &str, wanted: &str) -> bool {
    scope.split_ascii_whitespace().any(|s| s == wanted)
}
