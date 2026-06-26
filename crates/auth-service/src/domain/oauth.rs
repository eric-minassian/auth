use serde::{Deserialize, Serialize};

pub const SCOPE_OPENID: &str = "openid";
pub const SCOPE_PROFILE: &str = "profile";
pub const SCOPE_OFFLINE_ACCESS: &str = "offline_access";
pub const SUPPORTED_SCOPES: &[&str] = &[SCOPE_OPENID, SCOPE_PROFILE, SCOPE_OFFLINE_ACCESS];

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
    /// Require DPoP (RFC 9449) for this client: token requests without a valid
    /// proof are rejected, so every token it holds is sender-constrained.
    /// Default off — flip per client only after it has adopted the DPoP-capable
    /// SDK, or its logins break.
    #[serde(default)]
    pub require_dpop: bool,
}

impl OidcClient {
    pub fn allows_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }
}

/// The scopes actually granted for a request: `requested ∩ client-registered ∩
/// supported`, order-preserving and de-duplicated. Unsupported or unregistered
/// scopes are silently dropped rather than erroring — so a client can never be
/// granted (or even shown) a scope it wasn't registered for (e.g. a refresh
/// token via `offline_access`). The caller separately requires `openid`.
pub fn granted_scopes(requested: &str, client: &OidcClient) -> String {
    let mut out: Vec<&str> = Vec::new();
    for s in requested.split_ascii_whitespace() {
        if SUPPORTED_SCOPES.contains(&s)
            && client.scopes.iter().any(|cs| cs == s)
            && !out.contains(&s)
        {
            out.push(s);
        }
    }
    out.join(" ")
}

/// Space-delimited scope helper.
pub fn scope_contains(scope: &str, wanted: &str) -> bool {
    scope.split_ascii_whitespace().any(|s| s == wanted)
}
