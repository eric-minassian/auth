use std::env;

use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    /// Public origin of the service, e.g. `https://auth.ericminassian.com`.
    /// Also the OIDC issuer, the WebAuthn relying-party origin, and the only
    /// Origin accepted by the CSRF check.
    pub issuer: String,
    pub table_name: String,
    /// WebAuthn relying-party id: the issuer host (no scheme/port).
    pub rp_id: String,
    pub rp_origin: Url,
    pub cookie_name: String,
    pub cookie_secure: bool,
    /// Endpoint override for DynamoDB Local.
    pub dynamodb_endpoint: Option<String>,
    /// Shared secret CloudFront injects as the `x-origin-verify` header. When
    /// set, requests lacking a matching value are rejected (origin lock). Unset
    /// in local dev / tests, where the middleware is a no-op.
    pub origin_verify_secret: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer = env::var("ISSUER").map_err(|_| ConfigError::Missing("ISSUER"))?;
        let table_name = env::var("TABLE_NAME").map_err(|_| ConfigError::Missing("TABLE_NAME"))?;
        Self::build(issuer, table_name, env::var("DYNAMODB_ENDPOINT").ok())
    }

    pub fn build(
        issuer: String,
        table_name: String,
        dynamodb_endpoint: Option<String>,
    ) -> Result<Self, ConfigError> {
        let issuer = issuer.trim_end_matches('/').to_string();
        let rp_origin = Url::parse(&issuer).map_err(|e| ConfigError::Invalid {
            name: "ISSUER",
            message: e.to_string(),
        })?;
        let rp_id = rp_origin
            .host_str()
            .ok_or(ConfigError::Invalid {
                name: "ISSUER",
                message: "no host".to_string(),
            })?
            .to_string();
        let cookie_secure = rp_origin.scheme() == "https";
        // __Host- requires Secure, so the prefix is only usable over https.
        let cookie_name = if cookie_secure {
            "__Host-auth_session".to_string()
        } else {
            "auth_session".to_string()
        };
        Ok(Self {
            issuer,
            table_name,
            rp_id,
            rp_origin,
            cookie_name,
            cookie_secure,
            dynamodb_endpoint,
            origin_verify_secret: env::var("ORIGIN_VERIFY_SECRET").ok(),
        })
    }
}
