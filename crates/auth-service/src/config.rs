//! Service configuration from environment variables (protocol §13).
//!
//! Every value is validated at startup; a misconfigured service refuses to
//! start rather than running with weaker checks.

use std::net::SocketAddr;

/// A configuration error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid configuration: {0}")]
pub struct ConfigError(pub String);

/// Validated service configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// `AUTH_ISSUER`: public origin of the service, no path.
    pub issuer: String,
    /// `AUTH_RP_ID`.
    pub rp_id: String,
    /// `AUTH_RP_NAME`.
    pub rp_name: String,
    /// `AUTH_ALLOWED_ORIGINS`: WebAuthn origins, matched exactly.
    pub allowed_origins: Vec<String>,
    /// `AUTH_CORS_ORIGINS`: browser origins allowed by CORS.
    pub cors_origins: Vec<String>,
    /// `AUTH_AUDIENCES`: allowed resources; the first is the default. The
    /// issuer (account API) is always allowed in addition.
    pub audiences: Vec<String>,
    /// `AUTH_CLIENT_IDS`.
    pub client_ids: Vec<String>,
    /// `AUTH_TABLE_NAME`.
    pub table_name: String,
    /// `AUTH_ACCESS_TOKEN_KEY_ID`.
    pub access_token_key_id: String,
    /// `AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS`.
    pub access_token_previous_key_ids: Vec<String>,
    /// `AUTH_REFRESH_TOKEN_KEY_ID`.
    pub refresh_token_key_id: String,
    /// `AUTH_REFRESH_TOKEN_PREVIOUS_KEY_IDS`.
    pub refresh_token_previous_key_ids: Vec<String>,
    /// `AUTH_DPOP_NONCE_KEY_ID`.
    pub dpop_nonce_key_id: String,
    /// `AUTH_LISTEN_ADDR` (local mode only).
    pub listen_addr: SocketAddr,
    /// Running outside Lambda. Only then are `http://localhost` URLs allowed.
    pub local_mode: bool,
}

fn list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn is_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Splits `scheme://host[:port]` (no path, query, fragment or userinfo).
fn origin_parts(origin: &str) -> Option<(&str, &str, Option<u16>)> {
    let (scheme, rest) = origin.split_once("://")?;
    if rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().ok().filter(|p| *p != 0)?)),
        None => (rest, None),
    };
    is_host(host).then_some((scheme, host, port))
}

fn is_local_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1"
}

/// A web origin: `https://host[:port]`, or `http://localhost[:port]` in local mode.
fn web_origin_ok(origin: &str, local: bool) -> Option<&str> {
    let (scheme, host, port) = origin_parts(origin)?;
    let default_port = matches!((scheme, port), ("https", Some(443)) | ("http", Some(80)));
    match scheme {
        _ if default_port => None, // must be written without the default port
        "https" => Some(host),
        "http" if local && is_local_host(host) => Some(host),
        _ => None,
    }
}

/// Whether `host` is `rp_id` or a subdomain of it (WebAuthn §5.1.4.1).
fn host_matches_rp_id(host: &str, rp_id: &str) -> bool {
    host == rp_id || host.strip_suffix(rp_id).is_some_and(|p| p.ends_with('.'))
}

fn android_origin_ok(origin: &str) -> bool {
    origin
        .strip_prefix("android:apk-key-hash:")
        .and_then(auth_core::b64::decode_str)
        .is_some_and(|h| h.len() == 32)
}

impl Config {
    /// Loads the configuration from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let local_mode = std::env::var_os("AWS_LAMBDA_RUNTIME_API").is_none();
        Self::from_lookup(|k| std::env::var(k).ok(), local_mode)
    }

    /// Loads the configuration from an arbitrary lookup (used by tests).
    pub fn from_lookup(
        get: impl Fn(&str) -> Option<String>,
        local_mode: bool,
    ) -> Result<Self, ConfigError> {
        let req = |k: &str| -> Result<String, ConfigError> {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| ConfigError(format!("{k} is required")))
        };
        let opt_list = |k: &str| get(k).map(|v| list(&v)).unwrap_or_default();

        let issuer = req("AUTH_ISSUER")?;
        if web_origin_ok(&issuer, local_mode).is_none() {
            return Err(ConfigError(
                "AUTH_ISSUER must be an https origin without path, query, fragment or default port"
                    .into(),
            ));
        }

        let rp_id = req("AUTH_RP_ID")?;
        if !is_host(&rp_id) {
            return Err(ConfigError(
                "AUTH_RP_ID must be a lowercase domain name".into(),
            ));
        }
        let rp_name = req("AUTH_RP_NAME")?;
        if rp_name.chars().count() > 64 || rp_name.chars().any(char::is_control) {
            return Err(ConfigError(
                "AUTH_RP_NAME must be at most 64 printable characters".into(),
            ));
        }

        let allowed_origins = list(&req("AUTH_ALLOWED_ORIGINS")?);
        for o in &allowed_origins {
            let ok = match web_origin_ok(o, local_mode) {
                Some(host) => {
                    host_matches_rp_id(host, &rp_id) || (local_mode && is_local_host(host))
                }
                None => android_origin_ok(o),
            };
            if !ok {
                return Err(ConfigError(format!(
                    "AUTH_ALLOWED_ORIGINS entry {o:?} is not an https origin within the RP ID or an android:apk-key-hash origin"
                )));
            }
        }

        let cors_origins = opt_list("AUTH_CORS_ORIGINS");
        for o in &cors_origins {
            if web_origin_ok(o, local_mode).is_none() {
                return Err(ConfigError(format!(
                    "AUTH_CORS_ORIGINS entry {o:?} is not a web origin"
                )));
            }
        }

        let audiences = list(&req("AUTH_AUDIENCES")?);
        for a in &audiences {
            if !(a.starts_with("https://") || (local_mode && a.starts_with("http://localhost")))
                || a.contains(['#', '?', ' '])
            {
                return Err(ConfigError(format!(
                    "AUTH_AUDIENCES entry {a:?} must be an https URI"
                )));
            }
        }
        if audiences.is_empty() {
            return Err(ConfigError("AUTH_AUDIENCES must not be empty".into()));
        }

        let client_ids = list(&req("AUTH_CLIENT_IDS")?);
        if client_ids.is_empty()
            || client_ids.iter().any(|c| {
                c.len() > 32
                    || !c.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                    })
            })
        {
            return Err(ConfigError(
                "AUTH_CLIENT_IDS must be short lowercase identifiers".into(),
            ));
        }

        let listen_addr = get("AUTH_LISTEN_ADDR")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .map_err(|_| ConfigError("AUTH_LISTEN_ADDR must be host:port".into()))?;

        Ok(Self {
            issuer,
            rp_id,
            rp_name,
            allowed_origins,
            cors_origins,
            audiences,
            client_ids,
            table_name: req("AUTH_TABLE_NAME")?,
            access_token_key_id: req("AUTH_ACCESS_TOKEN_KEY_ID")?,
            access_token_previous_key_ids: opt_list("AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS"),
            refresh_token_key_id: req("AUTH_REFRESH_TOKEN_KEY_ID")?,
            refresh_token_previous_key_ids: opt_list("AUTH_REFRESH_TOKEN_PREVIOUS_KEY_IDS"),
            dpop_nonce_key_id: req("AUTH_DPOP_NONCE_KEY_ID")?,
            listen_addr,
            local_mode,
        })
    }

    /// Whether `aud` may be requested (RFC 8707).
    pub fn audience_allowed(&self, aud: &str) -> bool {
        aud == self.issuer || self.audiences.iter().any(|a| a == aud)
    }

    /// The default audience.
    pub fn default_audience(&self) -> &str {
        self.audiences
            .first()
            .map_or(self.issuer.as_str(), String::as_str)
    }

    /// Whether `client_id` is allowed.
    pub fn client_allowed(&self, client_id: &str) -> bool {
        self.client_ids.iter().any(|c| c == client_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> HashMap<&'static str, &'static str> {
        HashMap::from([
            ("AUTH_ISSUER", "https://auth.example.com"),
            ("AUTH_RP_ID", "example.com"),
            ("AUTH_RP_NAME", "Example"),
            (
                "AUTH_ALLOWED_ORIGINS",
                "https://app.example.com, https://example.com",
            ),
            ("AUTH_CORS_ORIGINS", "https://app.example.com"),
            ("AUTH_AUDIENCES", "https://api.example.com"),
            ("AUTH_CLIENT_IDS", "web,ios,android,cli"),
            ("AUTH_TABLE_NAME", "auth"),
            ("AUTH_ACCESS_TOKEN_KEY_ID", "k1"),
            ("AUTH_REFRESH_TOKEN_KEY_ID", "k2"),
            ("AUTH_DPOP_NONCE_KEY_ID", "k3"),
        ])
    }

    fn load(m: &HashMap<&str, &str>, local: bool) -> Result<Config, ConfigError> {
        Config::from_lookup(|k| m.get(k).map(|v| (*v).to_string()), local)
    }

    #[test]
    fn valid_configuration() {
        let c = load(&base(), false).unwrap();
        assert_eq!(c.allowed_origins.len(), 2);
        assert_eq!(c.default_audience(), "https://api.example.com");
        assert!(c.audience_allowed("https://auth.example.com"));
        assert!(!c.audience_allowed("https://evil.example.com"));
        assert!(c.client_allowed("cli") && !c.client_allowed("other"));
    }

    #[test]
    fn rejects_unsafe_values() {
        let cases: &[(&str, &str)] = &[
            ("AUTH_ISSUER", "http://auth.example.com"),
            ("AUTH_ISSUER", "https://auth.example.com/"),
            ("AUTH_ISSUER", "https://auth.example.com/path"),
            ("AUTH_ISSUER", "https://auth.example.com:443"),
            ("AUTH_ISSUER", "https://user@auth.example.com"),
            ("AUTH_RP_ID", "Example.com"),
            ("AUTH_ALLOWED_ORIGINS", "https://app.example.org"),
            ("AUTH_ALLOWED_ORIGINS", "https://notexample.com"),
            ("AUTH_ALLOWED_ORIGINS", "http://app.example.com"),
            ("AUTH_ALLOWED_ORIGINS", "android:apk-key-hash:short"),
            ("AUTH_CORS_ORIGINS", "*"),
            ("AUTH_AUDIENCES", "api"),
            ("AUTH_CLIENT_IDS", "Web"),
            ("AUTH_TABLE_NAME", ""),
        ];
        for (k, v) in cases {
            let mut m = base();
            m.insert(k, v);
            assert!(load(&m, false).is_err(), "{k}={v} must be rejected");
        }
    }

    #[test]
    fn localhost_only_in_local_mode() {
        let mut m = base();
        m.insert("AUTH_ISSUER", "http://localhost:8080");
        m.insert("AUTH_ALLOWED_ORIGINS", "http://localhost:5173");
        m.insert("AUTH_CORS_ORIGINS", "http://localhost:5173");
        assert!(load(&m, true).is_ok());
        assert!(load(&m, false).is_err());
    }

    #[test]
    fn android_origins() {
        let mut m = base();
        let hash = auth_core::b64::encode(&[7u8; 32]);
        let origin = format!("android:apk-key-hash:{hash}");
        m.insert("AUTH_ALLOWED_ORIGINS", Box::leak(origin.into_boxed_str()));
        assert!(load(&m, false).is_ok());
    }
}
