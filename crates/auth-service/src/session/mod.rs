pub mod extract;

use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

use crate::config::AppConfig;
use crate::domain::session::SESSION_IDLE_SECS;

/// Host-only session cookie (`__Host-` prefixed in prod). Never sets `Domain`:
/// SSO across subdomains rides same-site /oauth/authorize navigations, not a
/// shared-domain cookie.
pub fn session_cookie(cfg: &AppConfig, sid: String) -> Cookie<'static> {
    Cookie::build((cfg.cookie_name.clone(), sid))
        .path("/")
        .secure(cfg.cookie_secure)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(SESSION_IDLE_SECS))
        .build()
}

pub fn clear_session_cookie(cfg: &AppConfig) -> Cookie<'static> {
    Cookie::build((cfg.cookie_name.clone(), ""))
        .path("/")
        .secure(cfg.cookie_secure)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(0))
        .build()
}
