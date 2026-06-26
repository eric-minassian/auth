//! GET /.well-known/security.txt — RFC 9116 vulnerability-disclosure metadata.
//!
//! Served by the Lambda alongside the other `/.well-known` resources (that
//! path prefix is routed to the API origin, not the SPA bucket). `Expires` is
//! computed fresh on each render (now + 180 days) so the file can never go
//! stale; `Contact` is an email-free GitHub disclosure channel, in keeping with
//! the no-email design.

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::state::AppState;

const EXPIRES_DAYS: i64 = 180;

pub async fn security_txt(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = &state.cfg.issuer;
    let expires = (OffsetDateTime::now_utc() + time::Duration::days(EXPIRES_DAYS))
        .format(&Rfc3339)
        .unwrap_or_default();
    let body = format!(
        "Contact: https://github.com/eric-minassian/auth/security/advisories/new\n\
         Expires: {expires}\n\
         Preferred-Languages: en\n\
         Canonical: {issuer}/.well-known/security.txt\n\
         Policy: https://github.com/eric-minassian/auth/security/policy\n"
    );
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        body,
    )
}
