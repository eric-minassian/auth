//! Sink for CSP and Trusted-Types violation reports.
//!
//! The SPA ships `Content-Security-Policy: ... report-to csp-endpoint` and a
//! `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'`
//! header pointed here (via `Reporting-Endpoints`). Collecting the reports is
//! the prerequisite for ever flipping Trusted Types from Report-Only to
//! enforced: it tells us whether react-dom / Radix / sonner actually touch a
//! TT-guarded sink in production before we'd risk breaking the app.
//!
//! The endpoint is unauthenticated and CSRF-exempt (browsers POST reports
//! cross-context, without cookies, with a non-JSON content type), so it is
//! rate-limited, body-bounded, and strictly log-only — a report is never
//! trusted, parsed into behavior, or echoed back.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;

use super::rate_ip_key;
use crate::state::AppState;
use crate::store::rate_limit::RateClass;

const MAX_REPORT_BYTES: usize = 16 * 1024;
const MAX_SUMMARY_CHARS: usize = 512;

/// POST /api/reports — accept a CSP / Trusted-Types report and log a bounded
/// summary. Always answers `204` (no error oracle for an abusive client).
pub async fn reports(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let ip = rate_ip_key(&headers);
    // Fail closed on a store error: better to drop a report than let an
    // unauthenticated endpoint flood the logs.
    if !state
        .store
        .rate_allow(RateClass::ReportsIp, &ip)
        .await
        .unwrap_or(false)
    {
        return StatusCode::NO_CONTENT;
    }
    if body.is_empty() || body.len() > MAX_REPORT_BYTES {
        return StatusCode::NO_CONTENT;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&body) {
        let mut summary = summarize(&value);
        summary.truncate(MAX_SUMMARY_CHARS);
        tracing::warn!(target: "audit", event = "csp_report", report = %summary);
    }
    StatusCode::NO_CONTENT
}

/// Pull the violated directive(s) + blocked target from either the Reporting
/// API array (`[{type, body:{effectiveDirective, blockedURL, sample}}]`) or the
/// legacy single `{"csp-report": {"violated-directive", "blocked-uri"}}` shape.
/// Returns a compact, non-verbatim summary for observation.
fn summarize(value: &Value) -> String {
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .filter_map(|item| item.get("body").map(summarize_body))
            .collect::<Vec<_>>()
            .join("; ");
    }
    if let Some(legacy) = value.get("csp-report") {
        let directive = str_field(legacy, "violated-directive").unwrap_or("?");
        let blocked = str_field(legacy, "blocked-uri").unwrap_or("?");
        return format!("{directive} blocked={blocked}");
    }
    "unrecognized report".to_string()
}

fn summarize_body(body: &Value) -> String {
    let directive = str_field(body, "effectiveDirective")
        .or_else(|| str_field(body, "violatedDirective"))
        .unwrap_or("?");
    let blocked = str_field(body, "blockedURL").unwrap_or("?");
    match str_field(body, "sample") {
        Some(sample) => format!("{directive} blocked={blocked} sample={sample}"),
        None => format!("{directive} blocked={blocked}"),
    }
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}
