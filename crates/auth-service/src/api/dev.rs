use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::email::Mailer;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LastOtpQuery {
    pub email: String,
}

/// GET /api/dev/last-otp — dev mode only (route is not mounted otherwise).
/// Lets Playwright fetch the OTP that was "emailed" to stdout.
pub async fn last_otp(
    State(state): State<AppState>,
    Query(query): Query<LastOtpQuery>,
) -> Result<Json<Value>, ApiError> {
    let Mailer::Stdout(mailer) = &*state.mailer else {
        return Err(ApiError::NotFound);
    };
    let body = mailer.last_for(&query.email).ok_or(ApiError::NotFound)?;
    let code = extract_otp(&body).ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "code": code })))
}

fn extract_otp(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut run_start = None;
    for (i, b) in bytes.iter().enumerate() {
        if b.is_ascii_digit() {
            let start = *run_start.get_or_insert(i);
            if i - start + 1 == 6 {
                let next_is_digit = bytes.get(i + 1).is_some_and(|n| n.is_ascii_digit());
                if !next_is_digit {
                    return text.get(start..=i).map(str::to_string);
                }
            }
        } else {
            run_start = None;
        }
    }
    None
}
