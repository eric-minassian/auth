//! Discovery documents (protocol §10.1).

use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

fn cacheable(body: serde_json::Value) -> Response {
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp
}

/// RFC 8414 authorization server metadata.
pub async fn metadata(State(state): State<AppState>) -> Response {
    let iss = &state.config.issuer;
    cacheable(json!({
        "issuer": iss,
        "token_endpoint": format!("{iss}/v1/token"),
        "jwks_uri": format!("{iss}/.well-known/jwks.json"),
        "grant_types_supported": ["refresh_token"],
        "response_types_supported": [],
        "token_endpoint_auth_methods_supported": ["none"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": false
    }))
}

/// RFC 7517 JWK Set of the access-token keys.
pub async fn jwks(State(state): State<AppState>) -> Response {
    let keys: Vec<_> = state
        .access_keys
        .iter()
        .map(crate::kms::PublicKey::jwk)
        .collect();
    cacheable(json!({ "keys": keys }))
}
