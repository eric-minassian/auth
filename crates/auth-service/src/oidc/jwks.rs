use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

/// GET /.well-known/jwks.json
///
/// Cache headers are tuned to the verifier defaults (jose: 10-min cache,
/// refetch on unknown kid) and to the publish-before-sign rotation procedure.
/// With KMS keyring rotation (infra milestone) this serves next+current+
/// retired keys from the KEYRING items.
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CACHE_CONTROL,
            "public, max-age=600, stale-while-revalidate=60, stale-if-error=86400",
        )],
        Json(json!({ "keys": [state.signer.public_jwk()] })),
    )
}
