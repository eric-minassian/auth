use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

/// GET /.well-known/jwks.json
///
/// Cache headers are tuned to the verifier defaults (jose: 10-min cache,
/// refetch on unknown kid) and to the publish-before-sign rotation procedure:
/// the keyring serves every published key — standby (next) and retired keys
/// alongside the active one — so a flip never presents a kid verifiers
/// haven't already cached. Rotation runbook: docs/deploy.md.
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CACHE_CONTROL,
            "public, max-age=600, stale-while-revalidate=60, stale-if-error=86400",
        )],
        Json(json!({ "keys": state.signer.public_jwks() })),
    )
}
