pub mod api;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod email;
pub mod error;
pub mod jwt;
pub mod middleware;
pub mod session;
pub mod state;
pub mod store;

use axum::Router;
use axum::middleware as axum_middleware;
use axum::routing::{get, post};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/api/healthz", get(api::healthz))
        .route("/api/signup/start", post(api::signup::start))
        .route("/api/signup/verify", post(api::signup::verify))
        .route("/api/recovery/start", post(api::recovery::start))
        .route("/api/recovery/verify", post(api::recovery::verify))
        .route("/api/session", get(api::session::get))
        .route("/api/session/logout", post(api::session::logout));

    if state.cfg.dev_mode {
        router = router.route("/api/dev/last-otp", get(api::dev::last_otp));
    }

    router
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf::enforce,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
