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
use axum::routing::{delete, get, patch, post};
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
        .route("/api/session/logout", post(api::session::logout))
        .route(
            "/api/webauthn/register/start",
            post(api::webauthn::register_start),
        )
        .route(
            "/api/webauthn/register/finish",
            post(api::webauthn::register_finish),
        )
        .route(
            "/api/webauthn/login/start",
            post(api::webauthn::login_start),
        )
        .route(
            "/api/webauthn/login/finish",
            post(api::webauthn::login_finish),
        )
        .route("/api/account/passkeys", get(api::account::list_passkeys))
        .route(
            "/api/account/passkeys/{credential_id}",
            patch(api::account::rename_passkey).delete(api::account::delete_passkey),
        )
        .route("/api/account/sessions", get(api::account::list_sessions))
        .route(
            "/api/account/sessions/{session_id}",
            delete(api::account::revoke_session),
        );

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
