//! Anonymous, PII-free passkey authentication service.
//!
//! See `docs/protocol.md` for the protocol and `docs/verification.md` for what
//! is formally verified. Every security decision is delegated to the verified
//! `auth_core::decide` module; this crate is the HTTP and storage plumbing.
#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod dpop;
pub mod error;
pub mod http;
pub mod kms;
pub mod options;
pub mod random;
pub mod routes;
pub mod state;
pub mod store;
pub mod tokens;

use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath};
use axum::http::{HeaderName, HeaderValue, Method, Request, header};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

pub use state::AppState;

fn cors(state: &AppState) -> CorsLayer {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("dpop"),
        ])
        .expose_headers([
            HeaderName::from_static("dpop-nonce"),
            header::WWW_AUTHENTICATE,
            header::DATE,
        ])
        .max_age(Duration::from_secs(600))
}

async fn not_found() -> impl IntoResponse {
    error::ApiError::NotFound
}

/// The application router.
pub fn router(state: AppState) -> Router {
    let trace = TraceLayer::new_for_http()
        // Log the route template only: no URI, headers, IP or user agent.
        .make_span_with(|req: &Request<_>| {
            let route = req
                .extensions()
                .get::<MatchedPath>()
                .map_or("unmatched", MatchedPath::as_str);
            tracing::info_span!("request", method = %req.method(), route)
        })
        .on_request(())
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(routes::well_known::metadata),
        )
        .route("/.well-known/jwks.json", get(routes::well_known::jwks))
        .route("/v1/register/options", post(routes::register::options))
        .route("/v1/register/verify", post(routes::register::verify))
        .route("/v1/login/options", post(routes::login::options))
        .route("/v1/login/verify", post(routes::login::verify))
        .route("/v1/token", post(routes::token::token))
        .route("/v1/recover/options", post(routes::recover::options))
        .route("/v1/recover/verify", post(routes::recover::verify))
        .route(
            "/v1/account",
            get(routes::account::get).delete(routes::account::delete),
        )
        .route(
            "/v1/account/passkeys/options",
            post(routes::account::passkey_options),
        )
        .route(
            "/v1/account/passkeys/verify",
            post(routes::account::passkey_verify),
        )
        .route(
            "/v1/account/passkeys/{credential_id}",
            delete(routes::account::passkey_delete),
        )
        .route("/v1/account/logout-all", post(routes::account::logout_all))
        .route(
            "/v1/account/recovery-code",
            post(routes::account::rotate_recovery_code),
        )
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(http::MAX_BODY))
        .layer(trace)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            http::response_headers,
        ))
        .layer(cors(&state))
        .with_state(state)
}
