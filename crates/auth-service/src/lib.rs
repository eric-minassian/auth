pub mod api;
pub mod config;
pub mod crypto;
pub mod domain;
pub mod error;
pub mod jwt;
pub mod middleware;
pub mod oidc;
pub mod openapi;
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
        .route("/api/signup/pow", get(api::signup::pow))
        .route("/api/signup/start", post(api::signup::start))
        .route("/api/signup/finish", post(api::signup::finish))
        // Browser-posted CSP / Trusted-Types violation reports (CSRF-exempt; see
        // middleware::csrf and api::reports).
        .route("/api/reports", post(api::reports::reports))
        .route("/api/recovery/redeem", post(api::recovery::redeem))
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
        .route(
            "/api/webauthn/reauth/start",
            post(api::webauthn::reauth_start),
        )
        .route(
            "/api/webauthn/reauth/finish",
            post(api::webauthn::reauth_finish),
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
        )
        .route(
            "/api/account/recovery-codes",
            post(api::account::generate_recovery_codes),
        )
        .route(
            "/api/account/recovery-readiness",
            get(api::account::recovery_readiness),
        )
        .route(
            "/api/account",
            delete(api::account::delete_account).patch(api::account::update_account),
        )
        .route(
            "/api/account/sessions/revoke-others",
            post(api::account::revoke_other_sessions),
        )
        .route(
            "/api/account/credential-review/complete",
            post(api::account::complete_credential_review),
        );

    // OIDC endpoints. token/revoke/userinfo are browser-callable from RP
    // origins (CORS allowlist from client registrations); they never read
    // cookies, so the /api/* CSRF check doesn't apply to them.
    let oauth = Router::new()
        .route("/oauth/token", post(oidc::token::token))
        .route("/oauth/revoke", post(oidc::revoke::revoke))
        .route(
            "/oauth/userinfo",
            get(oidc::userinfo::userinfo).post(oidc::userinfo::userinfo),
        )
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            oidc::cors::allow_registered_origins,
        ));

    // Public OIDC metadata. RP SPAs fetch discovery (then JWKS) cross-origin
    // before anything else; these expose no secrets and read no cookies, so any
    // origin may read them (`Access-Control-Allow-Origin: *`).
    let metadata = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(oidc::discovery::openid_configuration),
        )
        // RFC 8414 alias so non-OIDC OAuth libraries (which look here, not at
        // the OIDC path) discover the same metadata.
        .route(
            "/.well-known/oauth-authorization-server",
            get(oidc::discovery::openid_configuration),
        )
        .route("/.well-known/jwks.json", get(oidc::jwks::jwks))
        // RFC 9116 vulnerability-disclosure contact.
        .route(
            "/.well-known/security.txt",
            get(oidc::security_txt::security_txt),
        )
        .layer(axum_middleware::from_fn(oidc::cors::allow_public));

    router = router
        .route(
            "/oauth/authorize",
            get(oidc::authorize::authorize).post(oidc::authorize::authorize_post),
        )
        .route("/oauth/logout", get(oidc::logout::logout))
        .merge(metadata)
        .merge(oauth);

    router
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf::enforce,
        ))
        .layer(TraceLayer::new_for_http())
        // Outermost: reject any request that didn't transit the CloudFront edge,
        // so the CloudFront-Viewer-* derived rate-limit keys are trustworthy.
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::origin::enforce,
        ))
        .with_state(state)
}
