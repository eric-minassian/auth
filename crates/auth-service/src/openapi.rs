//! OpenAPI document assembled from the `#[utoipa::path]`-annotated handlers.
//!
//! Scope: the SPA-facing JSON API (`/api/*`) plus the OIDC token endpoint —
//! i.e. everything the frontend and the TypeScript SDK consume. The other
//! OIDC endpoints are described by the discovery document
//! (`/.well-known/openid-configuration`) and are intentionally not duplicated
//! here.
//!
//! `cargo run --bin export-openapi` prints this; CI diffs it against the
//! committed `openapi/openapi.json` to catch drift.

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "auth.ericminassian.com",
        description = "Personal OIDC provider — SPA API and token endpoint.",
        license(name = "MIT"),
    ),
    tags(
        (name = "meta", description = "Health and metadata"),
        (name = "signup", description = "Account creation (passkey + proof-of-work)"),
        (name = "recovery", description = "Account recovery (one-time recovery codes)"),
        (name = "webauthn", description = "Passkey registration, login, and step-up"),
        (name = "session", description = "Session lifecycle"),
        (name = "account", description = "Passkey, session, and recovery-code management"),
        (name = "oidc", description = "OAuth 2.1 / OIDC endpoints"),
    ),
    paths(
        crate::api::healthz,
        crate::api::signup::pow,
        crate::api::signup::start,
        crate::api::signup::finish,
        crate::api::recovery::redeem,
        crate::api::webauthn::register_start,
        crate::api::webauthn::register_finish,
        crate::api::webauthn::login_start,
        crate::api::webauthn::login_finish,
        crate::api::webauthn::reauth_start,
        crate::api::webauthn::reauth_finish,
        crate::api::session::get,
        crate::api::session::logout,
        crate::api::account::list_passkeys,
        crate::api::account::rename_passkey,
        crate::api::account::delete_passkey,
        crate::api::account::list_sessions,
        crate::api::account::revoke_session,
        crate::api::account::delete_account,
        crate::api::account::generate_recovery_codes,
        crate::api::account::recovery_readiness,
        crate::oidc::token::token,
    ),
    components(schemas(
        crate::api::OkResponse,
        crate::api::ErrorResponse,
        crate::api::HealthResponse,
        crate::api::signup::PowChallenge,
        crate::api::signup::StartRequest,
        crate::api::recovery::RedeemRequest,
        crate::api::recovery::RedeemResponse,
        crate::api::session::SessionInfo,
        crate::api::session::SessionUser,
        crate::api::session::SessionMeta,
        crate::api::account::RenameRequest,
        crate::api::account::PasskeyInfo,
        crate::api::account::PasskeyList,
        crate::api::account::SessionListItem,
        crate::api::account::SessionList,
        crate::api::account::RecoveryCodes,
        crate::api::account::RecoveryReadiness,
        crate::oidc::token::TokenRequest,
        crate::oidc::token::TokenResponse,
    )),
)]
pub struct ApiDoc;
