use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

/// GET /.well-known/openid-configuration
///
/// Front-channel logout is deliberately absent (cross-site iframes are dead);
/// back-channel logout is the supported single-logout mechanism.
pub async fn openid_configuration(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = &state.cfg.issuer;
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/oauth/authorize"),
            "token_endpoint": format!("{issuer}/oauth/token"),
            "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "end_session_endpoint": format!("{issuer}/oauth/logout"),
            "revocation_endpoint": format!("{issuer}/oauth/revoke"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"],
            // DPoP (RFC 9449): clients may sender-constrain their tokens with an
            // ES256 proof-of-possession key. Honored but not required (a plain
            // bearer still works), so adoption is incremental.
            "dpop_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["openid", "profile", "offline_access"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "sid", "amr", "nickname", "updated_at"
            ],
            "backchannel_logout_supported": true,
            "backchannel_logout_session_supported": true,
            "frontchannel_logout_supported": false,
            // RFC 9207 — `iss` is stamped on every authorization response.
            "authorization_response_iss_parameter_supported": true,
            // OIDC Core fresh-auth controls honored at /oauth/authorize.
            "prompt_values_supported": ["none", "login", "create"],
            "request_parameter_supported": false,
            "request_uri_parameter_supported": false,
            "claims_parameter_supported": false,
        })),
    )
}
