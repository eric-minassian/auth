use axum::extract::{OriginalUri, Query, State};
use axum::response::Redirect;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use url::Url;

use crate::domain::oauth::{OidcClient, SCOPE_OPENID, granted_scopes, scope_contains};
use crate::domain::session::SessionLevel;
use crate::state::AppState;
use crate::store::oauth::AuthCodeData;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
}

/// GET /oauth/authorize — the OIDC authorization endpoint.
///
/// Validation order is load-bearing: client_id, then exact redirect_uri —
/// only after both validate may errors be redirected to the RP. Anything
/// earlier lands on the SPA's /error page.
pub async fn authorize(
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    jar: CookieJar,
    Query(query): Query<AuthorizeQuery>,
) -> Redirect {
    let issuer = &state.cfg.issuer;
    let fatal = |error: &str| Redirect::to(&format!("{issuer}/error?error={}", urlencoding(error)));

    // 1. client_id must reference a registered client.
    let Some(client_id) = query.client_id.as_deref() else {
        return fatal("invalid_client");
    };
    let client: OidcClient = match state.store.get_client(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return fatal("invalid_client"),
        Err(error) => {
            tracing::error!(?error, "authorize: client lookup failed");
            return fatal("server_error");
        }
    };

    // 2. redirect_uri: exact string match against the registration.
    let Some(redirect_uri) = query.redirect_uri.as_deref() else {
        return fatal("invalid_redirect_uri");
    };
    if !client.allows_redirect_uri(redirect_uri) {
        return fatal("invalid_redirect_uri");
    }

    // From here on, errors are safe to send to the RP.
    let rp_error = |error: &str| rp_redirect(redirect_uri, &[("error", error)], &query.state);

    if query.response_type.as_deref() != Some("code") {
        return rp_error("unsupported_response_type");
    }
    // PKCE S256 required for every client (OAuth 2.1 posture).
    let Some(code_challenge) = query.code_challenge.as_deref() else {
        return rp_error("invalid_request");
    };
    if query.code_challenge_method.as_deref() != Some("S256")
        || !is_plausible_challenge(code_challenge)
    {
        return rp_error("invalid_request");
    }
    // `openid` is required. The granted scope is the intersection of the
    // request with the client's registration and what we support — unsupported
    // or unregistered scopes (e.g. a removed `email`, or `offline_access` for a
    // client not registered for it) are silently dropped, never errored. Only
    // the granted scope is stored and later echoed/honored.
    let requested = query.scope.clone().unwrap_or_default();
    if !scope_contains(&requested, SCOPE_OPENID) {
        return rp_error("invalid_scope");
    }
    let scope = granted_scopes(&requested, &client);
    if !scope_contains(&scope, SCOPE_OPENID) {
        return rp_error("invalid_scope");
    }

    // 3. The SSO layer: the IdP's own session cookie.
    let session = match jar.get(&state.cfg.cookie_name) {
        Some(cookie) => match state.store.get_session(cookie.value()).await {
            Ok(session) => session.filter(|s| s.level == SessionLevel::Full),
            Err(error) => {
                tracing::error!(?error, "authorize: session lookup failed");
                return fatal("server_error");
            }
        },
        None => None,
    };

    // Authoritative account-status gate: a full session must back an active
    // account (defense-in-depth — also re-checks the pending TTL — so an
    // incomplete or expired account can never be issued an authorization code).
    let session = match session {
        Some(s) => match state.store.get_user(s.user_id).await {
            Ok(Some(user)) if user.is_active() => Some(s),
            Ok(_) => None,
            Err(error) => {
                tracing::error!(?error, "authorize: user lookup failed");
                return fatal("server_error");
            }
        },
        None => None,
    };

    let Some(session) = session else {
        if query.prompt.as_deref() == Some("none") {
            return rp_error("login_required");
        }
        // Send the browser to the sign-in UI, which returns to this exact
        // authorize URL after login. Use the relative path+query only: behind
        // API Gateway the reconstructed URI carries the internal execute-api
        // host, which the SPA's same-origin return_to guard would reject.
        let return_to = original_uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/oauth/authorize");
        return Redirect::to(&format!(
            "{issuer}/sign-in?return_to={}",
            urlencoding(return_to)
        ));
    };

    // 4. Mint the code and bounce back to the RP.
    let data = AuthCodeData {
        client_id: client.client_id.clone(),
        user_id: session.user_id,
        sid_hash: session.sid_hash.clone(),
        redirect_uri: redirect_uri.to_string(),
        scope,
        nonce: query.nonce.clone(),
        code_challenge: code_challenge.to_string(),
        auth_time: session.created_at,
        amr: session.amr.clone(),
    };
    let code = match state.store.create_auth_code(&data).await {
        Ok(code) => code,
        Err(error) => {
            tracing::error!(?error, "authorize: code mint failed");
            return rp_error("server_error");
        }
    };
    tracing::info!(target: "audit", event = "code_issued", client_id = %client.client_id, user_id = %session.user_id);
    rp_redirect(redirect_uri, &[("code", &code)], &query.state)
}

fn rp_redirect(redirect_uri: &str, params: &[(&str, &str)], state: &Option<String>) -> Redirect {
    let mut url = match Url::parse(redirect_uri) {
        Ok(url) => url,
        // Registered URIs are validated at seed time; this is unreachable in
        // practice but must not panic.
        Err(_) => return Redirect::to("/error?error=invalid_redirect_uri"),
    };
    {
        let mut query = url.query_pairs_mut();
        for (k, v) in params {
            query.append_pair(k, v);
        }
        if let Some(state) = state {
            query.append_pair("state", state);
        }
    }
    Redirect::to(url.as_str())
}

/// Challenges are BASE64URL(SHA256(...)) = exactly 43 url-safe chars.
fn is_plausible_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn urlencoding(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
