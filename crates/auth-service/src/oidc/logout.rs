use axum::extract::{Query, State};
use axum::response::Redirect;
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use super::verify_own_jws;
use crate::session::clear_session_cookie;
use crate::session::logout::revoke_session_cascade;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub state: Option<String>,
}

/// GET /oauth/logout — RP-initiated logout (OIDC `end_session_endpoint`).
///
/// A destructive logout only happens when `id_token_hint` verifies as a token
/// this service issued; the `post_logout_redirect_uri` is then honored only if
/// it is registered for that token's client. Without a valid hint we bounce to
/// the SPA's `/logout` confirmation page, which performs the logout via an
/// Origin-checked POST — a bare unauthenticated GET is never destructive.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<LogoutQuery>,
) -> (CookieJar, Redirect) {
    let issuer = &state.cfg.issuer;
    let confirm = || Redirect::to(&format!("{issuer}/logout"));

    // The hint must be one of our own tokens.
    let Some(hint) = query.id_token_hint.as_deref() else {
        return (jar, confirm());
    };
    let Some(claims) = verify_own_jws(&state.signer, issuer, hint) else {
        return (jar, confirm());
    };
    let token_client_id = claims["aud"].as_str().map(str::to_string);

    // Resolve the registered post_logout_redirect_uri (if requested).
    let redirect_target = match (&query.post_logout_redirect_uri, &token_client_id) {
        (Some(requested), Some(client_id)) => {
            match state.store.get_client(client_id).await {
                Ok(Some(client))
                    if client
                        .post_logout_redirect_uris
                        .iter()
                        .any(|u| u == requested) =>
                {
                    Some(requested.clone())
                }
                // Requested but not registered: ignore it, fall to confirm page.
                _ => None,
            }
        }
        _ => None,
    };

    // Revoke the current browser session (identified by the cookie) and clear
    // it — but only if the id_token_hint identifies that same user. This stops
    // a logout-CSRF where an attacker submits *their own* valid id_token to
    // sign the victim out (the cookie picks the session, the hint must prove
    // it's the same subject).
    let hint_sub = claims["sub"].as_str();
    let mut jar = jar;
    if let Some(cookie) = jar.get(&state.cfg.cookie_name) {
        if let Ok(Some(session)) = state.store.get_session(cookie.value()).await {
            if hint_sub == Some(session.user_id.to_string().as_str()) {
                if let Err(error) = revoke_session_cascade(&state, &session).await {
                    tracing::error!(?error, "logout: session cascade failed");
                }
                jar = jar.add(clear_session_cookie(&state.cfg));
                tracing::info!(target: "audit", event = "rp_initiated_logout", user_id = %session.user_id);
            } else {
                // Hint doesn't match the browser session — fall to the
                // confirmation page rather than acting.
                return (jar, confirm());
            }
        } else {
            jar = jar.add(clear_session_cookie(&state.cfg));
        }
    }

    match redirect_target {
        Some(uri) => {
            let location = match &query.state {
                Some(state_param) => append_state(&uri, state_param),
                None => uri,
            };
            (jar, Redirect::to(&location))
        }
        None => (jar, confirm()),
    }
}

fn append_state(uri: &str, state: &str) -> String {
    match url::Url::parse(uri) {
        Ok(mut url) => {
            url.query_pairs_mut().append_pair("state", state);
            url.to_string()
        }
        Err(_) => uri.to_string(),
    }
}
