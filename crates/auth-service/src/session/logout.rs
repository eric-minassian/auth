use std::collections::HashSet;

use uuid::Uuid;

use crate::domain::session::IdpSession;
use crate::jwt::claims::{LOGOUT_TOKEN_TTL_SECS, LogoutTokenClaims};
use crate::state::AppState;
use crate::store::{StoreError, now};

/// Revoke an IdP session and everything that hangs off it, then fan out
/// back-channel logout notifications.
///
/// Steps, in order: revoke every refresh-token family bound to the session
/// (so refresh grants stop immediately), delete the session record, then —
/// best effort — POST a logout token to each affected client's
/// `backchannel_logout_uri`. The session must be deleted *before* dispatch so
/// a slow/hanging RP can't keep the session alive.
pub async fn revoke_session_cascade(
    state: &AppState,
    session: &IdpSession,
) -> Result<(), StoreError> {
    let families = state
        .store
        .list_refresh_families(session.user_id, Some(&session.sid_hash))
        .await?;

    let mut clients: HashSet<String> = HashSet::new();
    for family in &families {
        clients.insert(family.client_id.clone());
        state
            .store
            .revoke_refresh_family(&family.family_id, "logout")
            .await?;
    }

    state.store.delete_session(&session.sid_hash).await?;

    dispatch_backchannel(state, session.user_id, &session.sid_hash, &clients).await;
    Ok(())
}

/// Mint a logout token per client and POST it to its back-channel endpoint.
/// Failures are logged, never propagated — RP availability must not block
/// logout (front-channel logout is dead; this is the supported mechanism).
async fn dispatch_backchannel(
    state: &AppState,
    user_id: Uuid,
    sid_hash: &str,
    client_ids: &HashSet<String>,
) {
    for client_id in client_ids {
        let client = match state.store.get_client(client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(?error, client_id, "backchannel: client lookup failed");
                continue;
            }
        };
        let Some(uri) = client.backchannel_logout_uri.clone() else {
            continue;
        };

        let ts = now();
        let claims = LogoutTokenClaims {
            iss: state.cfg.issuer.clone(),
            sub: user_id.to_string(),
            aud: client_id.clone(),
            iat: ts,
            exp: ts + LOGOUT_TOKEN_TTL_SECS,
            jti: Uuid::now_v7().to_string(),
            sid: sid_hash.to_string(),
            events: LogoutTokenClaims::backchannel_event(),
        };
        let token = match state.signer.sign("logout+jwt", &claims).await {
            Ok(token) => token,
            Err(error) => {
                tracing::error!(?error, client_id, "backchannel: logout token sign failed");
                continue;
            }
        };

        match state
            .http
            .post(&uri)
            .form(&[("logout_token", token.as_str())])
            .send()
            .await
        {
            Ok(response) => tracing::info!(
                target: "audit",
                event = "backchannel_logout_dispatched",
                client_id,
                status = u16::from(response.status()),
            ),
            Err(error) => tracing::warn!(
                target: "audit",
                event = "backchannel_logout_failed",
                client_id,
                error = %error,
            ),
        }
    }
}
