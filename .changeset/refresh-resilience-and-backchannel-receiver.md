---
"@ericminassian/auth": minor
---

Refresh resilience, offline-safe sign-out, and a back-channel logout receiver.

- **Transient refresh failures no longer destroy the session (fix).** A network
  blip, discovery outage, 5xx, or rate limit during token refresh used to clear
  the stored refresh/ID tokens and silently sign the user out of every RP.
  Local state is now cleared only on a definitive `400 invalid_grant` from the
  token endpoint (thrown as `login_required`); everything else surfaces as a
  retriable `token_refresh_failed` / `network_error` and the next
  `getAccessToken()` simply tries again.
- **`signOut()` works offline (fix).** Local state is cleared first; the
  refresh-token revocation and `end_session` redirect are best-effort
  afterwards. Previously an unreachable discovery document made `signOut()`
  throw without clearing anything.
- **Back-channel logout receiver (new).** `createLogoutReceiver(verifier, {
  onLogout, isReplay })` returns a `(Request) => Response` handler for the RP's
  registered `backchannel_logout_uri`, with express (`logoutReceiver`) and hono
  adapters. Verifies the logout token per OIDC Back-Channel Logout 1.0
  (signature via JWKS, `typ: logout+jwt`, the `events` claim, `sub`/`sid`
  presence, `nonce` rejection) and supports single-use `jti` enforcement via
  the bundled `inMemoryReplayCache()` or a custom store.
  `verifyLogoutToken` now also returns the token's `jti` for that purpose.
