# @ericminassian/auth

## 1.1.0

### Minor Changes

- 8c6d78a: Refresh resilience, offline-safe sign-out, and a back-channel logout receiver.

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

- be83a97: End-to-end DPoP, step-up auth, and a refresh race fix.

  - **Single-flight token refresh (fix).** Concurrent `getAccessToken()` calls (the
    common multi-component SPA case) now share one rotation instead of each
    redeeming the same refresh token in parallel — which the server's rotating,
    sender-constrained refresh family treated as token reuse and revoked, silently
    signing the user out. `forceRefresh` joins an in-flight rotation rather than
    racing it.
  - **Resource-server DPoP enforcement.** `authenticateRequest` now verifies a DPoP
    proof (RFC 9449) whenever the access token is sender-constrained (`cnf.jkt`),
    closing the gap where a bound token could be replayed as a plain bearer at an
    RP's own API. Configurable via `dpop: { mode }` — `"auto"` (default, verify
    when bound), `"required"` (every request must be bound + proven), or
    `"disabled"` (legacy bearer-only). New `verifyDpopProof` helper and an
    `isReplay` hook for single-use. The express/hono adapters now reconstruct the
    real method + absolute URL so `htm`/`htu` bind correctly, and emit a
    `WWW-Authenticate` challenge on 401.
  - **Client `fetchWithAuth` / `getDpopProof`.** Attach the access token and a fresh
    DPoP proof to RP-API calls, with a transparent retry on a resource-server
    DPoP-Nonce challenge.
  - **Step-up authentication (RFC 9470).** `signInWithRedirect({ acrValues, maxAge })`
    requests a higher assurance (e.g. `"phr-stepup"`), and `stepUpChallenge()`
    builds the `insufficient_user_authentication` challenge an RP resource server
    returns to demand it. Access-token claims now expose `acr`/`amr`.

  Behavior note: RPs using the express/hono adapters get DPoP verification
  automatically. An RP calling `authenticateRequest` with a hand-built `Request`
  that omits the method/URL or the `DPoP` header should either forward them or set
  `dpop: { mode: "disabled" }`.

## 1.0.0

### Major Changes

- c85443b: Sender-constrain tokens with DPoP (RFC 9449) and align the SDK with the
  email-free identity model.

  - **DPoP, automatic.** The browser client now generates a non-extractable P-256
    key (kept in IndexedDB) and signs a DPoP proof on every token request, so an
    exfiltrated refresh token can't be redeemed without the key. Falls back to
    bearer tokens where WebCrypto/IndexedDB are unavailable.
  - **RFC 9207.** The client now verifies the `iss` authorization-response
    parameter (mix-up defense).
  - **Breaking — `User`.** `User.email` / `User.emailVerified` are removed (this
    provider issues no email). `User` now exposes `nickname?` and `updatedAt?`,
    populated under the `profile` scope. Key identity on `sub` (+ issuer).
  - **Breaking — default scope.** `createAuthClient` now defaults to
    `openid profile offline_access` (was `openid email offline_access`), so the
    default config receives `nickname`.
  - `AccessTokenClaims` drops the speculative `email` field and adds `cnf?.jkt`
    to surface DPoP binding to resource servers.

## 0.3.0

### Minor Changes

- 17d89ce: Add silent SSO. `signInSilently()` attempts authentication through a hidden
  `prompt=none` iframe and resolves to the resulting state — picking up an
  existing IdP session without a redirect, and never rejecting on
  `login_required`. `handleCallback()` is the callback-page entry point: inside a
  silent-auth iframe it relays the result to the opener, and at top level it
  completes the redirect code exchange like `handleRedirectCallback()`.

## 0.2.0

### Minor Changes

- 7827d3a: Initial release: OIDC browser client (`/client`), React bindings (`/react`),
  and server-side JWT verification (`/server`, `/server/hono`, `/server/express`).
