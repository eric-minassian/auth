# @ericminassian/auth

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
