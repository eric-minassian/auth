# @ericminassian/auth

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
