---
"@ericminassian/auth": minor
---

End-to-end DPoP, step-up auth, and a refresh race fix.

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
