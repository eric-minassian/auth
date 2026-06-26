# @ericminassian/auth

TypeScript SDK for [auth.ericminassian.com](https://auth.ericminassian.com) — the
OIDC provider for `*.ericminassian.com` apps. ESM-only; subpath exports keep the
browser and server surfaces separate.

```sh
pnpm add @ericminassian/auth
```

## Browser (`/client`, `/react`)

Authorization code + PKCE, run entirely in the browser:

```ts
import { createAuthClient } from "@ericminassian/auth/client";

const auth = createAuthClient({
  clientId: "my-app",
  redirectUri: "https://my-app.ericminassian.com/callback",
});

// Kick off login
await auth.signInWithRedirect();

// On your /callback route
const { returnTo } = await auth.handleRedirectCallback();

// Call your API
const token = await auth.getAccessToken();
```

React bindings:

```tsx
import { createAuthClient } from "@ericminassian/auth/client";
import { AuthProvider, useAuth, useUser } from "@ericminassian/auth/react";

const client = createAuthClient({ clientId: "my-app", redirectUri: "…/callback" });

function App() {
  return (
    <AuthProvider client={client}>
      <Profile />
    </AuthProvider>
  );
}

function Profile() {
  const { state, signIn, signOut } = useAuth();
  const user = useUser();
  if (state.status !== "authenticated") return <button onClick={() => signIn()}>Sign in</button>;
  // Identity is `user.sub`; `nickname` is a mutable display label (profile scope).
  return <button onClick={() => signOut()}>Sign out {user?.nickname ?? user?.sub}</button>;
}
```

> Identity is keyed on `sub` (plus the issuer) — never on `nickname`, which is
> mutable and non-unique. This provider issues no email. The default scope is
> `openid profile offline_access`.

## Server (`/server`, `/server/hono`, `/server/express`)

Verify access tokens locally against the JWKS (no network call per request, edge-safe):

```ts
import { createAuthVerifier } from "@ericminassian/auth/server";

const verifier = createAuthVerifier({ audience: "my-app" });

const result = await verifier.authenticateRequest(request);
if (result.authenticated) {
  console.log(result.claims.sub, result.claims.scope);
}
```

Framework middleware:

```ts
import { authMiddleware } from "@ericminassian/auth/server/hono";
app.use("/api/*", authMiddleware(verifier)); // claims at c.var.auth

import { requireAuth } from "@ericminassian/auth/server/express";
app.use("/api", requireAuth(verifier)); // claims at req.auth
```

`verifyLogoutToken` validates back-channel logout tokens at your RP's logout receiver.

## Security / threat model

This is a **public-client** SDK: the entire flow (PKCE, token exchange,
rotation) runs in the browser, so there is no client secret. The honest
exposure is **XSS** — a script injected into your page can read the in-memory
access token and the `sessionStorage` refresh token and use them. The SDK
mitigates this, it does not eliminate it:

- **DPoP (RFC 9449), automatic.** Tokens are sender-constrained to a
  **non-extractable** P-256 key generated in-browser and kept in IndexedDB. An
  exfiltrated refresh token can't be redeemed without that key, and a
  DPoP-bound access token (`cnf.jkt`) is rejected by the IdP's userinfo without
  a fresh proof. (A live in-page payload can still use the key as a signing
  oracle while it runs — DPoP shrinks the blast radius, it isn't a wall.) Falls
  back to bearer where WebCrypto/IndexedDB are unavailable.
- Access token in memory only; refresh token in `sessionStorage` (not
  `localStorage`); rotation + server-side reuse detection revokes a whole token
  family on replay.

**Your responsibility:** ship a strict `Content-Security-Policy` (no
`unsafe-inline`/`unsafe-eval` scripts) so XSS can't run in the first place — it
is the load-bearing control behind everything above. To fully enforce DPoP at
*your own* resource server, verify a proof for the access token's `cnf.jkt`
(the bundled verifier checks the JWS signature, not the proof). A confidential
BFF is **not** an option here — every client is public by design.

## Development

```sh
pnpm generate   # regenerate wire types from ../../openapi/openapi.json
pnpm build      # tsdown → dist/
pnpm test       # vitest
```
