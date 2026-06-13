# @eric-minassian/auth

TypeScript SDK for [auth.ericminassian.com](https://auth.ericminassian.com) — the
OIDC provider for `*.ericminassian.com` apps. ESM-only; subpath exports keep the
browser and server surfaces separate.

```sh
pnpm add @eric-minassian/auth
```

## Browser (`/client`, `/react`)

Authorization code + PKCE, run entirely in the browser:

```ts
import { createAuthClient } from "@eric-minassian/auth/client";

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
import { createAuthClient } from "@eric-minassian/auth/client";
import { AuthProvider, useAuth, useUser } from "@eric-minassian/auth/react";

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
  return <button onClick={() => signOut()}>Sign out {user?.email}</button>;
}
```

## Server (`/server`, `/server/hono`, `/server/express`)

Verify access tokens locally against the JWKS (no network call per request, edge-safe):

```ts
import { createAuthVerifier } from "@eric-minassian/auth/server";

const verifier = createAuthVerifier({ audience: "my-app" });

const result = await verifier.authenticateRequest(request);
if (result.authenticated) {
  console.log(result.claims.sub, result.claims.scope);
}
```

Framework middleware:

```ts
import { authMiddleware } from "@eric-minassian/auth/server/hono";
app.use("/api/*", authMiddleware(verifier)); // claims at c.var.auth

import { requireAuth } from "@eric-minassian/auth/server/express";
app.use("/api", requireAuth(verifier)); // claims at req.auth
```

`verifyLogoutToken` validates back-channel logout tokens at your RP's logout receiver.

## Development

```sh
pnpm generate   # regenerate wire types from ../../openapi/openapi.json
pnpm build      # tsdown → dist/
pnpm test       # vitest
```
