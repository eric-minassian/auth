# Shipping a TypeScript SDK for an Auth Service — Best Practices Report (June 2026)

## 1. Packaging in 2026

### ESM-only vs dual CJS/ESM
**ESM-only is the correct default for a new SDK in 2026.** The deciding factor is `require(esm)`: Node can now `require()` synchronous ESM graphs, unflagged in **Node 22.12+ and backported to Node 20.19+** ([antfu, "Move on to ESM-only"](https://antfu.me/posts/move-on-to-esm-only), [Fullstack Notes require(esm) guide](https://fullstacknotes.dev/blog/2026/2026-01/2026-01-24-nodejs-require-esm/)). With Node 18 EOL (April 2025) and **Node 20 EOL on April 30, 2026** ([endoflife.date/nodejs](https://endoflife.date/nodejs), [HeroDevs EOL schedule](https://www.herodevs.com/blog-posts/node-js-end-of-life-dates-you-should-be-aware-of)), every supported Node release can consume ESM-only packages even from CJS callers. Roughly 80% of new packages in 2025–2026 are ESM-first ([PkgPulse migration guide](https://www.pkgpulse.com/guides/great-migration-cjs-to-esm-npm-ecosystem-2026)). Dual publishing carries the **dual package hazard** (two module instances, split singleton state — particularly bad for an auth SDK that holds session state) ([esmodules.com publishing guide](https://esmodules.com/publishing/)). Clerk's own SDK-development guide says: *"Consider publishing in ESM format exclusively rather than dual CJS/ESM unless necessary"* ([Clerk SDK conventions](https://clerk.com/docs/guides/development/sdk-development/conventions)). Verification note: one search result claimed `require(esm)` was backported to Node 18 — **refuted**; it landed in 20.19/22.12 only.

### Bundler: tsdown (not tsup)
**tsup is officially unmaintained.** Its README now states: *"This project is not actively maintained anymore. Please consider using tsdown instead"* ([egoist/tsup](https://github.com/egoist/tsup)). **tsdown** is the designated successor — Rolldown-powered (Oxc for `.d.ts` generation), compatible with tsup's options, with a published migration path ([tsdown.dev](https://tsdown.dev/guide/), [migrate-from-tsup](https://tsdown.dev/guide/migrate-from-tsup), [rolldown/tsdown](https://github.com/rolldown/tsdown)). It auto-enables DTS generation when `exports` contains type conditions ([tsdown FAQ](https://tsdown.dev/guide/faq)). `unbuild` (rollup-based, UnJS) remains fine but tsdown is the current ecosystem default for new libraries. **Recommendation: tsdown.**

### exports map, types condition, sideEffects
- Resolvers walk conditions **top-down, first match wins**; **`"types"` must be first in every condition block**, or TS may resolve the JS file as the type source ([TypeScript modules reference](https://www.typescriptlang.org/docs/handbook/modules/reference.html), [hirok.io exports guide](https://hirok.io/posts/package-json-exports), [Node packages docs](https://nodejs.org/api/packages.html)).
- ESM-only simplifies this drastically: per subpath you need only `{ "types": "...", "default": "..." }`.
- Set `"sideEffects": false` so bundlers can tree-shake; use **subpath exports as API boundaries** so server code can never leak into browser bundles (Clerk's explicit convention) ([Clerk SDK conventions](https://clerk.com/docs/guides/development/sdk-development/conventions), [webpack package exports](https://webpack.js.org/guides/package-exports/)).
- Target: `"engines": { "node": ">=20.19" }` (or `>=22` if you want to track only live LTS), compile target ~ES2022.

## 2. Publishing

- **npm Trusted Publishing (OIDC) is GA** since July 2025 and is the 2026 standard: no long-lived `NPM_TOKEN`, and **provenance attestations are generated automatically** — no `--provenance` flag needed ([npm docs: trusted publishers](https://docs.npmjs.com/trusted-publishers/), [GitHub changelog](https://github.blog/changelog/2025-07-31-npm-trusted-publishing-with-oidc-is-generally-available/)). Requirements: npm CLI ≥ 11.5.1, Node ≥ 22.14 in CI, GitHub-hosted runners only, `permissions: id-token: write`, one trusted publisher per package. Note: trusted-publisher configs created **after May 20, 2026** must explicitly select allowed actions (`npm publish` / `npm stage publish`) ([npm docs](https://docs.npmjs.com/trusted-publishers/)).
- **Changesets** is the standard versioning/release flow: `changesets/action` opens a "Version Packages" PR, then publishes on merge via your `publish` input ([changesets/action](https://github.com/changesets/action), [OpenReplay changesets guide](https://blog.openreplay.com/release-workflows-changesets/)).
- **Caveat (verified open issue):** there are active reports of E404 failures publishing **scoped** packages via `changesets/action` + OIDC trusted publishing ([npm/cli#8976](https://github.com/npm/cli/issues/8976), related #8730/#8678). Mitigation: ensure the publish step runs `npm publish`/`pnpm publish` with npm ≥11.5.1 from the exact configured workflow file; keep a granular automation token + `--provenance` as documented fallback.
- **Scoped naming**: publish under your org scope (e.g. `@acme/auth`), `publishConfig.access: "public"`. Clerk additionally recommends a recognizable brand prefix/suffix and prefixed env vars (`ACME_AUTH_*`), with secret keys server-only ([Clerk SDK conventions](https://clerk.com/docs/guides/development/sdk-development/conventions)). All Clerk SDKs publish with provenance — treat that as table stakes for an auth SDK.

## 3. How auth SDKs split surfaces

- **Auth0 (`@auth0/auth0-spa-js`)** — browser-only package: a single `Auth0Client` class behind a `createAuth0Client()` factory (factory also silently restores the session on init). Surface: `loginWithRedirect()` / `handleRedirectCallback()` (Authorization Code + PKCE), `getTokenSilently()` (cached token → refresh token or iframe), `getUser()`, `isAuthenticated()`, `logout()` ([Auth0 SPA SDK docs](https://auth0.com/docs/libraries/auth0-single-page-app-sdk), [auth0/auth0-spa-js](https://github.com/auth0/auth0-spa-js), [API reference](https://auth0.github.io/auth0-spa-js/classes/Auth0Client.html)). React bindings (`@auth0/auth0-react`) wrap this client in a Provider + hooks.
- **Clerk** — hard package split: `@clerk/clerk-js` is the browser bundle (session state, UI), while **`@clerk/backend`** is the isomorphic server package "built for Node.js/V8 isolates" exposing `createClerkClient`, `verifyToken`/`authenticateRequest` and low-level JWT utilities; framework SDKs (`@clerk/express`, `@clerk/nextjs`) are thin wrappers re-exporting from `@clerk/backend` ([Clerk backend overview](https://clerk.com/docs/reference/backend/overview), [Backend-only SDK guide](https://clerk.com/docs/guides/development/sdk-development/backend-only), [migration guide](https://medium.com/@bonfacealfonce/clerk-migration-guide-moving-from-clerk-sdk-node-to-clerk-backend-clerk-express-ba0c3ddca1bd)). Within framework SDKs, Clerk uses **subpath exports** (`@clerk/astro/client`, `@clerk/astro/server`) as the client/server boundary ([Clerk SDK conventions](https://clerk.com/docs/guides/development/sdk-development/conventions)).
- **jose** — runtime-agnostic crypto primitive; auth vendors build *on* it rather than reimplementing JOSE.
- **Pattern to copy at small scale:** one package, subpath-split: `./client` (redirect helpers, `getToken`, session state — no Node APIs), `./react` (Provider + `useAuth`/`useUser` hooks over the client), `./server` (JWKS verification + request authentication, edge-safe: WebCrypto + fetch only), plus tiny framework adapters. Separate npm packages (Clerk-style) only pay off when teams/release cadences diverge.

## 4. Server-side JWT verification with jose

The canonical pattern ([panva/jose docs](https://github.com/panva/jose/blob/main/docs/jwks/remote/functions/createRemoteJWKSet.md), defaults verified from [source](https://github.com/panva/jose/blob/main/src/jwks/remote.ts)):

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

// Module-level singleton — reuse across requests so the JWKS cache is shared
const jwks = createRemoteJWKSet(new URL("https://auth.example.com/.well-known/jwks.json"));

export async function verifyAccessToken(token: string) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer: "https://auth.example.com",
    audience: "https://api.example.com",
    clockTolerance: "30s",
  });
  return payload;
}
```

Verified behavior/defaults:
- **`cacheMaxAge`: 600 000 ms (10 min)** — refetch when stale; **`cooldownDuration`: 30 000 ms** — on unknown `kid` it refetches immediately (handles key rotation) unless within cooldown (prevents DoS-by-bogus-kid); **`timeoutDuration`: 5 000 ms** ([jose remote.ts](https://github.com/panva/jose/blob/main/src/jwks/remote.ts), [TTL discussion #394](https://github.com/panva/jose/discussions/394)).
- `clockTolerance` of 15–30s absorbs clock skew between issuer and verifier ([WorkOS JWKS guide](https://workos.com/blog/developers-guide-jwks)).
- Always pin `issuer` + `audience`; catch specific errors (`JWTExpired`, `JWKSNoMatchingKey`, …) and return non-descriptive 401s.
- jose is pure WebCrypto — works in Node, Workers, and edge runtimes; this is exactly why `@clerk/backend` targets V8 isolates.

## 5. Repo layout: polyglot pnpm monorepo

Typical layout for Rust service + CDK + SDK + frontend ([spa5k/monorepo-typescript-rust](https://github.com/spa5k/monorepo-typescript-rust), [Earthly Rust monorepo](https://earthly.dev/blog/rust-monorepo/), [GitButler structure](https://deepwiki.com/gitbutlerapp/gitbutler/3.1-but-cli-and-mcp-servers), [changesets in polyglot monorepos](https://luke.hsiao.dev/blog/changesets-polyglot-monorepo/)):

```
/
├─ pnpm-workspace.yaml          # packages: ["apps/*", "packages/*", "infra"]
├─ Cargo.toml                   # [workspace] members = ["crates/*"]
├─ crates/
│  └─ auth-service/             # Rust service (axum + utoipa)
├─ apps/
│  └─ web/                      # frontend (Vite/React)
├─ packages/
│  └─ auth-sdk/                 # the TypeScript SDK (published)
├─ infra/                       # AWS CDK app (or packages/infra)
└─ openapi/openapi.json         # generated contract, committed
```

Two parallel workspace managers (pnpm + cargo) at the root, joined by root scripts. The contract artifact (`openapi.json`) is the bridge between the Rust and TS halves.

**Turborepo: overkill at this scale.** pnpm workspaces alone handles linking and `pnpm -r --filter` task running; Turborepo's value (cached, graph-ordered tasks) appears as package count grows, and it can be added incrementally later with just a `turbo.json` over existing scripts ([Nhost pnpm+Turborepo](https://nhost.io/blog/how-we-configured-pnpm-and-turborepo-for-our-monorepo), [turborepo.dev](https://turborepo.dev/docs), [FSD monorepo guide](https://feature-sliced.design/blog/frontend-monorepo-explained)). With one SDK, one app, and a Rust service that pnpm can't orchestrate anyway, start without it.

## 6. API client generation

For a small API owned by the same author, the recommended pipeline is **spec-from-code, types-only codegen, hand-written thin client**:

1. **Rust side:** `utoipa` + `utoipa-axum`'s `OpenApiRouter` derives the OpenAPI 3 spec from the same handlers axum serves — handlers and spec can't drift ([docs.rs/utoipa-axum](https://docs.rs/utoipa-axum), [juhaku/utoipa](https://github.com/juhaku/utoipa), [Shuttle OpenAPI-in-Rust](https://www.shuttle.dev/blog/2024/04/04/using-openapi-rust)). Add a `cargo run --bin export-openapi > openapi/openapi.json` step and a CI check that it's committed.
2. **TS side:** `openapi-typescript` emits **types only — zero runtime code** ([dev.to codegen comparison](https://dev.to/nyaomaru/which-openapi-codegen-should-you-choose-openapi-typescript-vs-hey-api-vs-orval-vs-kubb-100p), [OpenReplay type-safe clients](https://blog.openreplay.com/type-safe-openapi-typescript-client/)). Pair with a small hand-written fetch wrapper (or `openapi-fetch`, ~2 kB).
3. **Orval** generates a full client layer (TanStack Query hooks, Zod schemas, MSW mocks) ([orval.dev](https://orval.dev/)) — valuable for large third-party APIs, but for a ~dozen-endpoint self-owned auth API it produces more generated surface than the API itself. Skip it.

Pure hand-written types are the worst option — they silently drift from the API ([PkgPulse OpenAPI client comparison](https://www.pkgpulse.com/guides/orval-vs-openapi-typescript-vs-kubb-openapi-client-2026)). Types-from-spec + hand-written ergonomics is the sweet spot: the SDK's *public* API stays hand-designed (auth SDKs need curated ergonomics, not 1:1 endpoint mirrors), while wire types are generated.

## 7. Recommended concrete SDK package structure

One ESM-only package, `@acme/auth`, subpath-split, built with tsdown:

```
packages/auth-sdk/
├─ package.json
├─ tsdown.config.ts
├─ tsconfig.json
├─ README.md
└─ src/
   ├─ index.ts            # shared: error classes, public types, re-export of wire types
   ├─ generated/
   │  └─ api.d.ts         # openapi-typescript output (types only, committed)
   ├─ core/
   │  ├─ http.ts          # thin typed fetch wrapper over generated paths
   │  └─ errors.ts        # AuthError hierarchy (shared client/server)
   ├─ client/
   │  ├─ index.ts         # createAuthClient()
   │  ├─ auth-client.ts   # loginWithRedirect, handleRedirectCallback (PKCE),
   │  │                   # getToken (cache→refresh), getUser, signOut, onAuthStateChange
   │  └─ storage.ts       # session persistence abstraction
   ├─ react/
   │  ├─ index.ts         # AuthProvider, useAuth, useUser, useToken
   │  └─ context.tsx
   └─ server/
      ├─ index.ts         # createAuthVerifier({ issuer, audience }) -> { verifyToken, authenticateRequest }
      ├─ verify.ts        # jose createRemoteJWKSet singleton per verifier, clockTolerance 30s
      ├─ hono.ts          # authMiddleware() for Hono (Request-based, edge-safe)
      └─ express.ts       # requireAuth() for Express
```

`package.json` (key fields):

```jsonc
{
  "name": "@acme/auth",
  "type": "module",
  "sideEffects": false,
  "engines": { "node": ">=20.19" },
  "files": ["dist"],
  "exports": {
    ".":          { "types": "./dist/index.d.ts",          "default": "./dist/index.js" },
    "./client":   { "types": "./dist/client/index.d.ts",   "default": "./dist/client/index.js" },
    "./react":    { "types": "./dist/react/index.d.ts",    "default": "./dist/react/index.js" },
    "./server":   { "types": "./dist/server/index.d.ts",   "default": "./dist/server/index.js" },
    "./server/hono":    { "types": "./dist/server/hono.d.ts",    "default": "./dist/server/hono.js" },
    "./server/express": { "types": "./dist/server/express.d.ts", "default": "./dist/server/express.js" }
  },
  "dependencies": { "jose": "^6" },
  "peerDependencies": { "react": ">=18", "hono": ">=4", "express": ">=5" },
  "peerDependenciesMeta": {
    "react":   { "optional": true },
    "hono":    { "optional": true },
    "express": { "optional": true }
  },
  "publishConfig": { "access": "public" }
}
```

`tsdown.config.ts`:

```ts
import { defineConfig } from "tsdown";
export default defineConfig({
  entry: ["src/index.ts", "src/client/index.ts", "src/react/index.ts",
          "src/server/index.ts", "src/server/hono.ts", "src/server/express.ts"],
  format: "esm",
  dts: true,
  platform: "neutral",   // server entry uses only fetch + WebCrypto via jose → edge-safe
  target: "es2022",
});
```

Design rules encoded here:
- **Subpath exports are the client/server boundary** (Clerk's convention): importing `@acme/auth/client` can never pull in `jose` or middleware; `types` first in every condition; ESM-only so no dual-package hazard for session-singleton state.
- `jose` is a regular dependency (server entries only — tree-shaken out of client graphs by the entry split); React/Hono/Express are optional peers so the core stays dependency-light.
- Wire types come from `openapi/openapi.json` (utoipa) via a `pnpm generate` script running `openapi-typescript`; the hand-written `core/http.ts` and public client API stay curated.
- Release: changesets + `changesets/action`; publish job with `permissions: id-token: write`, npm ≥11.5.1, trusted publisher configured for the workflow file — provenance attached automatically (watch [npm/cli#8976](https://github.com/npm/cli/issues/8976) for the scoped-package OIDC bug; granular token + `--provenance` is the fallback).
- Monorepo: layout from §5; no Turborepo until task graph pain appears.

## Sources

- [antfu — Move on to ESM-only](https://antfu.me/posts/move-on-to-esm-only) · [esmodules.com publishing guide](https://esmodules.com/publishing/) · [PkgPulse CJS→ESM migration](https://www.pkgpulse.com/guides/great-migration-cjs-to-esm-npm-ecosystem-2026) · [Fullstack Notes — require(esm)](https://fullstacknotes.dev/blog/2026/2026-01/2026-01-24-nodejs-require-esm/)
- [egoist/tsup (maintenance notice)](https://github.com/egoist/tsup) · [tsdown.dev guide](https://tsdown.dev/guide/) · [tsdown FAQ](https://tsdown.dev/guide/faq) · [migrate from tsup](https://tsdown.dev/guide/migrate-from-tsup) · [rolldown/tsdown](https://github.com/rolldown/tsdown)
- [TypeScript modules reference](https://www.typescriptlang.org/docs/handbook/modules/reference.html) · [hirok.io — exports field guide](https://hirok.io/posts/package-json-exports) · [Node.js packages docs](https://nodejs.org/api/packages.html) · [webpack package exports](https://webpack.js.org/guides/package-exports/)
- [npm docs — trusted publishers](https://docs.npmjs.com/trusted-publishers/) · [GitHub changelog — npm trusted publishing GA](https://github.blog/changelog/2025-07-31-npm-trusted-publishing-with-oidc-is-generally-available/) · [npm/cli#8976](https://github.com/npm/cli/issues/8976) · [changesets/action](https://github.com/changesets/action) · [OpenReplay — changesets workflows](https://blog.openreplay.com/release-workflows-changesets/)
- [Clerk SDK conventions](https://clerk.com/docs/guides/development/sdk-development/conventions) · [Clerk backend-only SDK guide](https://clerk.com/docs/guides/development/sdk-development/backend-only) · [Clerk backend reference](https://clerk.com/docs/reference/backend/overview) · [Auth0 SPA SDK docs](https://auth0.com/docs/libraries/auth0-single-page-app-sdk) · [auth0/auth0-spa-js](https://github.com/auth0/auth0-spa-js) · [Auth0Client API](https://auth0.github.io/auth0-spa-js/classes/Auth0Client.html)
- [jose createRemoteJWKSet docs](https://github.com/panva/jose/blob/main/docs/jwks/remote/functions/createRemoteJWKSet.md) · [jose remote.ts source](https://github.com/panva/jose/blob/main/src/jwks/remote.ts) · [jose discussion #394](https://github.com/panva/jose/discussions/394) · [WorkOS — developer's guide to JWKS](https://workos.com/blog/developers-guide-jwks)
- [endoflife.date/nodejs](https://endoflife.date/nodejs) · [HeroDevs Node EOL dates](https://www.herodevs.com/blog-posts/node-js-end-of-life-dates-you-should-be-aware-of)
- [spa5k/monorepo-typescript-rust](https://github.com/spa5k/monorepo-typescript-rust) · [Earthly — Rust monorepo](https://earthly.dev/blog/rust-monorepo/) · [GitButler monorepo structure](https://deepwiki.com/gitbutlerapp/gitbutler/3.1-but-cli-and-mcp-servers) · [luke.hsiao.dev — changesets polyglot](https://luke.hsiao.dev/blog/changesets-polyglot-monorepo/) · [Nhost — pnpm + Turborepo](https://nhost.io/blog/how-we-configured-pnpm-and-turborepo-for-our-monorepo) · [turborepo.dev](https://turborepo.dev/docs) · [FSD monorepo guide](https://feature-sliced.design/blog/frontend-monorepo-explained)
- [docs.rs/utoipa-axum](https://docs.rs/utoipa-axum) · [juhaku/utoipa](https://github.com/juhaku/utoipa) · [Shuttle — OpenAPI in Rust](https://www.shuttle.dev/blog/2024/04/04/using-openapi-rust) · [dev.to — OpenAPI codegen comparison](https://dev.to/nyaomaru/which-openapi-codegen-should-you-choose-openapi-typescript-vs-hey-api-vs-orval-vs-kubb-100p) · [orval.dev](https://orval.dev/) · [OpenReplay — type-safe OpenAPI clients](https://blog.openreplay.com/type-safe-openapi-typescript-client/) · [PkgPulse — OpenAPI client tools 2026](https://www.pkgpulse.com/guides/orval-vs-openapi-typescript-vs-kubb-openapi-client-2026)