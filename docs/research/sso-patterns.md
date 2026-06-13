# Centralized Auth at `auth.example.com`: SSO Architecture for First-Party Subdomain Apps

Research date: June 2026. Scope: a personal/small-scale centralized auth service serving first-party apps on sibling subdomains (`app1.example.com`, `app2.example.com`), browser apps first, CLI/M2M later.

---

## 1. The two shapes: shared domain cookie vs. full OIDC per app

### Shape A — Shared session cookie at `Domain=.example.com`

One login page at `auth.example.com` sets a single cookie with `Domain=example.com` (note: per [RFC 6265bis semantics documented on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie), if a `Domain` attribute is specified, **subdomains are always included** — the leading dot is legacy and ignored). Every app on `*.example.com` receives the cookie automatically; each app's backend verifies it, either:

- **JWT variant**: cookie value is a signed JWT; apps verify locally against the auth service's JWKS — zero network calls.
- **Opaque variant**: cookie is a random session ID; apps call the auth service's `whoami`/introspection endpoint (Ory Kratos's model — `ory_kratos_session` cookie + [`/sessions/whoami`](https://www.ory.com/docs/kratos/session-management/overview)).

This is exactly the pattern Ory documents for subdomain SSO: ["Subdomains can set HTTP Cookies for parent domains"](https://www.ory.com/docs/kratos/guides/multi-domain-cookies), configured via `cookies.domain` / `session.cookie.domain`. Cross **top-level-domain** SSO is where they cut you over to their paid multibrand feature — i.e., the cookie trick is the recommended shape *within* one registrable domain.

### Shape B — Full OIDC: each app a registered client (auth code + PKCE)

Each app redirects to `auth.example.com/authorize`, exchanges a code for ID/access/refresh tokens, and keeps its **own** session. SSO emerges because the *auth server's own session cookie* (on `auth.example.com` only) lets subsequent `/authorize` redirects complete silently. This is Auth0's three-layer model: application session layer + Auth0 session layer + upstream IdP session layer ([Auth0 Session Layers](https://auth0.com/docs/manage-users/sessions/session-layers), [Application Session Management Best Practices](https://auth0.com/blog/application-session-management-best-practices/)).

### Tradeoffs for FIRST-PARTY-only apps

| | Shared cookie (A) | Full OIDC (B) |
|---|---|---|
| Implementation cost | One cookie + one verify function per app | Client registration, redirect flow, callback route, token storage, refresh logic **per app** |
| SSO UX | Instant — no redirects after first login | First visit to each app requires a redirect round-trip |
| Single logout | Trivial (one cookie + one server-side session to kill) | Hard (front-/back-channel logout machinery, §6) |
| Per-app authorization | All apps see the same session; scoping is DIY claims | Native: per-client scopes, audiences, consent |
| Blast radius | A compromised app on any subdomain can steal/replant the shared cookie ([OWASP warns sibling subdomains are same-site for cookie purposes](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)) | Compromise scoped to one client's tokens |
| Third parties / other TLDs later | Dead end — cookie can't cross registrable domains | Standard; just register another client |

**When is full OIDC overkill?** The consensus across sources: when *every* relying app is first-party, trusted to the same degree, and lives under one registrable domain, the per-client OIDC ceremony buys you little — the shared cookie *is* the classic "magic cookie" SSO recipe ([Planet Kodiak](https://www.planetkodiak.com/architecture/web-sso-across-multiple-subdomains-using-the-magic-cookie-recipe/), [subdomain auth overview](https://medium.com/@jsmmkt123/how-authentication-works-across-subdomains-and-why-most-developers-get-it-wrong-322a53a6adbc)). OIDC becomes necessary when you have separate brands/TLDs, third-party clients, differing trust levels between apps, or need standards federation ([Curity OAuth cookie best practices](https://curity.io/resources/learn/oauth-cookie-best-practices/)). Notably, even the IETF's browser-app guidance pushes *away* from tokens-in-the-browser toward cookie-fronted backends: the [OAuth 2.0 for Browser-Based Applications BCP](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/) (draft-26, in the RFC Editor queue since Dec 2025) ranks **BFF — backend holds tokens, browser holds only an HttpOnly cookie** — as the strongest pattern. So "cookie to the browser" is the endorsed endpoint either way; the question is only whether OIDC runs *behind* it.

**Hybrid worth knowing:** run a real (small) OIDC provider, but let all first-party apps share the SSO experience through the provider's own cookie — you get Shape A's UX with Shape B's escape hatch. This is what the recommendation in §9 does.

---

## 2. How commercial products structure it (frontend SDK + backend-verify split)

The striking convergence: **every product splits into (a) a frontend SDK that maintains a session and materializes a verifiable credential in the browser, and (b) a backend SDK/middleware that verifies that credential locally via JWKS, networklessly.**

### Clerk — the most instructive design
- **Frontend API (FAPI)** is hosted on a subdomain of *your* domain in production (`clerk.example.com`), making all auth traffic same-site ([How Clerk works](https://clerk.com/docs/guides/how-clerk-works/overview)).
- Two cookies: long-lived **`__client`** (HttpOnly, on the FAPI domain — the source-of-truth session reference) and **`__session`** (on the app domain, a **60-second JWT**, not HttpOnly so SDKs can read it) ([How We Roll – Sessions](https://clerk.com/blog/how-we-roll-sessions)).
- The frontend SDK refreshes `__session` on a **50-second interval** against FAPI; revocation deletes the server-side Session so no new JWT can be minted — "auth state is never invalid for more than 60 seconds."
- Backend SDKs (`authenticateRequest()`, `verifyToken()`) verify the JWT against the instance JWKS at `clerk.example.com/.well-known/jwks.json` — no network call per request ([manual JWT verification](https://clerk.com/docs/guides/sessions/manual-jwt-verification)).
- A **handshake redirect** re-mints the session token via the `__client` cookie when SSR requests arrive with an expired `__session` ([overview](https://clerk.com/docs/guides/how-clerk-works/overview)).
- Same-root subdomains share auth state by default; **satellite domains** exist only for *different* root domains ([satellite domains](https://clerk.com/docs/advanced-usage/satellite-domains)).

### Auth0
Centralized Universal Login on the tenant/custom domain; the Auth0 session cookie on that domain provides SSO; each app keeps its own application session; silent re-auth historically via `prompt=none` iframe — which depends on the auth cookie being first-party, hence Auth0's push for **custom domains** to make it same-site ([Session Layers](https://auth0.com/docs/manage-users/sessions/session-layers), [sessions docs](https://auth0.com/docs/sessions-and-cookies)). Default access-token lifetime is 24h (long by modern standards); refresh-token rotation and idle/absolute session lifetimes are configurable ([token lifetime docs](https://auth0.com/docs/secure/tokens/access-tokens/update-access-token-lifetime), [session lifetime limits](https://auth0.com/docs/manage-users/sessions/session-lifetime-limits)).

### Ory Kratos
Headless, API-first, deliberately **not** OIDC for first-party apps: browser apps just share the `ory_kratos_session` cookie (domain set to the parent domain) and backends call `/sessions/whoami` (opaque session, server-validated); non-browser clients use the same session as a bearer **session token** ([sessions overview](https://www.ory.com/docs/kratos/session-management/overview), [multi-domain cookies](https://www.ory.com/docs/kratos/guides/multi-domain-cookies)). OIDC is a separate add-on (Hydra) only when you need real OAuth clients. This is the strongest precedent for "Shape A is the right default for first-party."

### Supabase Auth
JWT-centric: since May 2025 new projects sign with **asymmetric keys (RS256/ES256)** by default; backends verify locally via `/auth/v1/.well-known/jwks.json`; `supabase.auth.getClaims()` verifies with WebCrypto without a network hop ([JWT signing keys blog](https://supabase.com/blog/jwt-signing-keys), [signing keys docs](https://supabase.com/docs/guides/auth/signing-keys), [getClaims](https://supabase.com/docs/reference/javascript/auth-getclaims)). Key lifecycle: **standby → current → previously-used → revoked**, with JWKS edge-cached 10 minutes.

### rauthy
A lightweight self-hosted Rust OIDC provider squarely aimed at the personal/homelab use case: full OIDC + OAuth2, **passkey-first**, device-code flow, RP-initiated *and* back-channel logout, `forward_auth` endpoint for apps with no OIDC support, embedded Hiqlite DB (no external Postgres needed), ~35–65 MB memory, "runs on a Raspberry Pi" ([GitHub](https://github.com/sebadob/rauthy), [docs](https://sebadob.github.io/rauthy/)). Ships a `rauthy-client` crate for token verification.

---

## 3. Token design

Two proven models, both validated by products above:

- **Model 1 — Clerk-style "stateful core, stateless edge"**: server-side session is the source of truth; the JWT the apps see is an ultra-short-lived (60 s) cache of it, continuously re-minted. Revocation latency ≤ token TTL; no refresh-token machinery exposed to apps at all ([Clerk sessions](https://clerk.com/blog/how-we-roll-sessions)).
- **Model 2 — Classic OAuth**: access JWT 15–60 min + rotating refresh token. [RFC 9700 (OAuth 2.0 Security BCP, Jan 2025)](https://datatracker.ietf.org/doc/rfc9700/) makes rotation-or-sender-constraining a **MUST** for public-client refresh tokens; rotation lets the server detect replay (old token reused → kill the whole family) ([Okta rotation guide](https://developer.okta.com/docs/guides/refresh-tokens/main/), [Auth0 refresh tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)).

**Consensus lifetimes** (Auth0/Okta/Curity/zuplo guidance): access token **5–15 min** (up to 60 for low-risk; Auth0's 24 h default is widely considered too long); refresh token **~30 days idle / 90 days absolute**, rotated on every use; server-side SSO session: idle timeout days-scale, absolute cap weeks-scale ([token best practices](https://auth0.com/docs/secure/tokens/token-best-practices), [token expiry best practices](https://dev.to/zuplo/token-expiry-best-practices-3feo)).

**JWKS & key rotation** (uniform across [Curity](https://curity.io/resources/learn/token-signing-key-rotation/), [Okta](https://developer.okta.com/docs/concepts/key-rotation/), [Supabase](https://supabase.com/docs/guides/auth/signing-keys), [Zalando](https://engineering.zalando.com/posts/2025/01/automated-json-web-key-rotation.html)):
1. Always put `kid` in the JWT header; verifiers select the key by `kid`, never hardcode keys.
2. **Publish-before-sign**: add the new public key to JWKS, wait out all verifier caches, then start signing with it.
3. Keep the old key published for a grace period ≥ longest token TTL + max JWKS cache TTL (Supabase: "if access tokens live 1 h, wait ≥ 1 h 15 m before revoking").
4. Verifiers cache JWKS (~10 min typical) and re-fetch on unknown `kid`.
5. Prefer **ES256/EdDSA asymmetric** keys so verification never requires sharing a secret.

---

## 4. Cookie mechanics across subdomains in 2026

The crucial 2026 fact: **"site" = scheme + eTLD+1.** `app1.example.com` ↔ `auth.example.com` is **same-site** (merely cross-origin). All the third-party-cookie carnage is about **cross-site** contexts and does not apply to sibling subdomains ([MDN third-party cookies](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Third-party_cookies), [same-site vs same-origin](https://medium.com/@nurettinabaci/samesite-cookies-d13b314aa9c3)).

- **`Domain=example.com`** → cookie sent to every subdomain. Omit `Domain` → host-only ([MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)).
- **SameSite**: `Lax` (the default) is sent on *all* subdomain requests including XHR/fetch, because they're same-site. `Strict` also works across subdomains, but blocks the cookie on the first navigation arriving from an external site (e.g., a link from an email to `app1.example.com`) — so **`Lax` is the right choice** for the shared session cookie. **`SameSite=None` is not needed at all** in a pure-subdomain setup.
- **Prefixes**: `__Host-` **forbids the `Domain` attribute**, so it cannot be used for a cross-subdomain cookie. Use **`__Secure-`** for the shared cookie (enforces Secure+HTTPS); reserve `__Host-` for any cookie that should be locked to one host (e.g., the CSRF cookie on `auth.example.com`) ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)).
- **CHIPS / 3P-cookie deprecation**: `Partitioned` cookies exist for cross-site embeds and require `SameSite=None; Secure` ([MDN CHIPS](https://developer.mozilla.org/docs/Web/Privacy/Privacy_sandbox/Partitioned_cookies)). Per Duende's April 2026 assessment, cross-site cookie blocking is now effectively complete across Safari (ITP), Firefox (Total Cookie Protection), and Chromium — killing iframe silent-renew, OIDC session-management iframes, and front-channel logout ([The Cookie Apocalypse Already Happened](https://duendesoftware.com/blog/20260414-the-cookie-apocalypse-already-happened)). **Confirmed: none of this touches subdomain SSO**, which is precisely why Clerk moved its FAPI onto a customer subdomain and why Auth0 sells custom domains — to make auth traffic same-site by construction.

---

## 5. CSRF strategy

A shared cookie sent automatically to every subdomain is a CSRF-relevant credential. Per the [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html):

- **SameSite is defense-in-depth, not the defense** — explicitly because a cookie is "still considered same-site when the request originates from `anything.example.com`": any XSS or subdomain takeover on a sibling subdomain bypasses SameSite entirely, and sibling subdomains can also *plant* cookies on the parent domain (cookie tossing).
- **Auth endpoints** (`auth.example.com` login/logout/flows): synchronizer tokens or signed double-submit bound to the flow — exactly what Kratos does with per-flow anti-CSRF cookies ([Ory CSRF settings](https://www.ory.com/docs/kratos/guides/multi-domain-cookies)). Logout must be POST-only with a token (or at minimum an unguessable confirmation), never a bare GET.
- **Apps consuming the session**: for JSON APIs the cheapest robust defense is **require a custom header** (e.g., `X-Requested-With` or `Origin` check) — cross-site HTML forms can't set custom headers, and enforcing `Content-Type: application/json` + rejecting form content-types closes the form vector. Add **`Origin`/`Sec-Fetch-Site` validation** server-side as a second layer. Use the signed double-submit pattern only where you must accept form posts.

---

## 6. Single logout across subdomains

This is where Shape A crushes Shape B:

- **Shared-cookie world**: logout = (1) delete the `Domain=example.com` cookie, (2) revoke the server-side session record. Every app is logged out instantly (opaque variant) or within ≤ JWT TTL (e.g., 60 s in the Clerk model). No protocol needed.
- **OIDC world**: each app holds its own session, so you need Single Logout machinery. **Front-channel logout (iframes) is effectively dead** — it relied on cross-site cookies ([Duende 2026](https://duendesoftware.com/blog/20260414-the-cookie-apocalypse-already-happened), [Curity OIDC logout](https://curity.io/resources/learn/openid-connect-logout/)). The industry recommendation is **back-channel logout** (server-to-server POST of a logout token to each client) — recently added even by authentik because front-channel is so unreliable ([authentik SLO](https://goauthentik.io/blog/2025-10-21-authentik-now-supports-single-logout/), [WorkOS on why SLO support is so limited](https://workos.com/blog/single-logout)) — plus RP-initiated logout via top-level redirect for the app the user clicked logout in. Within one subdomain family you can cheat: have each OIDC app *also* check a shared `logged_out`/session-version cookie or short-TTL tokens, converging back to Shape A semantics.

---

## 7. Non-browser clients (CLI, server-to-server) — lightweight approach

- **CLI tools (human-owned)**: **OAuth Device Authorization Grant (RFC 8628)** — CLI prints a URL + short code, user approves in any browser (where the SSO cookie already exists, so it's one click), CLI polls for tokens. This is the modern standard for CLI auth ([WorkOS CLI auth](https://workos.com/blog/cli-auth), [Logto's comparison of all 4 CLI methods](https://blog.logto.io/cli-authentication-methods)). rauthy supports it out of the box ([rauthy README](https://github.com/sebadob/rauthy)). A simpler local alternative is loopback redirect (open browser → redirect to `http://127.0.0.1:port/callback`), but device flow also works over SSH.
- **M2M**: **client-credentials flow** issuing short-lived scoped JWTs is the "right way" ([Auth0 M2M](https://auth0.com/blog/using-m2m-authorization/), [Authgear M2M guide](https://www.authgear.com/post/the-complete-guide-to-machine-to-machine-m2m-authentication/)) — services verify via the same JWKS as browser traffic.
- **Lightweight escape hatch**: for a personal system with 1–3 machine callers, plain **hashed API keys** (random 256-bit, stored hashed, prefix-identifiable, per-service, revocable) are legitimately fine and dramatically simpler; the M2M-token advantages (short life, scoping, rotation) matter at scale ([Logto programmatic auth comparison](https://blog.logto.io/programmatic-authentication-methods)). Start with API keys verified by the auth service (or minted *as* long-lived JWTs with a `kind: api_key` claim so the same JWKS verification path handles them); upgrade to client-credentials when a second consumer appears.

---

## 8. Local development story

The core problem: `localhost:3000` and `auth.example.com` are **cross-site**, so the production cookie model breaks in dev. How vendors solve it:

- **Clerk dev instances** abandon cookies entirely: a "dev browser" token (`__clerk_db_jwt`) is passed **via querystring** between localhost and the dev FAPI domain, because Safari et al. won't reliably carry cross-site cookies; Clerk explicitly documents this as insecure-but-acceptable for dev only, with production switching to the same-site `__client` cookie ([managing environments](https://clerk.com/docs/guides/development/managing-environments), [URL-based session syncing](https://clerk.com/docs/upgrade-guides/url-based-session-syncing)). Dev instances also use separate keys/domains (`*.accounts.dev`) and Clerk warns against using production keys on localhost ([troubleshooting](https://clerk.com/docs/guides/development/troubleshooting/using-production-keys-in-development)).
- **Ory** ships `ory tunnel`, a CLI proxy that **mirrors the auth API onto a localhost port** (`ory tunnel --dev http://localhost:3000`), rewriting cookie domains so the session and CSRF cookies become same-site with your app; they also warn `localhost` ≠ `127.0.0.1` for cookie purposes ([Ory local development](https://www.ory.com/docs/getting-started/local-development), [proxy & tunnel](https://www.ory.com/docs/guides/cli/proxy-and-tunnel)).
- **Self-hosted (rauthy/Supabase CLI)**: just run the whole stack locally in Docker — the cleanest story when the IdP is yours.

**For a personal system**, the two good options: (a) run the auth service locally via docker-compose and point apps at it; or (b) the nicer trick — use a **dev domain with subdomains that resolve to 127.0.0.1** (e.g., `*.localhost`, which browsers treat as a secure context and which supports parent-domain cookies: `app1.localhost` + `auth.localhost` + `Domain=localhost`, or a real wildcard DNS entry like `*.dev.example.com → 127.0.0.1` with a wildcard cert via mkcert/Caddy). That reproduces the exact same-site cookie topology of production — no Clerk-style querystring hacks needed because you own both sides.

---

## 9. Recommended design (one concrete pick)

**Shape A+ : a self-hosted auth service at `auth.example.com` issuing a shared-domain cookie carrying a short-lived JWT backed by a server-side session — i.e., the Clerk model, self-hosted — with OIDC (via rauthy or future Hydra) deliberately deferred until a non-first-party or cross-domain need appears.**

Rationale: all apps are first-party on one registrable domain, so per-app OIDC clients add redirect choreography, per-app token storage, and an unsolvable-without-back-channel SLO problem while buying nothing you need today (§1, §6). The subdomain cookie is fully insulated from the third-party-cookie apocalypse (§4). The session-backed short JWT gives JWKS-local verification *and* ≤60 s revocation — the best of stateless and stateful (§3).

> **Pragmatic alternative**: if you'd rather not write the auth service, deploy **[rauthy](https://github.com/sebadob/rauthy)** (passkeys, device flow, back-channel logout, `forward_auth`, runs in ~50 MB) and put **one** OIDC client — a thin gateway/BFF on `example.com` — in front of all apps, sharing its session cookie domain-wide. You still get the Shape-A consumption model; rauthy just owns credentials and flows.

### Concrete spec

**Auth service (`auth.example.com`)** — TypeScript (Hono/Effect) or Rust; SQLite/Postgres tables: `users`, `sessions`, `signing_keys`, `api_keys`.

**Login**: passkeys-first (+ email magic-link fallback). On success, create server-side session row `{id, user_id, created_at, last_seen_at, version}`.

**Cookies** (set by auth service):
```
__Secure-sid=<random 256-bit session id>;
  Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000   # 30d idle, source of truth

__Secure-jwt=<ES256 JWT, 5 min TTL>;
  Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax                     # the credential apps verify
```
- JWT claims: `sub`, `sid`, `iat`, `exp` (now + 5 min), `iss=https://auth.example.com`, plus app-agnostic role claims. 5 min (vs Clerk's 60 s) keeps refresh traffic negligible for a personal system while capping revocation latency at 5 min.
- Refresh: each app's middleware, on seeing an expired/absent `__Secure-jwt` but present `__Secure-sid`, does a **302 to `auth.example.com/refresh?return_to=...`** (same-site top-level navigation → cookies flow; this is Clerk's handshake). `refresh` validates the session row, re-mints the JWT cookie, redirects back. SPAs may instead call `auth.example.com/refresh` via `fetch` with `credentials: include` + CORS allow-listed sibling origins — still same-site, so cookies are sent.
- Absolute session cap: 90 days; idle cap: 30 days (`last_seen_at` bumped on refresh).

**Verification in apps** — one tiny shared middleware package: fetch `https://auth.example.com/.well-known/jwks.json` (cache 10 min, refetch on unknown `kid`), verify ES256 + `iss` + `exp`, attach `req.user`. No per-request network call. Key rotation: keep `current` + `previous` keys in JWKS; publish new key ≥ 15 min before signing with it; retire old key ≥ (5 min JWT TTL + 10 min cache) after switchover (per §3 consensus).

**CSRF**: all cookies `SameSite=Lax` + every state-changing app endpoint requires JSON content-type and an `Origin` header allow-listed to `*.example.com`; auth-service flows (login/logout) use per-flow synchronizer tokens. No state-changing GETs anywhere. (SameSite alone is insufficient per OWASP, §5.)

**Logout** (single logout for free): `POST auth.example.com/logout` (CSRF-protected) → delete session row, clear both cookies on `Domain=example.com`. All apps reject within ≤ 5 min (JWT expiry) and immediately on next refresh attempt. Panic button: bump `sessions.version` / delete all rows.

**CLI later**: add `POST /device/code` + `/device/token` (RFC 8628). The browser approval page rides the existing SSO cookie, so approval is one click. Tokens issued: 5-min JWT + rotating refresh token (rotation mandatory per RFC 9700, family-revoke on reuse).

**M2M later**: start with hashed API keys exchanged at `POST /token` for a 5-min JWT with `sub: svc:<name>` — same JWKS verify path as users; graduate to client-credentials if a real second party ever appears.

**Local dev**: wildcard `*.dev.example.com → 127.0.0.1` (or `auth.localhost`/`app1.localhost`) + mkcert/Caddy wildcard TLS + auth service in docker-compose. Identical same-site cookie topology as prod; no special dev mode (the lesson from Clerk's `__clerk_db_jwt` contortions is to avoid needing one).

**Future escape hatch**: if a third-party or cross-TLD client ever appears, bolt an OIDC authorization endpoint onto the auth service (or swap in rauthy) — the existing session cookie becomes the IdP session, and existing apps don't change.

---

## Sources

- Clerk: [How Clerk works](https://clerk.com/docs/guides/how-clerk-works/overview) · [Cookies](https://clerk.com/docs/guides/how-clerk-works/cookies) · [How We Roll: Sessions](https://clerk.com/blog/how-we-roll-sessions) · [Manual JWT verification](https://clerk.com/docs/guides/sessions/manual-jwt-verification) · [Satellite domains](https://clerk.com/docs/advanced-usage/satellite-domains) · [Dev environments](https://clerk.com/docs/guides/development/managing-environments) · [URL-based session syncing](https://clerk.com/docs/upgrade-guides/url-based-session-syncing) · [Production keys in dev](https://clerk.com/docs/guides/development/troubleshooting/using-production-keys-in-development)
- Auth0: [Session Layers](https://auth0.com/docs/manage-users/sessions/session-layers) · [App session management](https://auth0.com/blog/application-session-management-best-practices/) · [Token best practices](https://auth0.com/docs/secure/tokens/token-best-practices) · [Access token lifetime](https://auth0.com/docs/secure/tokens/access-tokens/update-access-token-lifetime) · [Refresh tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/) · [M2M](https://auth0.com/blog/using-m2m-authorization/) · [BFF pattern](https://auth0.com/blog/the-backend-for-frontend-pattern-bff/)
- Ory: [Sessions overview](https://www.ory.com/docs/kratos/session-management/overview) · [Multi-domain cookies](https://www.ory.com/docs/kratos/guides/multi-domain-cookies) · [Local development](https://www.ory.com/docs/getting-started/local-development) · [Proxy & Tunnel](https://www.ory.com/docs/guides/cli/proxy-and-tunnel)
- Supabase: [JWT signing keys blog](https://supabase.com/blog/jwt-signing-keys) · [Signing keys docs](https://supabase.com/docs/guides/auth/signing-keys) · [JWTs](https://supabase.com/docs/guides/auth/jwts) · [getClaims](https://supabase.com/docs/reference/javascript/auth-getclaims)
- rauthy: [GitHub](https://github.com/sebadob/rauthy) · [Docs](https://sebadob.github.io/rauthy/)
- Standards: [RFC 9700 OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/rfc9700/) · [OAuth for Browser-Based Apps draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/) · [WorkOS on RFC 9700](https://workos.com/blog/oauth-best-practices)
- Cookies/browser: [MDN Set-Cookie (prefixes, Domain, SameSite)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie) · [MDN third-party cookies](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Third-party_cookies) · [MDN CHIPS](https://developer.mozilla.org/docs/Web/Privacy/Privacy_sandbox/Partitioned_cookies) · [Duende: The Cookie Apocalypse Already Happened (Apr 2026)](https://duendesoftware.com/blog/20260414-the-cookie-apocalypse-already-happened) · [SameSite and subdomains](https://medium.com/@rramgattie/samesite-and-subdomains-08870bbdd62c) · [Understanding SameSite](https://andrewlock.net/understanding-samesite-cookies/)
- CSRF: [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- Logout: [Curity OIDC logout](https://curity.io/resources/learn/openid-connect-logout/) · [authentik SLO](https://goauthentik.io/blog/2025-10-21-authentik-now-supports-single-logout/) · [WorkOS Single Logout](https://workos.com/blog/single-logout)
- Tokens/keys: [Curity key rotation](https://curity.io/resources/learn/token-signing-key-rotation/) · [Okta key rotation](https://developer.okta.com/docs/concepts/key-rotation/) · [Okta refresh rotation](https://developer.okta.com/docs/guides/refresh-tokens/main/) · [Zalando JWK rotation](https://engineering.zalando.com/posts/2025/01/automated-json-web-key-rotation.html) · [WorkOS JWKS guide](https://workos.com/blog/developers-guide-jwks) · [Token expiry best practices](https://dev.to/zuplo/token-expiry-best-practices-3feo)
- CLI/M2M: [WorkOS CLI auth](https://workos.com/blog/cli-auth) · [Logto CLI auth methods](https://blog.logto.io/cli-authentication-methods) · [Logto programmatic auth](https://blog.logto.io/programmatic-authentication-methods) · [Authgear M2M guide](https://www.authgear.com/post/the-complete-guide-to-machine-to-machine-m2m-authentication/)
- General SSO patterns: [Curity OAuth cookie best practices](https://curity.io/resources/learn/oauth-cookie-best-practices/) · [Magic cookie SSO recipe](https://www.planetkodiak.com/architecture/web-sso-across-multiple-subdomains-using-the-magic-cookie-recipe/) · [Auth across subdomains](https://medium.com/@jsmmkt123/how-authentication-works-across-subdomains-and-why-most-developers-get-it-wrong-322a53a6adbc)