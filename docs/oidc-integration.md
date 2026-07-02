# Integrating with auth.ericminassian.com

This is a **passwordless, email-free** OpenID Connect provider. Read this before
wiring an RP — a couple of its properties are deliberately unusual.

## No email, ever

The IdP holds **no email address** for any user and never will. Consequences for RPs:

- There is **no `email` claim and no `email` scope**. Requesting `scope=email`
  is not an error — the scope is silently dropped and the flow succeeds without it.
  The IdP will **never** fabricate a synthetic address (e.g. `user@…`); don't treat
  one as deliverable or as an identity key.
- Some libraries/proxies hard-require an `email` (or `preferred_username`) claim and
  will break against a conformant email-less IdP. That is their bug, not ours.

## Key identity on `iss` + `sub`

- `sub` is a stable, opaque, never-reassigned `user_id` (UUIDv7). It is the **only**
  identifier you may key a local account on. Anchor on the `(iss, sub)` pair
  (OIDC Core §5.7).
- `subject_types_supported` is `["public"]`: the same `sub` is issued to every client
  for a given user. (A future pairwise option may be added per-client; it would not
  change existing clients' `sub`.)

## `profile` scope and the `nickname` claim

- Request `scope=openid profile` to receive `nickname` and `updated_at` (in the
  id_token and from `userinfo`).
- `nickname` is **user-chosen, non-unique, and mutable**. It is display data only:
  **HTML-escape it**, and **never** use it as an identifier, a uniqueness key, or a
  security decision.

## Scopes are intersected, not echoed verbatim

The granted scope is `requested ∩ registered ∩ supported`. A client only receives
(and only ever sees echoed) the scopes it is registered for — notably, a client not
registered for `offline_access` gets **no refresh token**, even if it asks.

## Assurance: `acr` / `amr` and step-up (RFC 9470)

Every login is a user-verified, phishing-resistant passkey assertion, so tokens
carry `amr: ["webauthn"]` and `acr: "phr"` (in the id_token **and** the JWT
access token, so a resource server can gate on assurance without a `userinfo`
round-trip). `acr_values_supported` is `["phr-stepup", "phr"]`.

To force a **fresh** assertion before a sensitive action (RFC 9470):

1. Your API returns `401` with
   `WWW-Authenticate: DPoP error="insufficient_user_authentication", acr_values="phr-stepup"`.
   The SDK's `stepUpChallenge({ acrValues: "phr-stepup" })` builds this header.
2. The client re-authenticates with `acr_values=phr-stepup` (SDK:
   `signInWithRedirect({ acrValues: "phr-stepup" })`); the IdP performs a fresh
   passkey assertion and returns a token with `acr: "phr-stepup"`.

`acr: "phr-stepup"` is point-in-time — it is **not** carried across refreshes
(a refreshed token drops back to `acr: "phr"`). Re-challenge when you need it again.

## Sender-constrained tokens (DPoP, RFC 9449)

Tokens can be sender-constrained to a non-extractable client key: a bound access
token carries a `cnf.jkt` and is useless without a fresh proof signed by that key.
The SDK enables this automatically in the browser. On the resource-server side,
`createAuthVerifier` verifies the proof by default whenever a token is bound
(`dpop: { mode: "auto" }`) — so a bound token can't be downgraded to a plain
bearer — with `"required"` and `"disabled"` modes available. The express/hono
adapters wire this up; a hand-built `Request` must carry the real method/URL and
the `DPoP` header. `require_dpop` can be set per client to reject unbound tokens
at the token endpoint outright.

The token endpoint requires a **server-provided nonce** in every proof
(RFC 9449 §8): a proof without one is answered with
`400 {"error":"use_dpop_nonce"}` plus a `DPoP-Nonce` header, and the client
retries once with the nonce echoed in a fresh proof. The SDK (and any
conformant DPoP client) does this transparently; nonces stay valid for at
least five minutes, so steady-state traffic pays no extra round-trips.

## Everything else is standard OAuth 2.1 / OIDC

PKCE S256 is mandatory for every client; exact `redirect_uri` string match; auth-code
+ refresh-token grants only (no implicit/password); refresh rotation with reuse
detection; back-channel logout + RP-initiated logout. See
`/.well-known/openid-configuration`.

## How users authenticate (FYI — not your concern as an RP)

Sign-in is a passkey (WebAuthn) assertion; account recovery is one-time recovery
codes. There is no email/SMS fallback. A user who loses all passkeys **and** all
recovery codes is permanently locked out by design — there is no admin reset.
