# Security review — 2026-06-12

> **Note — superseded in part by the email-free migration.** This review predates
> the removal of email/SES. Entries that reference email-OTP signup/recovery or the
> enroll→full session *upgrade* no longer apply: recovery is now one-time recovery
> codes, signup is passkey + proof-of-work, and a Full session is minted **only** by
> `login/finish` (registering a passkey never elevates). See `CLAUDE.md` and
> `docs/oidc-integration.md`.

A multi-agent adversarial review (5 dimension finders → independent skeptic per
finding) surfaced 35 candidate issues; 14 were refuted as false positives, 21
confirmed. Two were **high** severity and are fixed; the rest were low/medium
defense-in-depth, with the load-bearing ones fixed and the remainder documented
below.

## Fixed

| Severity | Issue | Fix |
|---|---|---|
| High | `amr` claimed `webauthn` after OTP-only recovery + passkey *enrollment* — no WebAuthn assertion ever happened, misleading RPs that gate on phishing-resistant auth. | `register_finish` no longer overwrites `amr`; enroll→full keeps `["otp"]`. Only `login_finish` (a real assertion) mints `["webauthn"]`. Refresh tokens now carry the originating session's real `amr` instead of a hardcoded value. (`webauthn.rs`, `token.rs`, `sessions.rs`) |
| High | Account recovery was additive: a mailbox compromise yielded a full session while the victim's sessions/refresh tokens stayed live and silent. | `recovery/verify` now revokes every existing session (and its refresh families, via the cascade) before issuing the recovery session — recovery is a reset. (`recovery.rs`) |
| High | IP rate-limit key came from the leftmost `X-Forwarded-For`, which is client-controlled → trivially bypassable. | `client_ip` now prefers CloudFront's tamper-proof `CloudFront-Viewer-Address`, falling back to the rightmost (proxy-appended) XFF. CloudFront is configured to forward that header. (`api/mod.rs`, `app-stack.ts`) |
| Medium | Session fixation: the enroll session id was reused after elevation to full. | `register_finish` rotates the session id on enroll→full and deletes the old one. (`webauthn.rs`) |
| Medium | Logout-CSRF: any valid `id_token_hint` (incl. an attacker's own) logged out the cookie's session. | `/oauth/logout` now requires the hint's `sub` to match the cookie session's user. (`logout.rs`) |
| Low | `userinfo` lacked `Cache-Control: no-store`. | Added. (`userinfo.rs`) |
| Low | `delete_user` did two non-transactional deletes (could orphan the email pointer). | Now a single `TransactWriteItems`. (`users.rs`) |
| Low | SDK didn't pin `alg`, didn't enforce `typ=logout+jwt`, and accepted logout tokens with neither `sub` nor `sid`. | `algorithms: ["ES256"]` on both verifies; `typ: "logout+jwt"` + sub/sid requirement on logout tokens. (`verify.ts`) |
| Low | SDK rehydrated `authenticated` from an unverified, possibly-expired stored ID token. | `userFromIdToken` now drops expired tokens (display-only; the access token remains the real, server-verified credential). (`auth-client.ts`) |

## Accepted / documented (no code change)

- **Fixed-window rate limiter allows ~2× burst at window boundaries.** Inherent
  to fixed windows; limits are generous and API Gateway stage throttling is the
  global backstop. The per-OTP attempt cap (5, item-level conditional write) is
  the real brute-force control, independent of the IP window.
- **OTP attempt cap resets on re-issue.** Bounded by the send limits
  (3/email/hour); a 6-digit code with ≤15 attempts/hour is negligible.
- **Timing/work asymmetry on signup/recovery start** (existing vs unknown
  account). Real but dominated by SES round-trip jitter and bounded by the send
  rate limits; the response status/body is uniform. Could be equalized by moving
  mail send off the response path if it ever matters.
- **Refresh token in `sessionStorage` is XSS-exfiltratable.** Inherent to the
  browser-only SPA model the SDK implements; mitigated with sessionStorage (not
  localStorage), memory-only access tokens, and rotation + reuse detection.
  **Now substantially mitigated by DPoP (RFC 9449):** the SDK sender-constrains
  both tokens to a non-extractable WebCrypto P-256 key (in IndexedDB), so an
  exfiltrated refresh token can't be redeemed and a DPoP-bound access token is
  rejected at userinfo without a fresh proof for the same key. This collapses
  "steal once, replay anywhere" into "must run code in the live session" — a
  large but not total reduction (an in-page payload can still use the key as a
  signing oracle while it runs; a strict CSP is the load-bearing control). DPoP
  is honored, not required, so plain-bearer clients keep working during rollout.
  The all-public-client posture rules out a confidential BFF, so DPoP — not the
  BFF sketched in `docs/research/sso-patterns.md` — is the sender-constraint.
- **`get_session_by_hash` returns expired sessions** (the one caller checks
  expiry). Latent API trap, not a live bug.

## Staged hardening — flip when ready

Two protections ship in observe/opt-in mode because flipping them blind would
break production; each has a clear gate and a one-line change to enforce.

- **Trusted Types → enforce.** The SPA sends `Content-Security-Policy-Report-Only:
  require-trusted-types-for 'script'` with a `report-to` sink at `/api/reports`
  (logged as audit `csp_report`). Flip it into the *enforced* CSP only after the
  reports show that react-dom 19 / Radix / sonner never touch a TT-guarded sink
  in prod — and add a Trusted Types default policy first if they do. Until then,
  enforcing risks throwing on a dependency's sink write.
- **DPoP → required (per client).** `OidcClient.require_dpop` (default `false`)
  makes the token endpoint reject a client's bearer (no-proof) requests. Flip it
  to `true` per RP in `config/clients.json` *after* that RP upgrades to the
  DPoP-capable SDK (`@ericminassian/auth` ≥ the cnf/DPoP release) — flipping
  early breaks its logins. The AWS-managed WAF rule sets are staged the same way
  (COUNT before BLOCK; see `infra/lib/stacks/app-stack.ts`).
- **HSTS preload submission (manual).** The SPA and API already send
  `Strict-Transport-Security: max-age=31536000; includeSubdomains; preload`, but
  the browser preload list is opt-in: submit `ericminassian.com` at
  <https://hstspreload.org> once (it covers `auth.` via `includeSubdomains`).
  This is a one-time operator action — there is no code change. A CAA record now
  pins certificate issuance to Amazon's CAs (ACM), and
  `/.well-known/security.txt` (RFC 9116) publishes the disclosure contact.
