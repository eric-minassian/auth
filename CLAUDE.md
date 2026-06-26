# auth — project conventions

Personal OIDC provider at auth.ericminassian.com. Full plan & rationale: `docs/research/` (verified June 2026 — versions and patterns there are load-bearing; re-verify before "upgrading" away from them). **The email-free migration supersedes the email-OTP signup/recovery in older notes**: there is no email/SES anywhere — signup is passkey + proof-of-work, recovery is one-time recovery codes (see the rules below).

## Non-negotiable design rules

- **No passwords, no email, no SMS, no out-of-band channel — ever.** Passkeys (webauthn-rs) are the only auth factor; **one-time recovery codes** are the only break-glass; a **client-side proof-of-work** gates signup. Never add argon2/password fields, and never reintroduce SES/email or any messaging channel.
- **Usernameless identity.** An account is an opaque `user_id` (UUIDv7, also the WebAuthn user handle) plus a non-unique, mutable `nickname` (display only — never an identifier). No email, no username.
- **WebAuthn RP ID = `auth.ericminassian.com`** (the issuer host). IRREVERSIBLE — changing it orphans every passkey.
- **Full sessions are login-only.** A user-verified WebAuthn assertion (`login/finish`) is the ONLY path to a Full session. Signup, recovery, and add-passkey yield an **Enroll** session that can only register passkeys. `/oauth/authorize` additionally gates on account `status == Active`.
- **Recovery is unrecoverable by design.** Lose all passkeys AND all recovery codes → permanent loss. No backdoor, KBA, or help-desk reset (any such override would be the weakest link).
- **OAuth 2.1 posture**: PKCE S256 required for every client, no implicit/password grants, exact redirect URI string match (validate redirect_uri BEFORE redirecting any error to it). Only the **granted** scope (`requested ∩ client ∩ supported`) is stored and echoed — a client can never obtain a scope (or refresh token) it isn't registered for.
- **OIDC issues no email.** id_token/userinfo carry `sub` (= user_id); `nickname` + `updated_at` only under the `profile` scope. RPs must key identity on `iss`+`sub`; `nickname` is mutable display data they must HTML-escape and must not key on.
- **Secrets at rest are hashes**: session ids, auth codes, refresh secrets, and recovery codes are stored as SHA-256 only (recovery codes are 128-bit, so plain SHA-256 needs no KDF). Constant-time compares via `subtle`.
- **DynamoDB TTL is garbage collection, not enforcement** — every read of a TTL'd item must also check its `expires_at` attribute (pending users, recovery codes, PoW challenges, ceremonies, sessions).
- **One-time-use via conditional writes**: auth codes (used_at tombstone → replay revokes the refresh family), refresh rotation (single UpdateItem conditioned on current_token_hash; mismatch = reuse = revoke family), recovery codes & PoW challenges (conditional DeleteItem RETURN ALL_OLD, `expires_at` re-checked), ceremonies (DeleteItem RETURN ALL_OLD). Recovery-code rotation is write-new-before-delete-old; generation requires a fresh WebAuthn step-up (`reauth_at`).
- **Session cookie is host-only** `__Host-auth_session` (SameSite=Lax). SSO works because sibling subdomains are same-site — never set a Domain= cookie.
- **Key rotation is publish-before-sign** (JWKS serves next+current+retired; flip after verifier caches expire).
- **CSRF on /api/***: require `Content-Type: application/json` + allow-listed `Origin`. No state-changing GETs.
- **Abuse**: IPv6 rate-limit keys bucket to /64 + per-ASN; NO global signup/recovery caps (a mass-DoS lever); in prod a CloudFront-injected `x-origin-verify` secret (`ORIGIN_VERIFY_SECRET`) locks the API Gateway origin so the viewer-header-derived keys are trustworthy.
- **Anti-enumeration is structural**: usernameless accounts + discoverable login + 128-bit code recovery = nothing to enumerate. Keep uniform errors + rate limiting as defense-in-depth.
- Never log tokens, codes, recovery codes, or secrets. Audit events use `tracing` target="audit".

## Workflow

- pnpm only. Rust: clippy `-D warnings`, no `unwrap`/`expect`/`panic` in src (workspace lints deny them).
- `cargo test` needs Docker (testcontainers DynamoDB Local).
- After changing any HTTP handler/schema: `pnpm generate` (re-exports openapi.json + SDK types); CI fails on drift.
- Local stack: `pnpm dev`, browse `http://auth.localhost:5173`.
- CDK is multi-account, env selected via `cdk --context env=<local|prod>` (`infra/config/environments.ts`). **Prod auto-deploys on merge to main** (`deploy.yml`: checks → build → `cdk deploy --context env=prod`). **local** deploys are manual into a dev's own account. CI→AWS auth is GitHub OIDC (`AuthCiRoleStack`, deployed once per account out-of-band). DNS subdomains self-delegate cross-account from the `~/projects/aws` org repo. CDK code follows the `cdk` skill conventions. Full topology + one-time bring-up: `docs/deploy.md`.
