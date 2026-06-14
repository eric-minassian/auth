# auth — project conventions

Personal OIDC provider at auth.ericminassian.com. Full plan & rationale: `docs/research/` (verified June 2026 — versions and patterns there are load-bearing; re-verify before "upgrading" away from them).

## Non-negotiable design rules

- **No passwords.** Passkeys (webauthn-rs) + email OTP only. Never add argon2/password fields.
- **OAuth 2.1 posture**: PKCE S256 required for every client, no implicit/password grants, exact redirect URI string match (validate redirect_uri BEFORE redirecting any error to it).
- **Secrets at rest are hashes**: session ids, auth codes, refresh secrets, OTPs are stored as SHA-256 only. Constant-time compares via `subtle`.
- **DynamoDB TTL is garbage collection, not enforcement** — every read of a TTL'd item must also check its `expires_at` attribute.
- **One-time-use via conditional writes**: auth codes (used_at tombstone → replay revokes the refresh family), refresh rotation (single UpdateItem conditioned on current_token_hash; mismatch = reuse = revoke family), OTP (ADD attempts cond < 5, then conditional delete), ceremonies (DeleteItem RETURN ALL_OLD).
- **Session cookie is host-only** `__Host-auth_session` (SameSite=Lax). SSO works because sibling subdomains are same-site — never set a Domain= cookie.
- **Key rotation is publish-before-sign** (JWKS serves next+current+retired; flip after verifier caches expire).
- **CSRF on /api/***: require `Content-Type: application/json` + allow-listed `Origin`. No state-changing GETs.
- Anti-enumeration: signup/recovery start endpoints return uniform 200 regardless of account existence.
- Never log tokens, codes, OTPs, or emails. Audit events use `tracing` target="audit".

## Workflow

- pnpm only. Rust: clippy `-D warnings`, no `unwrap`/`expect`/`panic` in src (workspace lints deny them).
- `cargo test` needs Docker (testcontainers DynamoDB Local).
- After changing any HTTP handler/schema: `pnpm generate` (re-exports openapi.json + SDK types); CI fails on drift.
- Local stack: `pnpm dev`, browse `http://auth.localhost:5173`.
- CDK is multi-account, env selected via `cdk --context env=<local|prod>` (`infra/config/environments.ts`). **Prod auto-deploys on merge to main** (`deploy.yml`: checks → build → `cdk deploy --context env=prod`). **local** deploys are manual into a dev's own account. CI→AWS auth is GitHub OIDC (`AuthCiRoleStack`, deployed once per account out-of-band). DNS subdomains self-delegate cross-account from the `~/projects/aws` org repo. CDK code follows the `cdk` skill conventions. Full topology + one-time bring-up: `docs/deploy.md`.
