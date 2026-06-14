# auth

Personal OIDC provider at **auth.ericminassian.com** — SSO for first-party apps on `*.ericminassian.com`.

- **Passkeys-only** authentication (WebAuthn; no passwords). Email + OTP for signup verification and account recovery.
- **Full OIDC**: authorization code + PKCE (S256 only), discovery, JWKS, refresh rotation with reuse detection, back-channel logout. OAuth 2.1 posture.
- **AWS serverless**: one Rust Lambda (axum), DynamoDB single table, CloudFront + S3 SPA, KMS ES256 signing, SES email.

## Layout

| Path | What |
|---|---|
| `crates/auth-service` | Rust service (axum). Bins: `bootstrap` (Lambda), `local` (dev server), `export-openapi` |
| `apps/web` | React SPA (Vite, Tailwind v4, [@eric-minassian/design](https://github.com/eric-minassian/design)) — login/signup/account UI |
| `packages/auth-sdk` | `@ericminassian/auth` — TypeScript SDK (`/client`, `/react`, `/server`) |
| `infra` | AWS CDK (TypeScript), us-east-1 |
| `openapi/openapi.json` | Generated API contract (utoipa) — committed, CI checks drift |
| `config/clients.json` | OIDC client registry, seeded to DynamoDB |
| `docs/research/` | Architecture research underpinning the design decisions |

## Development

```sh
pnpm install
pnpm dev          # DynamoDB Local + Rust API on :8787 + Vite on :5173
```

Browse at `http://auth.localhost:5173` (same-site cookie parity with production; WebAuthn RP ID is `auth.localhost` in dev). OTP emails print to the API process stdout in dev; Playwright reads them from `/api/dev/last-otp`.

```sh
cargo test                      # integration tests (testcontainers DynamoDB; needs Docker)
pnpm typecheck && pnpm build
```
