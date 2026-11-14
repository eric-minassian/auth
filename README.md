# auth

An anonymous, PII-free authentication service. Users sign in with passkeys
only; there are no usernames, emails, phone numbers or passwords. Sessions are
bound to a key that never leaves the user's device, so sign-in is a single tap
on a new device and invisible everywhere else.

It does authentication only: it tells your services *which account* is calling,
and your services decide what that account may do.

## Highlights

- **Passkeys only** (WebAuthn Level 3) with user verification. Phishing-resistant,
  with no fallbacks that could be phished instead.
- **No PII anywhere**: accounts are random IDs; storage holds public keys,
  hashes and timestamps; logs carry no IP addresses or user agents.
- **Device-bound sessions** (DPoP, RFC 9449): stolen tokens are useless without
  the device's non-extractable key. Sessions renew silently for 30 days of
  inactivity, up to one year.
- **Standards throughout**: OAuth 2.0 token endpoint and errors (RFC 6749),
  JWT access tokens (RFC 9068), JWKS (RFC 7517), authorization server metadata
  (RFC 8414), resource indicators (RFC 8707), step-up (RFC 9470), OAuth security
  BCP (RFC 9700).
- **Formally verified**: every security decision is proven correct with Verus,
  the parsers are model-checked with Kani, and the protocol is proven secure in
  Tamarin. See [docs/verification.md](docs/verification.md) for exactly what is
  and isn't proven.

## Repository layout

| Path | What |
|---|---|
| [`docs/protocol.md`](docs/protocol.md) | The protocol: endpoints, token formats, DPoP and WebAuthn profiles, storage |
| [`docs/verification.md`](docs/verification.md) | What is proven, by which tool, and the trusted computing base |
| [`docs/threat-model.md`](docs/threat-model.md) | Threats, mitigations and accepted risks |
| [`crates/auth-core`](crates/auth-core) | The verified core: WebAuthn, DPoP and token checks (Verus + Kani), parsers |
| [`crates/auth-service`](crates/auth-service) | The service: axum on AWS Lambda (or a local server), DynamoDB, KMS |
| [`crates/auth-verifier`](crates/auth-verifier) | For your services: verifies DPoP-bound access tokens, with an axum extractor |
| [`sdk/web`](sdk/web) | TypeScript web SDK: sign-up, sign-in, silent sessions, `auth.fetch` |
| [`infra`](infra) | AWS CDK: API Gateway + WAF, Lambda, DynamoDB, KMS |
| [`model`](model) | Tamarin model of the protocol |
| [`fuzz`](fuzz) | cargo-fuzz targets for the parsers and checks |
| [`scripts`](scripts) | Tool installation, local development, proofs |

## Architecture

```
 Browser / app                          AWS
 ┌──────────────────────┐   HTTPS   ┌─────────┐   ┌──────────────────────────┐
 │ passkey (platform)   │──────────▶│   WAF   │──▶│ API Gateway (REST, regional)
 │ DPoP key (non-extr.) │           └─────────┘   └────────────┬─────────────┘
 │ @…/auth-web SDK      │                                      ▼
 └──────────┬───────────┘                         ┌──────────────────────────┐
            │ Authorization: DPoP <token>         │ Lambda: auth-service     │
            │ DPoP: <proof>                       │  └─ auth-core (verified) │
            ▼                                     └──┬───────────────┬───────┘
 ┌──────────────────────┐                            ▼               ▼
 │ Your API             │  JWKS (cached)       ┌───────────┐   ┌───────────┐
 │  └─ auth-verifier    │◀─────────────────────│ DynamoDB  │   │ KMS (sign,│
 │     (verified check) │                      │ 1 table   │   │ HMAC)     │
 └──────────────────────┘                      └───────────┘   └───────────┘
```

## Quick start (local)

Prerequisites: Rust (the toolchain in `rust-toolchain.toml` installs
automatically), the AWS CLI, and [aws-emulator](https://github.com/aws/aws-emulator)
for local DynamoDB and KMS (`scripts/install-tools.sh emulator` installs the
pinned version without root).

```sh
scripts/local-dev.sh          # emulator + table + keys + service on http://localhost:8080
curl http://localhost:8080/.well-known/oauth-authorization-server
```

`local-dev.sh` configures the service for a web app on `http://localhost:5173`
(RP ID `localhost`). See [`sdk/web/README.md`](sdk/web/README.md) for the client.

## Checks

| Command | What it runs |
|---|---|
| `cargo test --workspace --all-features` | Unit, property and integration tests (service tests need `eval "$(scripts/emulator.sh)"`; they are skipped otherwise) |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Lints |
| `cd crates/auth-core && cargo verus verify` | Verus proofs |
| `cd crates/auth-core && cargo kani --jobs 8` | Kani harnesses |
| `scripts/e2e-sdk.sh` | The web SDK against the real service (aws-emulator) |
| `cd sdk/web && npm test` / `cd infra && npm test && npm run synth` | SDK and infrastructure tests (synth runs cdk-nag) |
| `scripts/prove-model.sh` | Tamarin protocol proofs |
| `cd fuzz && cargo +nightly fuzz run <target>` | Fuzzing (`encodings`, `cbor_cose`, `wire`, `webauthn`, `jose`) |
| `cargo deny check` | Dependency advisories, licenses and sources |
| `cargo lambda build --release --arm64 -p auth-service` | The Lambda artifact |

`scripts/install-tools.sh all` installs the pinned Verus, Kani, Tamarin, Maude
and aws-emulator versions, with checksums verified. CI runs all of the above
(`.github/workflows`).

## Deploying

See [`infra/README.md`](infra/README.md). The service needs a custom domain
(the issuer), an ACM certificate, and the Lambda artifact built as above.

## Status

The service, SDK, infrastructure and proofs are complete and tested locally
against aws-emulator. Mobile (iOS/Android) and CLI clients use the same
endpoints and are follow-up work; the protocol already supports them (Android
origins, `client_id`s, DPoP keys from the Secure Enclave or Android Keystore).

Security issues: see [SECURITY.md](SECURITY.md).
