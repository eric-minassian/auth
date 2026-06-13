# Rust Stack for a Standalone Auth/Identity Service (axum on AWS Lambda) — June 2026

All crate versions below were verified against the crates.io API on 2026-06-12.

---

## 1. Web framework: axum 0.8 — still the default choice

- **Current version: axum 0.8.9** (released 2026-04-14); 349M total downloads ([crates.io](https://crates.io/api/v1/crates/axum)). The 0.8 line brought `/{id}` path syntax, native async traits, and better error messages.
- 2026 framework comparisons consistently call axum "the pragmatic default for new projects" — Tokio-team backed, Tower/Hyper-native, fastest-growing by downloads, surpassing Actix Web some months ([Rustfinity](https://www.rustfinity.com/blog/axum-rust-tutorial), [Medium framework comparison](https://aarambhdevhub.medium.com/rust-web-frameworks-in-2026-axum-vs-actix-web-vs-rocket-vs-warp-vs-salvo-which-one-should-you-2db3792c79a2), [SharpSkill](https://sharpskill.dev/en/blog/rust/rust-actix-web-vs-axum-comparison)).
- Nothing in 2026 displaces it for an auth service: Actix Web is fine but its ecosystem (actix middleware) is siloed from Tower; the Tower ecosystem is precisely what you want (tower-sessions, tower-governor, `lambda_http` all speak `tower::Service`).
- **Lambda fit is the clincher**: `lambda_http::run()` is a thin wrapper accepting any `tower::Service<http::Request>` — an axum `Router` plugs in directly, no adapter process needed ([Jun.codes tutorial](https://jun.codes/blog/kickstarting-rust-on-aws-lambda), [aws-lambda-rust-runtime](https://github.com/aws/aws-lambda-rust-runtime)).
- **Rust on Lambda is now officially GA**: AWS announced general availability on 2025-11-14, backed by AWS Support and the Lambda SLA, all regions including GovCloud/China ([AWS What's New](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-lambda-rust), [AWS Weekly Roundup Nov 17 2025](https://aws.amazon.com/blogs/aws/aws-weekly-roundup-aws-lambda-load-balancers-amazon-dcv-amazon-linux-2023-and-more-november-17-2025/), [InfoQ](https://infoq.com/news/2025/11/aws-lambda-rust-support-ga/)). Cold starts for Rust on `provided.al2023` are reported in the 12–22 ms range ([Nandann production guide](https://www.nandann.com/blog/rust-aws-lambda-production-guide) — single source for the exact numbers, but directionally corroborated everywhere).

## 2. Password hashing: RustCrypto `argon2` 0.5.3

- **Current stable: argon2 0.5.3**; a 0.6.0 line is in release-candidate stage (0.6.0-rc.8, 2026-03) — stay on 0.5.x until 0.6 stabilizes ([crates.io](https://crates.io/crates/argon2), [RustCrypto/password-hashes](https://github.com/RustCrypto/password-hashes)). Pure Rust, supports Argon2id, integrates with the `password-hash` PHC-string ecosystem. This is also what rauthy uses in production.
- **OWASP current guidance** ([Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)): Argon2id first choice, with five equivalent configs trading CPU vs RAM; the headline ones are **m=19456 KiB (19 MiB), t=2, p=1** and m=12288 (12 MiB), t=3, p=1. scrypt only if Argon2id unavailable; bcrypt for legacy systems only; pepper is optional defense-in-depth.
- **Lambda-specific advice**: Lambda allocates CPU proportional to memory. Configure the function at ≥512 MB–1 GB and you can comfortably exceed OWASP minimums (e.g. m=64 MiB, t=3, p=1). Run hashing inside `tokio::task::spawn_blocking` so you don't stall the reactor. Note `Argon2::default()` in the crate already matches OWASP's 19 MiB/t=2/p=1 minimum.

## 3. Sessions and JWT issuance

**Server-side sessions: tower-sessions 0.15.0** (2026-02-01) — the maintained successor to axum-sessions, Django-inspired semantics, `Session` works as an axum extractor, pluggable `SessionStore` ([GitHub](https://github.com/maxcountryman/tower-sessions), [docs.rs](https://docs.rs/tower-sessions/latest/tower_sessions/)). Caveat for your stack: the community [tower-sessions-dynamodb-store](https://github.com/necrobious/tower-sessions-dynamodb-store) is at 0.3.0 (Jan 2025) and pins **tower-sessions 0.14**, so you'd either pin 0.14 or vendor the store (it's ~one file). For a Lambda-deployed token service, I'd skip cookie sessions for API auth entirely and use short-lived JWTs + opaque refresh tokens in DynamoDB (with TTL attribute) — sessions only matter if you serve a browser-based login UI from the same service.

**JWT signing: jsonwebtoken 10.x is now the clear winner.**

| Crate | Version | ES256 | EdDSA | JWKS | Notes |
|---|---|---|---|---|---|
| **jsonwebtoken** | **10.4.0** (2026-05-11) | ✅ | ✅ | parse ✅ / publish: build JWK yourself | v10 (2025-09-29) rearchitected onto pluggable backends — you choose **`aws_lc_rs`** or `rust_crypto`; added JWS support, `TryFrom<&Jwk> for DecodingKey`, Ed25519 JWK thumbprints fixed in 10.4 ([changelog](https://github.com/Keats/jsonwebtoken/blob/master/CHANGELOG.md)) |
| josekit | 0.10.3 (2025-05) | ✅ | ✅ (Ed25519/Ed448) | ✅ full JWK/JWE | Binds **OpenSSL ≥1.1.1** ([repo](https://github.com/hidekatsu-izuno/josekit-rs)) — friction for `provided.al2023` static Lambda builds (needs vendored OpenSSL, slow builds). Only pick if you need JWE. |
| RustCrypto `jose-jwk` etc. | 0.1.2 (Aug **2023**) | — | — | — | Pre-1.0 and stale; not production-ready ([crates.io](https://crates.io/crates/jose-jwk)) |

Older comparisons claiming jsonwebtoken lacks EdDSA are outdated — that's been supported for years and v10 hardened it. The `jwk` module is explicitly "meant to deal with public JWK, not generate ones" ([docs.rs](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/jwk/index.html)), so for **JWKS publishing** you serialize your own `{"kty":"OKP","crv":"Ed25519","x":...,"kid":...}` / P-256 JWK JSON — ~30 lines, exactly what rauthy does internally. Recommendation: **EdDSA (Ed25519) as default signing alg, ES256 offered for clients that can't verify EdDSA** (rauthy made the same default).

## 4. Passkeys: webauthn-rs 0.5.5

- **Current stable: 0.5.5** (0.6.1-dev in progress as of 2026-04-30); from the kanidm project, MPL-2.0, the de-facto standard server-side WebAuthn crate — rauthy uses it in production ([crates.io](https://crates.io/crates/webauthn-rs), [docs.rs](https://docs.rs/webauthn-rs/latest/webauthn_rs/)).
- API shape: `WebauthnBuilder` (RP ID + origin) → `Webauthn` with the four-ceremony API: `start_passkey_registration` / `finish_passkey_registration` / `start_passkey_authentication` / `finish_passkey_authentication`, with a `Passkey` credential type you persist.
- On Lambda you **must** enable `danger-allow-state-serialisation` to stash `PasskeyRegistration`/`PasskeyAuthentication` state in DynamoDB between start/finish (safe per the docs when state lives server-side; never in client-readable cookies). `conditional-ui` feature enables username-less autofill flows.
- Don't confuse with 1Password's [passkey-rs](https://github.com/1Password/passkey-rs) — that's for building authenticators/clients, not relying parties.

## 5. Social login (client side): oauth2 + openidconnect

- **oauth2 5.0.0** (2025-01-21) and **openidconnect 4.0.1** (2025-07-06), both by ramosbugs, both actively maintained with explicit MSRV policies; openidconnect is built on oauth2 and is the recommended choice for sign-in flows ([crates.io oauth2](https://crates.io/crates/oauth2), [docs.rs openidconnect](https://docs.rs/openidconnect/latest/openidconnect/), [lib.rs](https://lib.rs/crates/oauth2)).
- Strongly typed (typestate prevents forgetting PKCE/nonce), supports discovery, JWKS fetching, ID-token verification. Use **openidconnect for Google** (full OIDC) and **oauth2 for GitHub** (GitHub is OAuth2-only, not OIDC — you fetch `/user` yourself).

## 6. Building the OIDC *provider*: hand-roll it (verified against rauthy)

- **There is no maintained "ory hydra in Rust" library.** [oxide-auth](https://docs.rs/oxide-auth/latest/oxide_auth/) (0.6.1) had its last release **June 2024**, and is OAuth2-only — no ID tokens, no discovery, no OIDC ([users.rust-lang discussion](https://users.rust-lang.org/t/is-there-any-openid-connect-provider/76824)).
- **rauthy** ([github.com/sebadob/rauthy](https://github.com/sebadob/rauthy), v0.35.2, 2026-05-19) is the proof-by-existence: a production Rust IdP whose workspace Cargo.toml contains **no OIDC-provider framework crate at all**. It hand-rolls the `/authorize`, `/token`, `/userinfo`, `/.well-known/openid-configuration`, JWKS endpoints on actix-web, signs tokens directly with `ring` + `ed25519-compact` + `rsa`, hashes with `argon2` 0.5, does passkeys with `webauthn-rs` 0.5, defaults to **ed25519 signing and S256 PKCE** ([Rauthy docs](https://sebadob.github.io/rauthy/)). It is a standalone product (Svelte UI, Hiqlite/Postgres), not a reusable library.
- **Verdict**: hand-rolling authorization-code + PKCE is the pragmatic and industry-validated path. The surface area is bounded: `/.well-known/openid-configuration` (static JSON), `/jwks.json` (serialize your public keys), `/authorize` (validate client_id/redirect_uri/PKCE challenge, persist a one-time code in DynamoDB with TTL), `/token` (exchange code + verifier, mint ID/access/refresh tokens via jsonwebtoken), `/userinfo`. Follow the **OAuth 2.1 draft posture**: PKCE required for all clients, no implicit grant, no password grant, exact redirect URI matching, refresh-token rotation with reuse detection. If you ever outgrow that, the realistic alternative is deploying rauthy itself, not a crate.

## 7. Supporting crates

| Concern | Pick | Version | Notes |
|---|---|---|---|
| Validation | **garde** | 0.23.0 (2026-05-23) | More actively developed than validator (0.20.0, Jan 2025); derive-based, context-aware ([crates.io](https://crates.io/crates/garde)). validator is also fine if you prefer maturity. |
| Rate limiting | **tower_governor** | 0.8.0 (2025-08) | Tower layer over `governor`; per-IP/custom-key ([GitHub](https://github.com/benwis/tower-governor)). **Lambda caveat**: state is per-instance memory — it only protects within one warm instance. Do real throttling at API Gateway/WAF, and implement per-account login-attempt lockout as DynamoDB conditional-update counters. |
| TOTP | **totp-rs** | 5.7.1 (2026-03-09) | RFC-compliant, QR/otpauth-URL helpers ([crates.io](https://crates.io/crates/totp-rs)) |
| AWS SDK | **aws-config 1.8.18 / aws-sdk-dynamodb 1.116.0 / aws-sdk-sesv2 1.123.0** | releases dated 2026-06-12 — daily release cadence, GA since Nov 2023 ([repo](https://github.com/awslabs/aws-sdk-rust)) |
| IDs | **uuid** | 1.23.3 (2026-06-09) | enable `v7` feature — time-ordered UUIDs are DynamoDB-sort-friendly |
| Time | **time** | 0.3.47 (2026-06-12) | Used by tower-sessions and most of the ecosystem. [jiff 0.2.28](https://github.com/BurntSushi/jiff) is the nicer modern API but still 0.x and less integrated; JWT claims are plain unix seconds anyway. |
| Lambda | **lambda_http / lambda_runtime 1.2.1** (2026-05-25), **cargo-lambda 1.9.1** (2026-02-26) | `cargo lambda build --release --arm64` → `provided.al2023` on Graviton |
| Secrets | aws-sdk-kms or aws-sdk-secretsmanager | — | Hold signing keys in KMS (sign via KMS API) or load PEM from Secrets Manager at cold start; never bake into the bundle |

## 8. Testing approach

1. **Handler-level integration tests** with **axum-test 20.1.0** (`TestServer` over your `Router`, mocked network, parallel-safe) ([docs.rs](https://docs.rs/axum-test)) — or zero-dep `tower::ServiceExt::oneshot`. Drive full flows: register → verify email → login → refresh → revoke.
2. **DynamoDB**: **testcontainers 0.27.3 + testcontainers-modules 0.15.0** (has a `dynamodb` module) running DynamoDB Local; point the SDK at the container with a custom `endpoint_url` ([testcontainers-rs](https://github.com/testcontainers/testcontainers-rs)). Faster trick for pure logic: the SDK's `aws-smithy-mocks` for unit-level rule-based mocking.
3. **Upstream IdPs (Google/GitHub)**: **wiremock 0.6.5** — stand up a fake OIDC discovery document + JWKS + token endpoint and point `openidconnect` at it ([wiremock-rs](https://github.com/LukeMathWalker/wiremock-rs)).
4. **Property tests**: **proptest 1.11.0** for invariants — PHC-string round-trips, JWT claim round-trips, redirect-URI validation never panics, PKCE verifier/challenge pairs.
5. **Protocol conformance**: run the OpenID Foundation conformance suite (Docker) against a deployed dev stage before claiming OIDC compliance — this is what rauthy does.
6. **Local Lambda parity**: `cargo lambda watch` + `cargo lambda invoke` to exercise the actual `lambda_http` event path (API Gateway payload quirks like multi-value headers).

---

## Recommended dependency list (Cargo.toml, versions current as of 2026-06-12)

```toml
[dependencies]
# HTTP / runtime
axum = "0.8.9"
axum-extra = { version = "0.12.6", features = ["cookie", "typed-header"] }
tokio = { version = "1.52", features = ["macros", "rt-multi-thread"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["trace", "cors", "request-id"] }
lambda_http = "1.2.1"                # tower-compatible; axum Router plugs straight in

# Crypto / credentials
argon2 = { version = "0.5.3", features = ["std"] }          # Argon2id, OWASP params
jsonwebtoken = { version = "10.4.0", features = ["aws_lc_rs"] }  # ES256 + EdDSA
webauthn-rs = { version = "0.5.5", features = ["danger-allow-state-serialisation", "conditional-ui"] }
totp-rs = { version = "5.7.1", features = ["qr", "otpauth"] }
rand = "0.9"
subtle = "2"                          # constant-time comparisons for codes/tokens

# OAuth/OIDC client (social login)
openidconnect = "4.0.1"               # Google (full OIDC)
oauth2 = "5.0.0"                      # GitHub (plain OAuth2)

# AWS
aws-config = "1.8"
aws-sdk-dynamodb = "1.116"
aws-sdk-sesv2 = "1.123"

# Domain plumbing
serde = { version = "1", features = ["derive"] }
serde_json = "1"
garde = { version = "0.23.0", features = ["derive", "email"] }
uuid = { version = "1.23", features = ["v7", "serde"] }
time = { version = "0.3.47", features = ["serde"] }
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
base64 = "0.22"                       # base64url for JWK x/y coordinates

# Only if you serve a browser login UI with cookie sessions:
# tower-sessions = "0.15.0"           # note: DynamoDB store crate still targets 0.14

[dev-dependencies]
axum-test = "20.1.0"
wiremock = "0.6.5"
testcontainers = "0.27.3"
testcontainers-modules = { version = "0.15.0", features = ["dynamodb"] }
proptest = "1.11.0"
```

Tooling: `cargo-lambda 1.9.1` for build/deploy (`provided.al2023`, arm64). Deliberately excluded: **oxide-auth** (stagnant, no OIDC — hand-roll the provider endpoints like rauthy does), **josekit** (OpenSSL dependency hurts Lambda static builds; only needed for JWE), **RustCrypto jose-\*** (stale pre-1.0), **tower_governor in production** (per-instance state is ineffective across Lambda instances — use API Gateway throttling + DynamoDB lockout counters; keep it only if you add a long-running deployment target).

### Key sources
- crates.io API (all version numbers, fetched 2026-06-12)
- [AWS: Lambda adds support for Rust (GA)](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-lambda-rust) · [InfoQ coverage](https://infoq.com/news/2025/11/aws-lambda-rust-support-ga/) · [aws-lambda-rust-runtime](https://github.com/aws/aws-lambda-rust-runtime) · [Rust on Lambda production guide](https://www.nandann.com/blog/rust-aws-lambda-production-guide) · [Kickstarting Rust on AWS Lambda](https://jun.codes/blog/kickstarting-rust-on-aws-lambda)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [jsonwebtoken CHANGELOG](https://github.com/Keats/jsonwebtoken/blob/master/CHANGELOG.md) · [jsonwebtoken jwk docs](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/jwk/index.html) · [josekit-rs](https://github.com/hidekatsu-izuno/josekit-rs)
- [webauthn-rs docs](https://docs.rs/webauthn-rs/latest/webauthn_rs/) · [1Password passkey-rs](https://github.com/1Password/passkey-rs)
- [rauthy](https://github.com/sebadob/rauthy) + its workspace Cargo.toml (actix-web 4, ring/ed25519-compact, argon2 0.5, webauthn-rs 0.5, no OIDC framework crate) · [Rauthy docs](https://sebadob.github.io/rauthy/) · [oxide-auth docs](https://docs.rs/oxide-auth/latest/oxide_auth/) · [OIDC provider discussion](https://users.rust-lang.org/t/is-there-any-openid-connect-provider/76824)
- [openidconnect docs](https://docs.rs/openidconnect/latest/openidconnect/) · [tower-sessions](https://github.com/maxcountryman/tower-sessions) · [tower-sessions-dynamodb-store Cargo.toml](https://github.com/necrobious/tower-sessions-dynamodb-store) · [tower-governor](https://github.com/benwis/tower-governor) · [testcontainers-rs](https://github.com/testcontainers/testcontainers-rs) · [axum-test](https://docs.rs/axum-test) · [wiremock-rs](https://github.com/LukeMathWalker/wiremock-rs)
- Framework landscape: [Rust Web Frameworks in 2026](https://aarambhdevhub.medium.com/rust-web-frameworks-in-2026-axum-vs-actix-web-vs-rocket-vs-warp-vs-salvo-which-one-should-you-2db3792c79a2) · [Actix vs Axum 2026](https://sharpskill.dev/en/blog/rust/rust-actix-web-vs-axum-comparison) · [axum ECOSYSTEM.md](https://github.com/tokio-rs/axum/blob/axum-v0.8.0/ECOSYSTEM.md)