# Deploying a Low-Traffic Personal Rust Auth Service to AWS (June 2026)

## Recommended architecture (TL;DR)

One CloudFront distribution on `auth.example.com` serving everything; Rust axum "Lambdalith"; DynamoDB single table; all defined in CDK TypeScript.

```
Route 53 (auth.example.com)
  └─ CloudFront distribution (ACM cert in us-east-1)
       ├─ default behavior  → private S3 bucket (OAC) — React SPA
       └─ /api/*  behavior  → API Gateway HTTP API (regional, default
                              execute-api endpoint, CachingDisabled)
                                └─ ONE Rust Lambda (axum via lambda_http,
                                   ARM64/Graviton, provided.al2023,
                                   built with cargo-lambda-cdk RustFunction)
                                     ├─ DynamoDB single table (on-demand, TTL
                                     │  on sessions/tokens/magic links)
                                     ├─ SES (verification + magic-link email)
                                     └─ KMS asymmetric ECC_NIST_P256 (ES256)
                                        for JWT signing — or skip JWTs and use
                                        opaque session cookies in DynamoDB
```

Estimated steady-state cost: **~$1.50–$4/month**, dominated by the Route 53 hosted zone ($0.50) and the KMS key ($1.00). Everything else rounds to pennies at <100 users.

---

## 1. Rust on Lambda in 2026

**Status: officially GA.** On November 14, 2025, AWS graduated Rust on Lambda from "experimental" to Generally Available, backed by AWS Support and the Lambda SLA, in all regions including GovCloud/China; the runtime client was promoted to v1.0.0 ([AWS What's New](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-lambda-rust), [InfoQ](https://infoq.com/news/2025/11/aws-lambda-rust-support-ga/)). The runtime repo ([aws/aws-lambda-rust-runtime](https://github.com/awslabs/aws-lambda-rust-runtime)) is actively maintained — latest release v1.2.1 (May 2026), MSRV 1.84 — and ships four crates: `lambda-runtime`, `lambda-http`, `lambda-extension`, `lambda-events`. Rust runs on the OS-only `provided.al2023` runtime (you ship a static binary named `bootstrap`). In March 2026, Lambda Managed Instances also added Rust support ([Nandann production guide](https://www.nandann.com/blog/rust-aws-lambda-production-guide)) — irrelevant at personal scale, but a sign of continued investment.

**Tooling: cargo-lambda is the standard.** `cargo lambda build/watch/deploy` cross-compiles via Zig (no Docker needed, trivially targets `aarch64`), and is the officially recommended workflow ([cargo-lambda](https://github.com/cargo-lambda/cargo-lambda), latest v1.9.1, Feb 2026; [scanner.dev guide](https://scanner.dev/blog/getting-started-with-serverless-rust-in-aws-lambda)).

**axum integration is first-class.** `lambda_http` adapts API Gateway (REST + HTTP API), ALB, Lambda Function URLs, and VPC Lattice events into standard `http` types, and because axum's `Router` implements `tower::Service`, you pass it straight to the runtime ([official http-axum example](https://github.com/aws/aws-lambda-rust-runtime/tree/main/examples/http-axum), [docs.rs/lambda_http](https://docs.rs/lambda_http/latest/lambda_http/)):

```rust
#[tokio::main]
async fn main() -> Result<(), Error> {
    let app = Router::new().route("/", get(root));
    lambda_http::run(app).await   // works because axum Router is a tower::Service
}
```

This gives you the "Lambdalith" pattern: one function, full axum routing/middleware/extractors, and the same code runs locally with `cargo lambda watch` or behind any HTTP trigger. Cookies and redirects are just normal `Set-Cookie`/`Location` response headers in axum — `lambda_http` maps them correctly to the API Gateway v2 payload (which has a dedicated `cookies` field, so multiple `Set-Cookie` headers work).

**Cold starts: a non-issue in Rust.** Benchmarks consistently put minimal Rust functions on `provided.al2023`/ARM64 in the **~12–30 ms cold-init range** (one widely cited benchmark: 16 ms on arm64; P50/P99 of 12–22 ms at 512 MB), versus hundreds of ms to seconds for Node/Python/JVM ([cebert/aws-lambda-performance-benchmarks](https://github.com/cebert/aws-lambda-performance-benchmarks), [Nandann guide](https://www.nandann.com/blog/rust-aws-lambda-production-guide), [viprasol 2026 cold-start guide](https://viprasol.com/blog/aws-lambda-cold-start-optimization/)). Real-world cold starts for an auth app (TLS init for AWS SDK clients, config load) will be ~100–300 ms total — fine for login flows. You don't need SnapStart or provisioned concurrency.

**ARM64/Graviton: use it.** ~20% cheaper per GB-second than x86 ("up to 34% better price performance" per [AWS Lambda pricing](https://aws.amazon.com/lambda/pricing/)) and benchmarks show equal-or-faster cold starts on arm64 (19–23 ms vs 26–29 ms x86) ([benchmarks](https://github.com/cebert/aws-lambda-performance-benchmarks), [Kelsey Merten on ARM64 Lambda costs](https://kelseymerten.medium.com/why-serverless-isnt-always-cheap-and-how-to-fix-it-c44f528172a6)). cargo-lambda makes `--arm64` a flag.

## 2. Fronting the API: Function URL vs HTTP API vs CloudFront

| | Lambda Function URL | API Gateway HTTP API | CloudFront in front |
|---|---|---|---|
| Cost | Free (standard Lambda charges only) | $1.00/M requests (first 300M) | 1 TB + 10M req/month always free |
| Custom domain | **Not supported natively** — needs CloudFront | Yes (regional domain + ACM cert in same region) | Yes (ACM cert must be in us-east-1) |
| Cookies/redirects | Fine (payload v2.0, `cookies` field) | Fine (same payload v2.0) | Pass-through with right policies |
| Throttling/WAF | None natively | Built-in throttling | WAF attachable, OAC to origin |

Sources: [API Gateway pricing](https://aws.amazon.com/api-gateway/pricing/), [CloudFront pay-as-you-go pricing](https://aws.amazon.com/cloudfront/pricing/pay-as-you-go/), [theburningmonk: when to use API Gateway vs Function URLs](https://theburningmonk.com/2024/03/when-to-use-api-gateway-vs-lambda-function-urls/), [Code Genie: So long API Gateway](https://codegenie.codes/blog/so-long-api-gateway-and-thanks-for-all-the-routes/), [ACM region requirements](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-specify-certificate-for-custom-domain-name.html), [CloudFront cert requirements](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html).

**Key decision — and a trap to avoid.** Since you need CloudFront anyway for the SPA + same-domain cookies (section 5), the question is only what the `/api/*` origin is. The trendy answer is "Function URL + CloudFront Origin Access Control" (free, no API Gateway). But there is a documented sharp edge: **with OAC on a Function URL origin, CloudFront cannot sign POST/PUT bodies — every client must compute SHA-256 of the request body and send it in `x-amz-content-sha256`, or the request is rejected** ([AWS docs: restricting access to Lambda Function URL origins](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html), [re:Post thread](https://repost.aws/questions/QUbHCI9AfyRdaUPCCo_3XKMQ/lambda-function-url-behind-cloudfront-invalidsignatureexception-only-on-post), [arpadt.com analysis](https://arpadt.com/articles/function-url-oac)). An auth API is mostly POSTs. You can hide this in a fetch wrapper in your own SPA (`crypto.subtle.digest`), but it silently breaks any POST you don't control — OIDC `form_post` responses, SAML bindings, webhooks, curl testing. As of June 2026, Function URLs still have no native custom domain support (nothing announced at re:Invent 2025, which focused on Managed Instances and Durable Functions — [theburningmonk re:Invent 2025 roundup](https://theburningmonk.com/2025/12/the-biggest-reinvent-2025-serverless-announcements/)).

**Recommendation: CloudFront → API Gateway HTTP API (regional, default `execute-api` endpoint — no API Gateway custom domain needed) → Lambda.** At personal volume the $1.00/M request fee is fractions of a cent, and you get unrestricted POSTs, built-in throttling, and a payload format `lambda_http` handles natively. Use the managed `CachingDisabled` cache policy and `AllViewerExceptHostHeader` origin request policy on the `/api/*` behavior (forwards cookies, query strings, all headers; strips `Host`, which `execute-api` endpoints require). One ACM cert in us-east-1 for `auth.example.com`, DNS-validated, attached to CloudFront; Route 53 alias record. ACM certs are free.

*Alternative worth knowing:* CloudFront's new **flat-rate pricing plans** (launched Nov 18, 2025) include a Free tier: $0/month for 1M requests + 100 GB, bundling WAF, Route 53 DNS, TLS cert, and S3 credits, with no overage charges ([AWS What's New](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-flat-rate-pricing-plans), [docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/flat-rate-pricing-plan.html)). Caveats: max 5 cache behaviors, mandatory WAF web ACL, custom cache policies only on Business+ tier (managed policies are fine), accounts on the AWS Free Tier plan are ineligible, and CDK support is still pending ([aws-cdk#37857](https://github.com/aws/aws-cdk/issues/37857)). Classic pay-as-you-go CloudFront is already effectively $0 at your scale (always-free 1 TB + 10M requests/month), so use pay-as-you-go now and revisit the flat-rate Free plan if you want bundled WAF/DNS.

## 3. CDK support

**cargo-lambda-cdk is the way.** The official construct library from the cargo-lambda org provides `RustFunction` (point it at a `Cargo.toml`, it builds with locally-installed cargo-lambda or via Docker, defaults to `provided.al2023`). Latest release v0.0.36 (Dec 8, 2025), tracking CDK 2.215+, with recent additions like log-group support ([cargo-lambda-cdk](https://github.com/cargo-lambda/cargo-lambda-cdk), [releases](https://github.com/cargo-lambda/cargo-lambda-cdk/releases)). It's still 0.x-versioned but actively maintained and the de facto standard; pin the version.

```ts
const apiFn = new RustFunction(this, 'AuthFn', {
  manifestPath: 'lambda/Cargo.toml',
  architecture: lambda.Architecture.ARM_64,
  environment: { TABLE_NAME: table.tableName },
});
```

The rest of the stack is vanilla, well-trodden CDK: `dynamodb.TableV2` (on-demand by default, `timeToLiveAttribute`), `HttpApi` + `HttpLambdaIntegration` (aws-apigatewayv2 L2s, stable in aws-cdk-lib for years), `cloudfront.Distribution` with an S3 origin via `S3BucketOrigin.withOriginAccessControl` plus an additional `/api/*` behavior with an `HttpOrigin`, `BucketDeployment` for the SPA assets, `acm.Certificate` (in us-east-1 — either a us-east-1 stack with cross-region reference or `certificates` cross-region support), and `route53.ARecord` alias. The multi-origin CloudFront + S3 + API pattern is extensively documented ([AWS blog: CloudFront with Lambda as origin](https://aws.amazon.com/blogs/networking-and-content-delivery/using-amazon-cloudfront-with-aws-lambda-as-origin-to-accelerate-your-web-applications/), [CloudFront 101: API Gateway and S3 SPA origins](https://dev.to/aws-builders/cloudfront-101-api-gateway-and-s3-spa-origins-5a2h)).

## 4. Database: DynamoDB, decisively

For <100 users and low request volume:

| | DynamoDB on-demand | Aurora Serverless v2 (Postgres) | RDS t4g.micro |
|---|---|---|---|
| Monthly cost at your scale | **~$0** (free tier: 25 GB storage; $0.625/M writes, $0.125/M reads after) | **~$44/month floor** at 0.5 ACU minimum, or ~$0 compute with 0-ACU auto-pause but **~15 s resume** | ~$12–25/month + storage, always-on |
| VPC required | No | Yes (+ Lambda in VPC) | Yes |
| Ops | Zero (no patching, no connections) | Minor (engine upgrades, VPC) | Most |
| Session/token expiry | **Native TTL, free** | cron/pg_cron cleanup | cron cleanup |

DynamoDB on-demand prices were halved in late 2024 and now sit at $0.625/M writes, $0.125/M reads, $0.25/GB-month with a 25 GB always-free storage tier ([DynamoDB on-demand pricing](https://aws.amazon.com/dynamodb/pricing/on-demand/)). Aurora Serverless v2 costs $0.12/ACU-hour with a 0.5 ACU minimum (≈$44/month always-on); scaling to 0 ACU with auto-pause exists since late 2024, but resume takes "typically ~15 seconds" — terrible UX when the first login of the day hits a paused database ([Aurora auto-pause docs](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2-auto-pause.html), [usage.ai Aurora Serverless v2 guide](https://www.usage.ai/blogs/aws/rds/aurora-serverless-v2/), [usage.ai DynamoDB vs Aurora](https://www.usage.ai/blogs/aws/reserved-instances/dynamodb/vs-aurora/), [CloudZero Aurora pricing](https://www.cloudzero.com/blog/aws-aurora-pricing/)).

An auth service's access patterns are pure key-value: user by id, user by email (GSI), session by id, token by hash. A simple single-table design (`PK = USER#<id>` / `SESSION#<id>` / `TOKEN#<hash>`, one GSI for email lookup) covers all of it. **DynamoDB TTL** expires sessions, magic-link tokens, and verification codes for free, without consuming write capacity — with one caveat: deletion happens "within a few days" of expiry, so you must still check the expiry timestamp at read time (filter expression or app-level check); TTL is garbage collection, not enforcement ([DynamoDB TTL docs](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html)).

Choose relational only if you genuinely want SQL for future products; at this scale it costs 50x more and drags your Lambda into a VPC.

## 5. SPA hosting: same domain, one distribution

**Serve the SPA and API from the same origin (`auth.example.com`), via CloudFront behaviors.** This is the single most consequential decision for an auth service that sets cookies:

- **Same-domain pros:** session cookies are first-party — `Secure; HttpOnly; SameSite=Lax` (or `Strict`) just works, no `Domain` attribute gymnastics, immune to the ongoing browser crackdown on third-party cookies. No CORS at all — no preflights, no `Access-Control-Allow-Credentials`, no maintaining origin allowlists; this also measurably improves SPA latency ([CloudFront multi-origin SPA pattern](https://dev.to/aws-builders/cloudfront-101-api-gateway-and-s3-spa-origins-5a2h), [Serverless forum: multi-origin cookies/headers](https://forum.serverless.com/t/passing-headers-cookies-between-a-multiorigin-cloudfront-dist-s3-api-gateway-origins/11525)). `SameSite=Lax` also gives you meaningful CSRF protection by default; pair with Origin-header checks for state-changing requests.
- **Separate-domain cons (e.g., SPA on `app.example.com`, API on `auth-api.example.com`):** you need CORS with credentials, `SameSite=None` cookies (or a shared parent `Domain=` cookie, widening scope), and you re-enter the world of cookie-blocking heuristics and preflight latency. Only worth it if multiple frontends will consume the API — and even then a shared parent domain usually suffices.

Mechanics: private S3 bucket behind OAC as default behavior (CachingOptimized policy); SPA routing handled by mapping 403/404 to `/index.html` with 200 (or a CloudFront Function rewrite); `/api/*` behavior with `CachingDisabled` + cookie/header forwarding to the HTTP API origin. Redirects (magic-link `Location:` hops) and `Set-Cookie` pass straight through a non-caching behavior.

## 6. SES for transactional email

- **Pricing:** $0.10 per 1,000 outbound emails + $0.12/GB attachment data; new free tier gives 3,000 message charges/month for the first 12 months ([SES pricing](https://aws.amazon.com/ses/pricing/)). At a few hundred verification/magic-link emails a month: effectively $0.00–$0.10.
- **Setup:** verify your domain identity (DKIM via three CNAME records — CDK `ses.EmailIdentity` + Route 53 automates this), set a custom MAIL FROM, add DMARC. Send from Rust with `aws-sdk-sesv2` (`SendEmail`).
- **Sandbox:** new accounts start sandboxed — max 200 emails/day and only to verified recipient addresses, which blocks real signups. Request production access via the SES console (Service Quotas/support request): describe your use case (transactional auth email, low volume, bounce/complaint handling via SNS). Approval typically takes 1–3 business days, often one ([emailplatformreview SES 2026 breakdown](https://www.emailplatformreview.com/blog/amazon-ses-pricing-official-2026/), [saaspricepulse SES free-tier guide](https://www.saaspricepulse.com/tools/amazon-ses)). Do this early — it's the only human-gated step in the whole stack. Tip: for a personal service where you verify your own recipients, you can even start building in the sandbox.
- Wire SES bounce/complaint notifications to an SNS topic from day one; it's expected in the production-access review and protects your sender reputation.

## 7. JWT signing keys

| Option | Cost | Properties |
|---|---|---|
| **KMS asymmetric (ECC_NIST_P256, ES256)** | $1/month per key + $0.15/10k Sign/GetPublicKey calls (asymmetric ops excluded from the 20k free tier) | Private key **never leaves the HSM**, non-extractable, IAM-audited; public key exposed via `GetPublicKey` for a JWKS endpoint; ~10–50 ms added latency per token issuance |
| Secrets Manager | $0.40/month per secret + $0.05/10k API calls | Key bytes loaded into Lambda memory; rotation machinery you won't use |
| SSM Parameter Store (Standard, SecureString) | **Free** storage, free standard throughput | Same security model as Secrets Manager minus rotation; cheapest |

Sources: [KMS pricing](https://aws.amazon.com/kms/pricing/), [Cloud Burn KMS pricing breakdown](https://cloudburn.io/blog/aws-kms-pricing), [TechPlained Parameter Store vs Secrets Manager cost math](https://www.techplained.com/aws-parameter-store-vs-secrets-manager), [AWS blog: verifying KMS signatures at scale](https://aws.amazon.com/blogs/security/how-to-verify-aws-kms-signatures-in-decoupled-architectures-at-scale/).

**Can KMS sign JWTs directly (ES256)? Yes, and it's practical from Rust.** Create an `ECC_NIST_P256` key with usage `SIGN_VERIFY`, call `aws-sdk-kms` `Sign` with `ECDSA_SHA_256` (hash the signing input yourself and pass `MessageType::Digest`). One real gotcha: KMS returns the signature **DER-encoded**, while JWS ES256 requires the raw 64-byte `r||s` concatenation — a ~15-line conversion (parse DER with e.g. the `ecdsa`/`p256` crates, also normalize `s` to low-S form). Production projects do exactly this ([hotsock/jwt-issuer](https://github.com/hotsock/jwt-issuer), [AWS re:Post on verifying KMS signatures](https://repost.aws/knowledge-center/kms-asymmetric-key-signature)). Verification inside your own service should use the cached public key locally (free, fast) rather than calling `kms:Verify`.

**Recommendation:** Since this is an auth service and the marginal cost is ~$1/month, use **KMS ES256** — a non-exfiltratable signing key is the "right way" for the one secret that matters most, and it gives you a clean JWKS story if other services ever verify your tokens. Two pragmatic alternatives: (a) generate a P-256 key, store the PEM in a free SSM SecureString, load once at cold start, sign with the `p256`/`jsonwebtoken` crates — $0 and zero per-request latency; (b) **question whether you need JWTs at all**: for a first-party-only service, opaque random session IDs in an `HttpOnly` cookie backed by the DynamoDB sessions table (with TTL) are simpler, instantly revocable, and need no signing keys. Use KMS-signed JWTs only where stateless verification by other parties is the point.

## 8. Total monthly cost estimate (us-east-1, personal scale: <100 users, ~50k requests/month, ~500 emails/month)

| Component | Monthly cost |
|---|---|
| Route 53 hosted zone | $0.50 (+~$1/month amortized domain registration) |
| KMS ECC key + ~10k Sign calls | $1.00 + $0.15 |
| CloudFront | $0.00 (always-free: 1 TB transfer + 10M requests) |
| ACM certificate | $0.00 |
| Lambda (ARM64, 256 MB, ~50k invocations) | ~$0.00 (within 1M req + 400k GB-s free tier) |
| API Gateway HTTP API (~50k requests) | ~$0.05 |
| DynamoDB (on-demand, <1 GB, ~100k RRU/WRU) | ~$0.05 (storage within 25 GB free tier) |
| S3 (SPA assets, a few MB) | ~$0.01 |
| SES (~500 emails) | $0.00–$0.05 (free first 12 months) |
| CloudWatch Logs (with short retention set) | ~$0.10–$0.50 |
| **Total** | **~$1.90–$3.50/month** |

(If you skip KMS in favor of SSM + sessions-only, it drops to ~$1/month. Note AWS Free Tier changed for accounts created after July 15, 2025 — new accounts get a credits-based plan, but Lambda's 1M requests, DynamoDB's 25 GB, and CloudFront's 1 TB remain always-free offers; an account on the new "free plan" is ineligible for CloudFront flat-rate plans.)

## Build order

1. ACM cert (us-east-1) + Route 53 zone; submit SES production-access request immediately (slowest step).
2. Rust workspace: axum app behind `lambda_http::run`, `cargo lambda watch` for local dev.
3. CDK stack: `RustFunction` (ARM64) + `HttpApi` + `TableV2` (TTL attribute) + CloudFront (S3 OAC default behavior, `/api/*` → HTTP API with CachingDisabled/AllViewerExceptHostHeader) + `BucketDeployment` + Route 53 alias.
4. KMS key + JWKS endpoint (or DynamoDB sessions only).
5. SES DKIM identity + send path + bounce SNS topic.

## Sources

- [AWS What's New: Lambda adds support for Rust (GA, Nov 2025)](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-lambda-rust) / [InfoQ coverage](https://infoq.com/news/2025/11/aws-lambda-rust-support-ga/)
- [aws/aws-lambda-rust-runtime](https://github.com/awslabs/aws-lambda-rust-runtime) and [http-axum example](https://github.com/aws/aws-lambda-rust-runtime/tree/main/examples/http-axum); [docs.rs/lambda_http](https://docs.rs/lambda_http/latest/lambda_http/)
- [cargo-lambda](https://github.com/cargo-lambda/cargo-lambda) / [cargo-lambda-cdk + releases](https://github.com/cargo-lambda/cargo-lambda-cdk/releases)
- Cold starts/ARM64: [cebert/aws-lambda-performance-benchmarks](https://github.com/cebert/aws-lambda-performance-benchmarks), [Nandann Rust-on-Lambda production guide](https://www.nandann.com/blog/rust-aws-lambda-production-guide), [viprasol cold-start 2026](https://viprasol.com/blog/aws-lambda-cold-start-optimization/), [Merten on ARM64 costs](https://kelseymerten.medium.com/why-serverless-isnt-always-cheap-and-how-to-fix-it-c44f528172a6), [scanner.dev serverless Rust](https://scanner.dev/blog/getting-started-with-serverless-rust-in-aws-lambda)
- Fronting: [theburningmonk: API Gateway vs Function URLs](https://theburningmonk.com/2024/03/when-to-use-api-gateway-vs-lambda-function-urls/), [Code Genie](https://codegenie.codes/blog/so-long-api-gateway-and-thanks-for-all-the-routes/), [AWS: CloudFront with Lambda origin](https://aws.amazon.com/blogs/networking-and-content-delivery/using-amazon-cloudfront-with-aws-lambda-as-origin-to-accelerate-your-web-applications/), [OAC for Function URLs docs (x-amz-content-sha256 caveat)](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html), [re:Post InvalidSignatureException on POST](https://repost.aws/questions/QUbHCI9AfyRdaUPCCo_3XKMQ/lambda-function-url-behind-cloudfront-invalidsignatureexception-only-on-post), [arpadt on Function URL OAC](https://arpadt.com/articles/function-url-oac), [theburningmonk re:Invent 2025 roundup](https://theburningmonk.com/2025/12/the-biggest-reinvent-2025-serverless-announcements/)
- Certs/domains: [API Gateway ACM cert requirements](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-specify-certificate-for-custom-domain-name.html), [CloudFront TLS requirements](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html)
- Pricing: [Lambda](https://aws.amazon.com/lambda/pricing/), [API Gateway](https://aws.amazon.com/api-gateway/pricing/), [CloudFront pay-as-you-go](https://aws.amazon.com/cloudfront/pricing/pay-as-you-go/), [CloudFront flat-rate plans (What's New)](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-flat-rate-pricing-plans) + [docs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/flat-rate-pricing-plan.html) + [CDK gap #37857](https://github.com/aws/aws-cdk/issues/37857), [DynamoDB on-demand](https://aws.amazon.com/dynamodb/pricing/on-demand/), [SES](https://aws.amazon.com/ses/pricing/), [KMS](https://aws.amazon.com/kms/pricing/)
- Database: [DynamoDB TTL docs](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html), [Aurora Serverless v2 auto-pause docs](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2-auto-pause.html), [usage.ai Aurora Serverless v2](https://www.usage.ai/blogs/aws/rds/aurora-serverless-v2/), [usage.ai DynamoDB vs Aurora](https://www.usage.ai/blogs/aws/reserved-instances/dynamodb/vs-aurora/), [CloudZero Aurora pricing](https://www.cloudzero.com/blog/aws-aurora-pricing/)
- SPA/cookies: [CloudFront 101: API Gateway + S3 SPA origins](https://dev.to/aws-builders/cloudfront-101-api-gateway-and-s3-spa-origins-5a2h), [Serverless forum multi-origin cookies](https://forum.serverless.com/t/passing-headers-cookies-between-a-multiorigin-cloudfront-dist-s3-api-gateway-origins/11525)
- SES ops: [emailplatformreview SES 2026](https://www.emailplatformreview.com/blog/amazon-ses-pricing-official-2026/), [saaspricepulse SES](https://www.saaspricepulse.com/tools/amazon-ses)
- JWT/KMS: [hotsock/jwt-issuer](https://github.com/hotsock/jwt-issuer), [AWS blog: verify KMS signatures at scale](https://aws.amazon.com/blogs/security/how-to-verify-aws-kms-signatures-in-decoupled-architectures-at-scale/), [re:Post KMS asymmetric signatures](https://repost.aws/knowledge-center/kms-asymmetric-key-signature), [Cloud Burn KMS pricing](https://cloudburn.io/blog/aws-kms-pricing), [TechPlained Parameter Store vs Secrets Manager](https://www.techplained.com/aws-parameter-store-vs-secrets-manager)