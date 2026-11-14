# Auth service infrastructure (AWS CDK)

AWS CDK v2 (TypeScript) app that deploys the passkey-only, PII-free
authentication service described in [`docs/protocol.md`](../docs/protocol.md).
The service itself is a Rust binary (`bootstrap`) that runs on Lambda's
`provided.al2023` runtime.

Synthesis and tests run fully offline: no AWS credentials or context lookups.

## Architecture

```
client ──TLS 1.3 (+PQ hybrid KEX) / hardened TLS 1.2──▶ auth.example.com  (Route 53 A + AAAA alias)
                                                        │
                                   API Gateway custom domain (regional, dual-stack,
                                   enhanced TLS policy, STRICT endpoint access mode,
                                   base path mapping at "/")
                                                        │
                                   WAFv2 web ACL ── IP reputation ── per-IP rate limits
                                                 ── 64 KiB body / 1385 B path limits
                                                 ── Core + KnownBadInputs managed rules
                                                        │
                                   REST API, stage "prod" (execute-api endpoint disabled,
                                   stage throttling, PII-free access logs)
                                                        │  Lambda proxy: ANY / and ANY /{proxy+}
                                                        ▼
                                   Lambda (Rust, arm64, provided.al2023, 512 MB, 10 s)
                                      │                 │                   │
                       DynamoDB table (pk/sk,      KMS: access-token     KMS: DPoP nonce
                       on-demand, TTL, PITR,       + refresh-token       HMAC_256 key
                       deletion protection)        ECC_NIST_P256 keys
                                      │
                       KMS: table CMK (symmetric, yearly rotation)
```

| Resource | Notes |
|---|---|
| DynamoDB table | `pk`/`sk` strings, TTL attribute `ttl`, on-demand, point-in-time recovery, deletion protection, `RETAIN`, encrypted with a dedicated customer-managed key (protocol §12). |
| KMS keys | Table key (symmetric, automatic rotation), access-token signing key and a **separate** refresh-token signing key (`ECC_NIST_P256`, `SIGN_VERIFY`), DPoP nonce key (`HMAC_256`, `GENERATE_VERIFY_MAC`). All `RETAIN`, 30-day deletion window, aliases `alias/<stack>/{table,access-token,refresh-token,dpop-nonce}` (protocol §5). |
| Lambda | `PROVIDED_AL2023`, `ARM_64`, handler `bootstrap`, 512 MB, 10 s, explicit log group (30 days), optional reserved concurrency, environment exactly per protocol §13 plus `AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH=true` and `RUST_LOG=info`. |
| API Gateway | Regional REST API (WAF cannot attach to HTTP APIs), dual-stack, `disableExecuteApiEndpoint: true`, stage `prod` with throttling, custom JSON access logs, gateway responses in the OAuth error format. |
| Custom domain | Regional, dual-stack, `SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09` (configurable), endpoint access mode `STRICT`, root base path mapping so the issuer is `https://<domainName>` with no stage prefix. |
| WAFv2 | Regional web ACL on the stage (see below). No WAF logging. |
| Route 53 | Optional A and AAAA alias records (when `hostedZone` is configured). |

Outputs: `IssuerUrl`, `TableName`, `TableKeyArn`, `AccessTokenSigningKeyArn`,
`RefreshTokenSigningKeyArn`, `DpopNonceKeyArn`, `WebAclArn`, and
`DomainAliasTarget` / `DomainAliasHostedZoneId` for manual DNS.

## Security and privacy decisions

### Nothing records IP addresses or user agents

- **Access logs** use an explicit allowlist (`lib/access-log.ts`): request ID,
  times, method, route template (`resourcePath`), status, sizes, latencies,
  integration/WAF/error codes, TLS version and cipher suite. Nothing from
  `$context.identity.*` (source IP, user agent, caller, …),
  `$context.authorizer.*` or `$context.path` (which would contain credential
  IDs). A test enforces the allowlist.
- **Execution logging is off**, and so is data tracing: execution logs can
  include request headers (`X-Forwarded-For`, `User-Agent`) and their content
  cannot be filtered.
- **No X-Ray on API Gateway**: its segments record the client IP and user
  agent. Lambda tracing is also off (it would need a wildcard IAM grant for
  little value without SDK instrumentation).
- **No WAF logging and no sampled requests.** WAF log records contain the client
  IP and all headers; "sampled requests" keep the same data for three hours in
  the console. Every rule emits CloudWatch metrics instead (allowed, blocked and
  counted requests per rule).
- **The service itself** receives `requestContext.identity.sourceIp`, the
  `User-Agent` and `X-Forwarded-For` in every proxy event (API Gateway cannot
  strip them for proxy integrations). The Rust service must never log raw events
  or headers.

### WAF

Rule order: Amazon IP reputation list → stricter per-IP rate limit on
`/v1/register/*` and `/v1/recover/*` → global per-IP rate limit → body size
limit → URI path size limit → `AWSManagedRulesCommonRuleSet` →
`AWSManagedRulesKnownBadInputsRuleSet`. Rate-limited requests get
`429 {"error":"rate_limited",…}` with `Cache-Control: no-store` (protocol §10.8).
The register/recover matcher URL-decodes, normalizes and lowercases the path
first, because over-matching is the safe direction for a rate limit.

**Request body size.** The core rule set's `SizeRestrictions_BODY` blocks bodies
over 8 KB. A legitimate `RegistrationResponseJSON` can exceed that: a 1023-byte
credential ID appears base64url-encoded in `id`, `rawId`, the attestation object
and the duplicated authenticator data, and with an RSA-4096 credential key and
packed self-attestation the request is about 9–10 KB. The protocol allows
64 KiB. So:

1. `SizeRestrictions_BODY` is switched to **Count** (its metric still shows how
   often it would have fired).
2. The web ACL's body inspection limit for API Gateway is raised from the
   default 16 KB to **64 KB**, so the managed body rules (XSS, LFI, RFI, SSRF)
   see the whole request. AWS only charges for the larger inspection on requests
   whose bodies are actually over 16 KB, which legitimate traffic never is.
3. A custom `BodySizeLimit` rule blocks bodies over exactly 65,536 bytes with
   `413 {"error":"payload_too_large"}`. Its oversize handling is `MATCH`, so
   anything past the inspection limit is blocked rather than waved through.
   The service enforces the same 64 KiB limit as a second layer.

**URI path size.** `SizeRestrictions_URIPATH` blocks paths over 1024 bytes, but
`DELETE /v1/account/passkeys/{credential_id}` with a 1023-byte credential ID is
1385 bytes. That rule is switched to Count and replaced by `UriPathSizeLimit`,
which blocks paths over exactly 1385 bytes (`400 invalid_request`).

**User-Agent.** `NoUserAgent_HEADER` is switched to Count. The protocol does not
require a User-Agent, CLI and native clients may omit it, and a PII-free service
should not insist on a fingerprinting header. Abuse is handled by the rate
limits.

`AWSManagedRulesAnonymousIpList` is deliberately **not** used: it would block
VPN and Tor users, who are exactly the users an anonymous service should serve.
Bot Control, CAPTCHA and Challenge actions are not used (cost, and they break
non-browser clients).

### TLS

The custom domain (and the REST API itself, whose disabled default host still
negotiates TLS) uses `SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09` with endpoint
access mode `STRICT` (SNI must match the Host header, and requests must arrive
through the matching endpoint type). That policy offers TLS 1.3 with hybrid
post-quantum key exchange, and limits TLS 1.2 to ECDHE + AES-GCM (forward
secrecy, no CBC, no RSA key exchange). TLS 1.3's downgrade protection means
offering TLS 1.2 does not weaken TLS 1.3-capable clients.

It is preferred over the TLS 1.3-only `SecurityPolicy_TLS13_1_3_2025_09` because
AWS documents post-quantum key exchange only for the `PQ` policies. This matters
here because the service sends long-lived secrets (recovery codes) that a
"harvest now, decrypt later" adversary could otherwise record. Set
`tlsSecurityPolicy` to `SecurityPolicy_TLS13_1_3_2025_09` (or the FIPS variant)
to drop TLS 1.2 entirely.

Response compression is not enabled: compressing responses that carry tokens and
recovery codes next to attacker-influenced data invites BREACH-style attacks.

### KMS key policies

The account principal (IAM administrators, the CloudFormation execution role)
gets **administrative actions only**: no `Sign`, `GenerateMac`, `VerifyMac`,
`Encrypt`, `Decrypt` and no `CreateGrant`. The service role is named directly
in each key policy:

- active signing keys: `kms:Sign` only with `kms:SigningAlgorithm = ECDSA_SHA_256`
  and `kms:MessageType = DIGEST` (protocol §5), plus `kms:GetPublicKey`;
- previous signing keys: `kms:GetPublicKey` only;
- nonce key: `kms:GenerateMac` / `kms:VerifyMac` only with
  `kms:MacAlgorithm = HMAC_SHA_256`.

So an IAM policy elsewhere in the account that grants `kms:Sign` on `*` cannot
mint tokens. An administrator would first have to rewrite the key policy, which
is a visible, auditable change in CloudTrail. The table key additionally lets
account principals use it **through DynamoDB only** (`kms:ViaService` and
`kms:CallerAccount`), which CloudFormation, backups and point-in-time restores
need, and lets DynamoDB create grants only for AWS resources
(`kms:GrantIsForAWSResource`).

### IAM

The Lambda role has no managed policies. Its single policy grants exactly:

| Actions | Resource |
|---|---|
| `dynamodb:BatchGetItem, ConditionCheckItem, DeleteItem, GetItem, PutItem, Query, UpdateItem` | the table only (no indexes exist) |
| `kms:Decrypt, DescribeKey, Encrypt, GenerateDataKey` with `kms:ViaService = dynamodb.<region>.amazonaws.com` | table key |
| `kms:Sign` (ES256 digest conditions) | active access-token key, active refresh-token key |
| `kms:GetPublicKey` | all access-token and refresh-token key generations |
| `kms:GenerateMac, kms:VerifyMac` (HMAC-SHA-256 condition) | nonce key |
| `logs:CreateLogStream, logs:PutLogEvents` | the function's log group |

There is no `dynamodb:TransactWriteItems` IAM action: transactions are
authorized per item against PutItem, UpdateItem, DeleteItem and
ConditionCheckItem, which are granted. There is no `Scan` and no
`BatchWriteItem`. A test asserts the exact action/resource pairs and that no
IAM policy in the stack contains a wildcard action or a `*` resource.

API Gateway may invoke the function only from this API's `prod` stage, and the
console "test invoke" permission is not granted.

### cdk-nag

`AwsSolutionsChecks` runs as a CDK validation plugin on every synthesis
(`bin/app.ts`). Any finding, error or warning, that is not acknowledged fails
`cdk synth`/`cdk deploy`. Acknowledgments live in `lib/nag-suppressions.ts`,
attached to the narrowest construct, each with a written reason:

| Rule | Where | Why |
|---|---|---|
| `AwsSolutions-APIG2` (request validation) | REST API | Single Lambda proxy with no models: a validator would validate nothing. The service is the normative validator (strict parsing, canonical base64url, WebAuthn/DPoP verification, 64 KiB, also enforced by WAF). |
| `AwsSolutions-APIG4` (authorization) | both methods | The API *is* the authentication server: sign-up/sign-in/refresh/discovery are reachable without credentials by definition, and the account endpoints verify the service's own DPoP-bound tokens inside the function. |
| `AwsSolutions-COG4` (Cognito authorizer) | both methods | No Cognito: it would add a second identity store with PII-capable attributes. |
| `AwsSolutions-APIG6` (execution logging) | stage | Execution logs can include client IP and User-Agent headers and cannot be filtered (protocol §1). |
| `AwsSolutions-IAM4[…AmazonAPIGatewayPushToCloudWatchLogs]` | API Gateway account role | AWS-documented policy for the regional, account-wide role API Gateway needs to write access logs. It cannot be scoped to one stack without breaking other APIs in the account. Only present when `manageApiGatewayCloudWatchRole` is true. |

A test checks that this is the complete list and that the checks are live (a
deliberately added wildcard policy fails synthesis).

## Configuration

The app reads a JSON file passed as context: `-c config=<path>`. It is
validated before anything is created (`lib/config.ts`); synthesis fails with a
list of every problem. Unknown properties are rejected, so typos fail too.

| Property | Required | Meaning |
|---|---|---|
| `stackName` | no (`AuthServiceStack`) | CloudFormation stack name; also the KMS alias prefix and WAF metric prefix. |
| `account`, `region` | yes | The stack's environment (12-digit account ID, region name). |
| `domainName` | yes | Public host name, e.g. `auth.example.com`. The issuer is `https://<domainName>`. |
| `certificateArn` | yes | ACM certificate for `domainName` in the **same account and region** (regional endpoint). |
| `hostedZone` | no | `{ "id": "Z…", "name": "example.com" }`. Creates A and AAAA alias records. The domain must be inside the zone. |
| `rpId`, `rpName` | yes | WebAuthn RP ID (a DNS name) and display name (≤ 64 bytes, no control characters). |
| `allowedOrigins` | yes | WebAuthn origins: canonical `https://host[:port]` origins whose host is `rpId` or a subdomain, or `android:apk-key-hash:<43-char base64url SHA-256>`. |
| `corsOrigins` | yes | Canonical `https://` browser origins allowed by CORS (§11). `http:`, paths, trailing slashes, default ports and uppercase hosts are rejected. |
| `audiences` | yes | RFC 8707 resource indicators: canonical absolute `https` URIs, no query or fragment. The first is the default `aud`. The issuer is implicit and must not be listed. |
| `clientIds` | yes | Allowed `client_id`s: 1–64 of `A–Z a–z 0–9 . _ ~ -`. |
| `lambdaAssetPath` | yes | Directory containing the executable `bootstrap`. Relative paths are resolved against the config file's directory. |
| `reservedConcurrency` | no | Lambda reserved concurrency (≥ 1). Also caps worst-case cost under attack. |
| `waf.rateLimitPerIp` | no (1000) | Requests per IP per window, all paths. |
| `waf.sensitiveRateLimitPerIp` | no (60) | Requests per IP per window on `/v1/register/*` and `/v1/recover/*`. Must be lower than `rateLimitPerIp`. Minimum 10 for both. |
| `waf.evaluationWindowSeconds` | no (300) | 60, 120, 300 or 600. |
| `apiThrottle.rateLimit`, `.burstLimit` | no (100, 200) | Stage-wide API Gateway throttling (requests/s, burst). |
| `tlsSecurityPolicy` | no | `SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09` (default), `SecurityPolicy_TLS13_1_3_2025_09` or `SecurityPolicy_TLS13_1_3_FIPS_2025_09`. |
| `manageApiGatewayCloudWatchRole` | no (true) | Create the regional, account-wide API Gateway CloudWatch Logs role (`AWS::ApiGateway::Account`), which access logging requires. Set it to `true` in **exactly one** stack per account and region. Set it to `false` if the account already has the role configured. |
| `keys` | no (all generation 1) | Key generations, see the rotation runbook. |

Lists are passed to the service comma-separated, so entries may not contain
commas, and duplicates are rejected.

[`config/example.json`](config/example.json) is a complete example (with dummy
account, certificate and hosted zone values).

## Deploying

Prerequisites: Node.js ≥ 24, Rust with [cargo-lambda](https://www.cargo-lambda.info/),
AWS credentials for the target account, an issued ACM certificate for the
domain in the target region.

```sh
# 1. Build the service (repository root). Produces target/lambda/auth-service/bootstrap.
cargo lambda build --release --arm64

# 2. Install the infra toolchain (exact versions from package-lock.json).
cd infra
npm ci

# 3. Write the config. "lambdaAssetPath" is relative to the config file:
#    from infra/config/prod.json use "../../target/lambda/auth-service".
cp config/example.json config/prod.json   # then edit

# 4. One-time per account/region: bootstrap CDK.
#    Consider --cloudformation-execution-policies with a scoped policy instead of
#    the default AdministratorAccess for the CloudFormation execution role.
npx cdk bootstrap aws://<account>/<region> -c config=config/prod.json

# 5. Review and deploy.
npx cdk diff   -c config=config/prod.json
npx cdk deploy -c config=config/prod.json
```

Without `hostedZone`, create the DNS records yourself: A and AAAA aliases (or a
CNAME) for `domainName` pointing at the `DomainAliasTarget` output (zone
`DomainAliasHostedZoneId`).

Notes:

- The stack has **termination protection**, and the table, keys and log groups
  are `RETAIN`. Deleting the stack leaves them in place on purpose. KMS aliases
  are deleted with the stack so that it can be re-created.
- `cdk.json` disables CDK version reporting, CDK CLI telemetry, notices and the
  extra metadata collection. Nothing about the deployment is sent to AWS beyond
  what CloudFormation needs.
- After the first deploy the custom domain's `STRICT` mode can take up to
  15 minutes to be enforced.

## Key rotation runbook

KMS rotates the **table key** automatically every 365 days. Old key material is
kept, so nothing needs to happen.

Asymmetric (ECC) and HMAC KMS keys **cannot be rotated automatically or on
demand**. Rotation means creating a new key and switching to it. The stack models
each signing key as numbered **generations** in the config:

```json
"keys": {
  "accessToken":  { "active": 1, "previous": [] },
  "refreshToken": { "active": 1, "previous": [] },
  "dpopNonce":    { "active": 1 }
}
```

Each generation is its own KMS key with a stable construct ID
(`Keys/AccessTokenSigningKeyG<n>`, …), so adding a generation never replaces an
existing key. The `active` generation signs and is
`AUTH_*_TOKEN_KEY_ID`. `previous` generations are listed in
`AUTH_*_TOKEN_PREVIOUS_KEY_IDS`: the service may only call `GetPublicKey` on them
(their key policy no longer allows `Sign`), to publish them in the JWKS (access
tokens) or keep accepting them (refresh tokens). Deploy with
`cdk deploy -c config=…` after every step and check the `cdk diff` first.

### Access-token signing key (published in JWKS)

1. **Pre-publish.** `"accessToken": { "active": 1, "previous": [2] }`. This
   creates generation 2, which is published in the JWKS but not yet signing.
2. **Wait** for every resource server's JWKS cache to refresh: at least the
   JWKS `max-age` (300 s), more if a verifier caches longer.
3. **Switch.** `"accessToken": { "active": 2, "previous": [1] }`. New access
   tokens are signed with generation 2. Generation 1 stays in the JWKS for tokens
   already issued.
4. **Wait** for every generation-1 access token to expire: `ACCESS_TOKEN_TTL`
   (300 s) + allowed clock skew + JWKS cache time. 15 minutes is ample.
5. **Retire.** `"accessToken": { "active": 2, "previous": [] }`. Generation 1
   leaves the stack, and since keys are `RETAIN` it still exists in KMS.
6. **Destroy.** Disable it, then schedule deletion. Note its ARN before step 5
   (it is the function's `AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS`), or find it by its
   description, `<stack>: access-token signing key, generation 1 …`:

   ```sh
   aws kms disable-key --key-id <generation-1 key ARN>
   aws kms schedule-key-deletion --key-id <generation-1 key ARN> --pending-window-in-days 30
   ```

### Refresh-token signing key (never published)

1. **Switch.** `"refreshToken": { "active": 2, "previous": [1] }`. New refresh
   tokens (including every token rotated on refresh) are signed with
   generation 2, and generation-1 tokens are still accepted.
2. **Wait** `REFRESH_IDLE_TTL` (30 days) plus clock skew. A refresh token's
   `exp` is at most 30 days after it was issued, so every generation-1 token has
   then expired. Active sessions have been re-signed with generation 2 in the
   meantime.
3. **Retire.** `"refreshToken": { "active": 2, "previous": [] }`.
4. **Destroy** generation 1 as above.

### DPoP nonce key (HMAC)

There is no previous-key variable for nonces (protocol §13). Nonces live for at
most two 300 s windows, and a client holding a stale nonce gets
`use_dpop_nonce` with a fresh `DPoP-Nonce` and retries once (§7.2). Rotation is
therefore a single step with at most one extra round trip per client:

1. `"dpopNonce": { "active": 2 }`. Deploy, ideally at low traffic.
2. **Destroy** generation 1 (disable, schedule deletion).

### Suspected misuse of a signing key

KMS private keys cannot be exported, so "compromise" means unauthorized use of
`kms:Sign` (investigate in CloudTrail). Rotate immediately, skipping the waits:

- access-token key: `{ "active": 2, "previous": [] }`. Outstanding access tokens
  stop verifying once resource servers refetch the JWKS.
- refresh-token key: `{ "active": 2, "previous": [] }`. Every session must sign
  in with a passkey again (a global sign-out).

Then disable the old key at once (`aws kms disable-key`) and schedule deletion.

Keep at most three previous generations per key (enforced by config
validation). Generation numbers are labels: they only need to be unique among
the generations in the config.

## Costs

Rough, us-east-1 list prices; check current AWS pricing.

- **Fixed:** 4 KMS keys at about $1/month each (the table key's first two
  automatic rotations add a little); WAF web ACL $5/month + $1/month per rule
  (7 rules; the AWS managed rule groups used here carry no extra subscription).
  About $12–15/month before traffic.
- **Per request:** WAF ~$0.60/million; API Gateway REST ~$3.50/million;
  Lambda arm64 at 512 MB per millisecond of run time; DynamoDB on-demand
  reads/writes; CloudWatch Logs ingestion (access logs are about 0.5 KB per
  request); KMS requests. Asymmetric `Sign` requests cost more than symmetric
  ones (about 5×). Each token issuance is two `Sign` calls (access + refresh),
  and ECC operations have a much lower default per-account request quota than
  symmetric ones (check Service Quotas before launch). The service should cache
  `GetPublicKey` results and the per-window nonce MAC (the nonce is deterministic
  per 300 s window), so `GenerateMac`/`VerifyMac` are not per-request calls.
- **Storage:** DynamoDB storage + point-in-time recovery (per GB-month); items
  are small and challenges/JTIs expire via TTL.
- **Body inspection** beyond 16 KB is billed per request, but only for requests
  whose bodies exceed 16 KB, which legitimate traffic never does.
- **Bounding abuse:** WAF rate limits, stage throttling (`apiThrottle`) and
  `reservedConcurrency` cap the worst-case Lambda/DynamoDB/KMS spend. IPv6
  clients are rate-limited per /128 address (a WAF limitation), so the stage
  throttle is the backstop against address rotation.

## Local development

Local development does not use CDK. The service runs as a plain HTTP server when
`AWS_LAMBDA_RUNTIME_API` is unset (protocol §13, `AUTH_LISTEN_ADDR`), and talks
to [aws-emulator](https://github.com/aws/aws-emulator) for DynamoDB and KMS. The
emulator cannot run Rust (custom-runtime) Lambda functions, so deploying this
CDK app into it is not useful. Create the table and keys in the emulator with
the AWS CLI, mirroring what the stack creates:

```sh
export AWS_ENDPOINT_URL=<aws-emulator endpoint, see its README>
aws dynamodb create-table --table-name auth \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST
aws dynamodb update-time-to-live --table-name auth \
  --time-to-live-specification Enabled=true,AttributeName=ttl
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY   # access token
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY   # refresh token
aws kms create-key --key-spec HMAC_256 --key-usage GENERATE_VERIFY_MAC # DPoP nonce
```

Then run the service with the `AUTH_*` variables pointing at those resources and
`AWS_ENDPOINT_URL` set.

## Working on this package

```sh
npm ci
npm run typecheck   # tsc, strict
npm run lint        # eslint + typescript-eslint (strict, type-checked)
npm test            # vitest + aws-cdk-lib/assertions + cdk-nag
npm run synth       # offline synth of config/example.json with a placeholder asset
```

`npm run synth` writes a placeholder `bootstrap` (which refuses to run) to
`.example-asset/` (git-ignored), so it works without building the Rust service.

Layout:

| Path | Contents |
|---|---|
| `bin/app.ts` | App entry: loads `-c config=…`, creates the stack, registers cdk-nag. |
| `lib/config.ts` | Config types, defaults and validation. |
| `lib/auth-service-stack.ts` | The stack. |
| `lib/keys.ts` | KMS keys, generations, key policies, aliases. |
| `lib/waf.ts` | Web ACL and the protocol-derived size limits. |
| `lib/access-log.ts` | PII-free access-log field allowlist. |
| `lib/permissions.ts` | Every granted IAM/KMS action, shared with the tests. |
| `lib/nag-suppressions.ts` | cdk-nag acknowledgments and reasons. |
| `test/` | Config validation, resource, IAM, WAF and cdk-nag tests. |

Dependencies are pinned to exact versions. TypeScript is pinned to 6.0.x, the
newest release `typescript-eslint` supports (it does not support TypeScript 7
yet). `npm audit` reports a moderate ReDoS advisory in `minimatch` 10.x
(GHSA-g3hv-75wg-m249), pulled in by `aws-cdk-lib` (bundled) and
`typescript-eslint`. It affects build-time tooling that only receives the
project's own glob patterns. The fix is a semver-major `minimatch` that neither
dependency accepts yet, so revisit it when they update.

## Known limitations and follow-ups

- **Edge-generated responses** (WAF blocks, API Gateway throttling, integration
  failures) use the OAuth error format and `Cache-Control: no-store`, but carry
  no CORS headers and no `DPoP-Nonce` (neither layer can add allowlisted CORS
  headers or a per-window nonce). Browsers will surface them as network errors,
  so the SDK should treat an opaque failure as retryable with backoff.
- **WAF/managed-rule blocks** return `403 {"error":"access_denied"}`. The
  protocol's error table (§10.8) has no code for this case.
- **Lambda code signing** (AWS Signer) is not configured. It needs a signing
  step between `cargo lambda build` and deployment.
- **Alarms** (5xx rate, Lambda errors/throttles, WAF block spikes, KMS
  throttling) are not defined because there is no notification target yet.
- The managed rule groups use their default (AWS-updated) versions.
