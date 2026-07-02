# Deployment

The auth service runs in **two environments, each its own AWS account**, selected
at synth/deploy time with `cdk --context env=<name>` (`infra/config/environments.ts`).
Stack construct IDs (`AuthStateful`, `AuthApp`, `AuthCiRole`) and physical stack
names (`auth-stateful`, `auth-app`, `auth-ci-role`) are constant across accounts —
no collision because the accounts differ.

| env     | account        | host                       | how it deploys                                  |
| ------- | -------------- | -------------------------- | ----------------------------------------------- |
| `local` | 586098609055 ¹ | dev.auth.ericminassian.com | a developer, manually, with their own creds     |
| `prod`  | 399827112494   | auth.ericminassian.com     | GitHub Actions, automatically on merge to `main`|

¹ `local` is **not pinned** to an account — it resolves from `CDK_DEFAULT_ACCOUNT`,
so it deploys into whatever account your credentials provide. The dev DNS
delegation role trusts the `eric-dev` account (586098609055).

## DNS delegation (cross-account, automated)

The parent zone `ericminassian.com` lives in the org-management account
(`298499393596`, repo `~/projects/aws`). It exposes one scoped IAM role per
subdomain, `route53-delegation-<host-with-dashes>`, that trusts the member account
and may UPSERT/DELETE only that subdomain's `NS` record in the root zone.

`AuthStatefulStack` creates the subdomain's hosted zone and, via
`CrossAccountZoneDelegationRecord`, assumes that role to register its `NS` records
in the parent zone. No manual nameserver copying. The role ARN is derived from the
**full host** in `delegationRoleArn()` (`infra/config/types.ts`) and must match the
org repo's `delegationRoleName()` — don't change one without the other.

All subdomains are delegated **directly from the root `ericminassian.com` zone**
(there is no intermediate `auth.ericminassian.com` zone in the management account;
that zone is owned by the prod member account).

## Ongoing prod deploys (the pipeline)

`.github/workflows/deploy.yml`, on push/merge to `main` (or manual
`workflow_dispatch`):

1. **checks** — reuses `ci.yml` (rust clippy/tests, OpenAPI drift, TS typecheck/build,
   and the full Playwright e2e against a local DynamoDB + dev API). This is the gate.
2. **deploy** — `environment: prod`; builds the Rust ARM64 Lambda + the SPA, assumes
   the prod deploy role via GitHub OIDC, `cdk deploy --context env=prod AuthStateful
   AuthApp`, then seeds the OIDC client registry (`scripts/seed.ts`).

The pipeline **never** deploys `AuthCiRole` — that role is what the pipeline assumes,
so it must already exist (see bring-up below). Prod is unattended; if you want a human
gate, add a required reviewer to the `prod` GitHub Environment.

## One-time bring-up

### 1. DNS delegation roles (management account)

The prod role (`route53-delegation-auth-ericminassian-com`) already exists. The dev
role is added by this repo's companion change to `~/projects/aws` (`cdk/config.ts`
sets `subdomain: dev.auth.ericminassian.com` on `eric-dev`):

```sh
cd ~/projects/aws && pnpm login && pnpm deploy   # management creds
```

### 2. Prod account (399827112494) — admin creds

Get admin creds for the account (SSO admin, or from the management account assume
`arn:aws:iam::399827112494:role/OrganizationAccountAccessRole`). Then:

```sh
cd infra
# Bootstrap with the DEFAULT qualifier (hnb659fds) — the deploy role is scoped to
# cdk-hnb659fds-* roles; a custom --qualifier would break every pipeline deploy.
pnpm exec cdk bootstrap aws://399827112494/us-east-1
# Deploy the GitHub OIDC deploy role, then copy its DeployRoleArn output.
pnpm exec cdk deploy --context env=prod AuthCiRole
```

> Pre-flight: an account may have only **one** GitHub Actions OIDC provider. If
> `aws iam list-open-id-connect-providers` already lists
> `token.actions.githubusercontent.com`, import it in `ci-role-stack.ts` with
> `OpenIdConnectProvider.fromOpenIdConnectProviderArn` instead of creating it.

### 3. GitHub

Create a **`prod` Environment** and set `AWS_DEPLOY_ROLE_ARN` as an **environment**
secret on it (= the `DeployRoleArn` output from step 2). It must be environment-scoped:
the deploy role's trust policy requires the OIDC subject
`repo:eric-minassian/auth:environment:prod`, which only matches when the job declares
`environment: prod`.

Then push to `main` — the pipeline runs.

> First prod deploy of `AuthApp` may sit in ACM certificate validation for a few
> minutes while the new `NS` delegation propagates from the root zone. This is
> expected; `AuthStateful` (which creates the zone + delegation) deploys first.

## Local deploys (a dev's own account)

No GitHub Actions. With eric-dev credentials (`AWS_PROFILE=dev`), one-time
`cdk bootstrap aws://586098609055/us-east-1`, then:

```sh
# Build the artifacts (cargo-lambda + zig toolchain required for the Rust Lambda).
cargo lambda build --release --arm64 --bin auth-service
pnpm --filter web build

cd infra
AWS_PROFILE=dev LAMBDA_DIST=../target/lambda/auth-service SPA_DIST=../apps/web/dist \
  pnpm exec cdk deploy --context env=local AuthStateful AuthApp
AWS_PROFILE=dev pnpm exec tsx scripts/seed.ts
```

This serves `https://dev.auth.ericminassian.com`. (Day-to-day local development
doesn't need a cloud deploy at all — use `pnpm dev`, which runs the stack against
DynamoDB Local.)

## Signing-key rotation (publish-before-sign)

Two ES256 KMS keys are always provisioned — `alias/auth-jwt-a` and
`alias/auth-jwt-b`. Both public keys are always served by
`/.well-known/jwks.json`; only the **active** one signs. The active key is
selected by `activeSigningKey` in `infra/config/environments.ts`, which orders
`KMS_KEY_IDS` (active first) for the Lambda.

To rotate (e.g. annually, or on suspicion of compromise):

1. **Confirm the standby is published.** Both keys are in JWKS at all times,
   so any verifier that has fetched JWKS in the last 10 minutes (the SDK's
   jose cache TTL; unknown `kid`s also trigger a refetch) already has it.
2. **Flip** `activeSigningKey` (`"a"` → `"b"`) and merge — the pipeline
   deploys it. New tokens now carry the standby's `kid`; old tokens keep
   verifying because the retired key stays published.
3. **Leave both keys published.** Access tokens live 10 minutes and id_tokens
   5, but `id_token_hint` at logout accepts expired id_tokens, so the retired
   key must stay in JWKS until you are comfortable rejecting stale hints
   (they fail soft — logout falls back to the confirmation page).
4. **For a compromised key**: after the flip, ALSO disable the retired key in
   KMS (`aws kms disable-key`) once step 2's deploy is out — verification
   uses only the published public keys, so disabling breaks nothing except
   the attacker's ability to sign.
5. To replace the retired key material entirely, schedule key deletion and
   provision a fresh standby (new CDK logical id), then repeat.

An emergency rotation is therefore: flip config → merge → (optionally)
disable the old key. No RP ever sees an unknown `kid`.
