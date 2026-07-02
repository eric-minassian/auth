import type { AuthConfig, EnvName } from "./types.js";

/**
 * Per-environment CDK configuration. Each environment is its own AWS account;
 * the environment is selected at synth/deploy time with `cdk --context env=<name>`
 * (see `bin/auth.ts`). Account topology and bring-up live in `docs/deploy.md`.
 *
 * Everything is in us-east-1 because CloudFront requires its ACM certificate
 * there; keeping the whole stack in that region avoids cross-region wiring.
 */

const DOMAIN = "ericminassian.com";

// The org-management account that owns the parent `ericminassian.com` zone and
// the per-subdomain cross-account delegation roles (see `~/projects/aws`).
const DELEGATION = {
  managementAccountId: "298499393596",
  parentZoneName: DOMAIN,
} as const;

// The deploy workflow points these at the freshly built artifacts via
// LAMBDA_DIST / SPA_DIST; committed placeholders keep `cdk synth` working
// offline (and in CI checks before a build).
const lambdaAssetPath = process.env.LAMBDA_DIST ?? "assets/lambda-bootstrap";
const spaAssetPath = process.env.SPA_DIST ?? "assets/spa-placeholder";

const ENVIRONMENTS: Record<EnvName, AuthConfig> = {
  // local → a developer's own account, resolved from CDK_DEFAULT_ACCOUNT (not
  // pinned). The dev delegation role trusts the eric-dev account (586098609055).
  local: {
    name: "local",
    env: { account: undefined, region: "us-east-1" },
    domain: DOMAIN,
    subdomain: "dev.auth",
    delegation: DELEGATION,
    lambdaAssetPath,
    spaAssetPath,
    activeSigningKey: "a",
  },
  prod: {
    name: "prod",
    env: { account: "399827112494", region: "us-east-1" },
    domain: DOMAIN,
    subdomain: "auth",
    delegation: DELEGATION,
    lambdaAssetPath,
    spaAssetPath,
    activeSigningKey: "a",
  },
};

/** Resolve the config for an environment name, failing loudly on a typo. */
export function getConfig(name: string): AuthConfig {
  const config = ENVIRONMENTS[name as EnvName];
  if (!config) {
    const valid = Object.keys(ENVIRONMENTS).join(", ");
    throw new Error(`Unknown env "${name}". Use --context env=<${valid}>.`);
  }
  return config;
}
