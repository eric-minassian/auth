import type { AuthConfig } from "./types.js";

/**
 * Single production config. Everything lives in us-east-1 because CloudFront
 * requires its ACM certificate there — keeping the whole stack in that region
 * avoids cross-region certificate wiring.
 *
 * The account defaults to the `dev` SSO account but can be overridden with
 * `CDK_DEFAULT_ACCOUNT` at synth time.
 */
export function prodConfig(): AuthConfig {
  return {
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT ?? "586098609055",
      region: "us-east-1",
    },
    domain: "ericminassian.com",
    subdomain: "auth",
    // Points at `cargo lambda build` output in the deploy workflow
    // (`LAMBDA_DIST` env); a committed placeholder keeps `cdk synth` working
    // offline.
    lambdaAssetPath: process.env.LAMBDA_DIST ?? "assets/lambda-bootstrap",
    // Built by `pnpm --filter web build`; the deploy workflow points this at
    // the real dist (`SPA_DIST` env) and falls back to a placeholder so
    // `cdk synth` works offline.
    spaAssetPath: process.env.SPA_DIST ?? "assets/spa-placeholder",
  };
}
