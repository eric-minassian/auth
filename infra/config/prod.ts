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
    // Overwritten by `cargo lambda build` output in the deploy workflow; a
    // committed placeholder keeps `cdk synth` working offline.
    lambdaAssetPath: "assets/lambda-bootstrap",
    // Built by `pnpm --filter web build`; placeholder for offline synth.
    spaAssetPath: "assets/spa-placeholder",
  };
}
