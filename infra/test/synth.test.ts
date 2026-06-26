import * as cdk from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { describe, expect, it } from "vitest";

import { getConfig } from "../config/environments.js";
import type { AuthConfig } from "../config/types.js";
import { AuthAppStack } from "../lib/stacks/app-stack.js";
import { AuthCiRoleStack } from "../lib/stacks/ci-role-stack.js";
import { AuthStatefulStack } from "../lib/stacks/stateful-stack.js";

const config: AuthConfig = {
  name: "prod",
  env: { account: "123456789012", region: "us-east-1" },
  domain: "ericminassian.com",
  subdomain: "auth",
  delegation: { managementAccountId: "298499393596", parentZoneName: "ericminassian.com" },
  lambdaAssetPath: "assets/lambda-bootstrap",
  spaAssetPath: "assets/spa-placeholder",
};

function synth() {
  const app = new cdk.App();
  const stateful = new AuthStatefulStack(app, "AuthStateful", config, { env: config.env });
  const appStack = new AuthAppStack(app, "AuthApp", config, {
    env: config.env,
    hostedZone: stateful.hostedZone,
    table: stateful.table,
    signingKey: stateful.signingKey,
  });
  return {
    stateful: Template.fromStack(stateful),
    app: Template.fromStack(appStack),
  };
}

describe("AuthStateful", () => {
  const { stateful } = synth();

  it("creates the delegated subdomain hosted zone", () => {
    stateful.hasResourceProperties("AWS::Route53::HostedZone", {
      Name: "auth.ericminassian.com.",
    });
  });

  it("registers cross-account NS delegation via the org-management role", () => {
    // The role name derives from the full host, and must match the org repo's
    // route53-delegation-<host> role (see config/types.ts delegationRoleArn).
    stateful.hasResourceProperties("Custom::CrossAccountZoneDelegation", {
      AssumeRoleArn: "arn:aws:iam::298499393596:role/route53-delegation-auth-ericminassian-com",
      ParentZoneName: "ericminassian.com",
    });
  });

  it("creates the single table with the GSI1 index and TTL, matching the Rust schema", () => {
    // These names are the contract between crates/.../store/schema.rs and the
    // deployed table; a mismatch would break every query.
    stateful.hasResourceProperties("AWS::DynamoDB::GlobalTable", {
      AttributeDefinitions: Match.arrayWith([
        { AttributeName: "PK", AttributeType: "S" },
        { AttributeName: "SK", AttributeType: "S" },
        { AttributeName: "GSI1PK", AttributeType: "S" },
        { AttributeName: "GSI1SK", AttributeType: "S" },
      ]),
      GlobalSecondaryIndexes: Match.arrayWith([
        Match.objectLike({ IndexName: "GSI1" }),
      ]),
      TimeToLiveSpecification: { AttributeName: "ttl", Enabled: true },
    });
  });

  it("uses an ECC_NIST_P256 KMS key for ES256 signing, retained", () => {
    stateful.hasResourceProperties("AWS::KMS::Key", {
      KeySpec: "ECC_NIST_P256",
      KeyUsage: "SIGN_VERIFY",
    });
    stateful.hasResource("AWS::KMS::Key", { DeletionPolicy: "Retain" });
  });
});

describe("AuthApp", () => {
  const { app } = synth();

  it("runs the Lambda on ARM64 provided.al2023", () => {
    app.hasResourceProperties("AWS::Lambda::Function", {
      Runtime: "provided.al2023",
      Handler: "bootstrap",
      Architectures: ["arm64"],
    });
  });

  it("injects the CloudFront origin-lock secret into the Lambda env", () => {
    // The backend fails open if ORIGIN_VERIFY_SECRET is unset, so the env var
    // must always be present; its value is a resolved Secrets Manager reference.
    app.hasResourceProperties("AWS::Lambda::Function", {
      Environment: {
        Variables: Match.objectLike({
          ORIGIN_VERIFY_SECRET: Match.anyValue(),
        }),
      },
    });
  });

  it("grants the Lambda only kms:Sign and kms:GetPublicKey on the key", () => {
    app.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith(["kms:Sign", "kms:GetPublicKey"]),
            Effect: "Allow",
          }),
        ]),
      },
    });
  });

  it("serves the SPA and routes /api, /oauth, /.well-known to the API origin", () => {
    app.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        Aliases: ["auth.ericminassian.com"],
        CacheBehaviors: Match.arrayWith([
          Match.objectLike({ PathPattern: "/api/*" }),
          Match.objectLike({ PathPattern: "/oauth/*" }),
          Match.objectLike({ PathPattern: "/.well-known/*" }),
        ]),
      }),
    });
  });

  it("stamps the origin-lock header on the API origin", () => {
    // CloudFront must inject `x-origin-verify` on every request to the API
    // origin so the backend can prove the request came through the distribution
    // (not directly via the public execute-api endpoint). The header name must
    // match the Rust middleware exactly.
    app.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        Origins: Match.arrayWith([
          Match.objectLike({
            OriginCustomHeaders: Match.arrayWith([
              Match.objectLike({ HeaderName: "x-origin-verify" }),
            ]),
          }),
        ]),
      }),
    });
  });

  it("forwards the viewer ASN to the API origin for per-ASN rate limiting", () => {
    // The Rust backend rate-limits per source network using the tamper-proof
    // CloudFront-Viewer-ASN header, so the API origin request policy must
    // forward it (alongside CloudFront-Viewer-Address).
    app.hasResourceProperties("AWS::CloudFront::OriginRequestPolicy", {
      OriginRequestPolicyConfig: Match.objectLike({
        HeadersConfig: Match.objectLike({
          Headers: Match.arrayWith(["CloudFront-Viewer-Address", "CloudFront-Viewer-ASN"]),
        }),
      }),
    });
  });

  it("invalidates the OIDC metadata cache on deploy", () => {
    // A Lambda-only deploy must bust the edge cache for /.well-known/*, or
    // discovery/JWKS serve stale responses for up to max-age (1h).
    app.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "cloudfront:CreateInvalidation",
            Effect: "Allow",
          }),
        ]),
      },
    });
  });

  it("throttles the HTTP API default stage", () => {
    app.hasResourceProperties("AWS::ApiGatewayV2::Stage", {
      DefaultRouteSettings: { ThrottlingRateLimit: 25, ThrottlingBurstLimit: 50 },
    });
  });

  it("enforces HSTS and a CSP on the SPA", () => {
    app.hasResourceProperties("AWS::CloudFront::ResponseHeadersPolicy", {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          StrictTransportSecurity: Match.objectLike({ Preload: true }),
          ContentSecurityPolicy: Match.objectLike({
            ContentSecurityPolicy: Match.stringLikeRegexp("frame-ancestors 'none'"),
          }),
        }),
      }),
    });
  });
});

describe("AuthCiRole", () => {
  const ciRole = Template.fromStack(
    new AuthCiRoleStack(new cdk.App(), "AuthCiRole", getConfig("prod"), {
      env: getConfig("prod").env,
    }),
  );

  it("registers the GitHub Actions OIDC provider", () => {
    ciRole.hasResourceProperties("Custom::AWSCDKOpenIdConnectProvider", {
      Url: "https://token.actions.githubusercontent.com",
      ClientIDList: ["sts.amazonaws.com"],
    });
  });

  it("trusts only this repo's runs against the matching GitHub Environment", () => {
    ciRole.hasResourceProperties("AWS::IAM::Role", {
      RoleName: "auth-github-deploy-prod",
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "sts:AssumeRoleWithWebIdentity",
            Condition: {
              StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
              StringLike: {
                "token.actions.githubusercontent.com:sub":
                  "repo:eric-minassian/auth:environment:prod",
              },
            },
          }),
        ]),
      }),
    });
  });

  it("can only assume the CDK bootstrap roles to deploy", () => {
    ciRole.hasResourceProperties("AWS::IAM::Policy", {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: "sts:AssumeRole",
            Resource: "arn:aws:iam::399827112494:role/cdk-hnb659fds-*-399827112494-us-east-1",
          }),
        ]),
      },
    });
  });
});
