import * as cdk from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { describe, expect, it } from "vitest";

import type { AuthConfig } from "../config/types.js";
import { AuthAppStack } from "../lib/stacks/app-stack.js";
import { AuthStatefulStack } from "../lib/stacks/stateful-stack.js";

const config: AuthConfig = {
  env: { account: "123456789012", region: "us-east-1" },
  domain: "ericminassian.com",
  subdomain: "auth",
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
