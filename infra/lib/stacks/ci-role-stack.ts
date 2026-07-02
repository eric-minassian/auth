import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import type { Construct } from "constructs";

import type { AuthConfig } from "../../config/types.js";

const GITHUB_OIDC_URL = "https://token.actions.githubusercontent.com";
const GITHUB_REPO = "eric-minassian/auth";

/**
 * The IAM trust GitHub Actions assumes to deploy this account, kept in its own
 * stack because it must be deployed ONCE with admin credentials before the
 * pipeline can run (the pipeline assumes this very role, so it can't create it).
 *
 * Deploy: `cdk deploy --context env=<env> AuthCiRole`, then set the
 * `DeployRoleArn` output as the `AWS_DEPLOY_ROLE_ARN` secret on the matching
 * GitHub Environment. See `docs/deploy.md`.
 */
export class AuthCiRoleStack extends cdk.Stack {
  constructor(scope: Construct, id: string, config: AuthConfig, props?: cdk.StackProps) {
    super(scope, id, props);

    // One GitHub OIDC identity provider per account. (If the account already
    // has one, import it with `fromOpenIdConnectProviderArn` instead — see
    // docs/deploy.md.)
    const provider = new iam.OpenIdConnectProvider(this, "GitHubOidcProvider", {
      url: GITHUB_OIDC_URL,
      clientIds: ["sts.amazonaws.com"],
    });

    // Trust only this repo's runs that target the matching GitHub Environment,
    // so a beta-environment run can never assume the prod role (and vice versa).
    const deployRole = new iam.Role(this, "DeployRole", {
      roleName: `auth-github-deploy-${config.name}`,
      description: `GitHub Actions deploy role for ${GITHUB_REPO} (${config.name})`,
      maxSessionDuration: cdk.Duration.hours(1),
      assumedBy: new iam.OpenIdConnectPrincipal(provider, {
        StringEquals: {
          [`${GITHUB_OIDC_URL.replace("https://", "")}:aud`]: "sts.amazonaws.com",
        },
        StringLike: {
          [`${GITHUB_OIDC_URL.replace("https://", "")}:sub`]:
            `repo:${GITHUB_REPO}:environment:${config.name}`,
        },
      }),
    });

    const account = this.account;
    const region = this.region;

    // `cdk deploy` works entirely by assuming the bootstrap roles; the GitHub
    // role itself needs almost no direct permissions.
    deployRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "AssumeCdkBootstrapRoles",
        actions: ["sts:AssumeRole"],
        resources: [`arn:aws:iam::${account}:role/cdk-hnb659fds-*-${account}-${region}`],
      }),
    );
    deployRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ReadCdkBootstrapVersion",
        actions: ["ssm:GetParameter"],
        resources: [`arn:aws:ssm:${region}:${account}:parameter/cdk-bootstrap/hnb659fds/version`],
      }),
    );
    // The alert email lives in SSM (never in this public repo); the deploy
    // workflow reads it and passes `-c alertEmail=...` so the SNS subscription
    // is wired by the pipeline. See docs/deploy.md.
    deployRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ReadAlertEmail",
        actions: ["ssm:GetParameter"],
        resources: [`arn:aws:ssm:${region}:${account}:parameter/auth/alert-email`],
      }),
    );

    // The seed step (scripts/seed.ts) runs directly under this role after the
    // deploy: it reads the table name from the auth-stateful stack and writes
    // the OIDC client registry.
    deployRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "SeedClientsLookup",
        actions: ["cloudformation:DescribeStacks"],
        resources: [`arn:aws:cloudformation:${region}:${account}:stack/auth-*/*`],
      }),
    );
    deployRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "SeedClientsWrite",
        actions: ["dynamodb:DescribeTable", "dynamodb:PutItem"],
        resources: [`arn:aws:dynamodb:${region}:${account}:table/*`],
      }),
    );

    new cdk.CfnOutput(this, "DeployRoleArn", {
      value: deployRole.roleArn,
      description: `Set as the AWS_DEPLOY_ROLE_ARN secret on the '${config.name}' GitHub Environment`,
    });
  }
}
