#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";

import { getConfig } from "../config/environments.js";
import { AuthAppStack } from "../lib/stacks/app-stack.js";
import { AuthCiRoleStack } from "../lib/stacks/ci-role-stack.js";
import { AuthStatefulStack } from "../lib/stacks/stateful-stack.js";

const app = new cdk.App();

// Environment is selected with `cdk --context env=<local|beta|prod>`; defaults
// to `local` so a bare `cdk` command never targets beta/prod by accident.
const envName = (app.node.tryGetContext("env") as string | undefined) ?? "local";
const config = getConfig(envName);

const stateful = new AuthStatefulStack(app, "AuthStateful", config, {
  stackName: "auth-stateful",
  env: config.env,
});

new AuthAppStack(app, "AuthApp", config, {
  stackName: "auth-app",
  env: config.env,
  hostedZone: stateful.hostedZone,
  table: stateful.table,
  signingKey: stateful.signingKey,
});

// The GitHub Actions deploy role only exists for the CI-deployed environments;
// `local` deploys use the developer's own credentials directly.
if (config.name !== "local") {
  new AuthCiRoleStack(app, "AuthCiRole", config, {
    stackName: "auth-ci-role",
    env: config.env,
  });
}

cdk.Tags.of(app).add("project", "auth");
cdk.Tags.of(app).add("env", config.name);
