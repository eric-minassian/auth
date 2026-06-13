#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";

import { prodConfig } from "../config/prod.js";
import { AuthAppStack } from "../lib/stacks/app-stack.js";
import { AuthStatefulStack } from "../lib/stacks/stateful-stack.js";

const app = new cdk.App();
const config = prodConfig();

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

cdk.Tags.of(app).add("project", "auth");
