/**
 * CDK app entry point.
 *
 *   cdk synth  -c config=config/example.json
 *   cdk deploy -c config=config/prod.json
 *
 * The config file is JSON matching `AuthServiceConfigInput` (lib/config.ts).
 * A relative `lambdaAssetPath` is resolved against the config file's directory.
 */
import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { App, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AuthServiceStack } from '../lib/auth-service-stack.js';
import { parseConfig, type AuthServiceConfigInput } from '../lib/config.js';

const app = new App({ analyticsReporting: false });

const configArg: unknown = app.node.tryGetContext('config');
if (typeof configArg !== 'string' || configArg === '') {
  throw new Error('Missing config. Pass the path to a JSON config file, e.g. `cdk synth -c config=config/example.json`.');
}
const configPath = path.resolve(configArg);
let raw: unknown;
try {
  raw = JSON.parse(readFileSync(configPath, 'utf8'));
} catch (err) {
  throw new Error(`Cannot read config file ${configPath}: ${err instanceof Error ? err.message : String(err)}`, {
    cause: err,
  });
}
const configBaseDir = path.dirname(configPath);
// Validate once up front so the stack name comes from a validated config.
const { stackName } = parseConfig(raw, { baseDir: configBaseDir });

new AuthServiceStack(app, stackName, {
  // Shape already checked by parseConfig above; the stack validates it again.
  config: raw as AuthServiceConfigInput,
  configBaseDir,
});

// cdk-nag (v3 runs as a CDK policy-validation plugin): any finding that is not
// acknowledged with a written reason (lib/nag-suppressions.ts) fails synthesis.
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
