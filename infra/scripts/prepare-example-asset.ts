/**
 * Creates a placeholder Lambda asset so `npm run synth` works offline without
 * building the Rust service. The placeholder refuses to run; real deployments
 * point `lambdaAssetPath` at `target/lambda/auth-service` (cargo lambda output).
 */
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';

const dir = path.resolve(import.meta.dirname, '..', '.example-asset');
mkdirSync(dir, { recursive: true });
const bootstrap = path.join(dir, 'bootstrap');
writeFileSync(
  bootstrap,
  '#!/bin/sh\necho "placeholder asset: build the service with cargo lambda build --release --arm64" >&2\nexit 1\n',
);
chmodSync(bootstrap, 0o755);
console.log(`placeholder Lambda asset written to ${bootstrap}`);
