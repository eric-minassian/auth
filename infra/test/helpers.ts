import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AuthServiceStack } from '../lib/auth-service-stack.js';
import type { AuthServiceConfigInput } from '../lib/config.js';

export const ACCOUNT = '111122223333';
export const REGION = 'eu-west-1';
export const CERT_ARN = `arn:aws:acm:${REGION}:${ACCOUNT}:certificate/12345678-1234-4123-8123-123456789012`;

/** Feature flags exactly as the CDK app uses them. */
export const CDK_CONTEXT = (
  JSON.parse(readFileSync(path.join(import.meta.dirname, '..', 'cdk.json'), 'utf8')) as {
    context: Record<string, unknown>;
  }
).context;

/** A temp directory with an executable dummy `bootstrap`, standing in for the cargo-lambda output. */
export function makeLambdaAsset(options: { executable?: boolean; withBootstrap?: boolean } = {}): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'auth-infra-asset-'));
  if (options.withBootstrap !== false) {
    const bootstrap = path.join(dir, 'bootstrap');
    writeFileSync(bootstrap, '#!/bin/sh\nexit 1\n');
    chmodSync(bootstrap, options.executable === false ? 0o644 : 0o755);
  }
  return dir;
}

export function makeEmptyDir(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'auth-infra-empty-'));
  mkdirSync(dir, { recursive: true });
  return dir;
}

let sharedAsset: string | undefined;

/** A valid configuration; tests override single fields. */
export function validConfig(overrides: Record<string, unknown> = {}): AuthServiceConfigInput {
  sharedAsset ??= makeLambdaAsset();
  return {
    account: ACCOUNT,
    region: REGION,
    domainName: 'auth.example.com',
    certificateArn: CERT_ARN,
    hostedZone: { id: 'Z0123456789ABCDEFGHIJ', name: 'example.com' },
    rpId: 'example.com',
    rpName: 'Example',
    allowedOrigins: ['https://app.example.com', 'android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
    corsOrigins: ['https://app.example.com'],
    audiences: ['https://api.example.com'],
    clientIds: ['web', 'ios', 'android', 'cli'],
    lambdaAssetPath: sharedAsset,
    ...overrides,
  };
}

export interface Synthesized {
  readonly app: App;
  readonly stack: AuthServiceStack;
  readonly template: Template;
}

export function synth(config: AuthServiceConfigInput = validConfig()): Synthesized {
  const app = new App({ context: CDK_CONTEXT });
  const stack = new AuthServiceStack(app, 'TestAuthStack', { config });
  return { app, stack, template: Template.fromStack(stack) };
}

// ---------------------------------------------------------------------------
// Template helpers.
// ---------------------------------------------------------------------------

export interface PolicyStatementJson {
  Sid?: string;
  Effect: string;
  Action: string | string[];
  Resource?: unknown;
  Principal?: unknown;
  Condition?: Record<string, Record<string, unknown>>;
}

export function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

export type Resources = Record<string, { Type: string; Properties: Record<string, unknown> }>;

export function resourcesOfType(template: Template, type: string): Resources {
  return template.findResources(type) as Resources;
}

export function onlyResource(template: Template, type: string): { id: string; props: Record<string, unknown> } {
  const found = Object.entries(resourcesOfType(template, type));
  if (found.length !== 1) {
    throw new Error(`expected exactly one ${type}, found ${String(found.length)}`);
  }
  const [id, res] = found[0] as [string, { Properties: Record<string, unknown> }];
  return { id, props: res.Properties };
}

/** `{ "Fn::GetAtt": [id, "Arn"] }` → id; `{ Ref: id }` → id. */
export function refTarget(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const v = value as Record<string, unknown>;
  if (Array.isArray(v['Fn::GetAtt'])) return String((v['Fn::GetAtt'] as unknown[])[0]);
  if (typeof v.Ref === 'string') return v.Ref;
  return undefined;
}

/**
 * Logical ID of the KMS key created as `Keys/<name>` (logical IDs are the
 * construct path plus an 8-hex-digit hash).
 */
export function keyId(template: Template, name: string): string {
  const pattern = new RegExp(`^Keys${name}[0-9A-F]{8}$`);
  const matches = Object.keys(template.findResources('AWS::KMS::Key')).filter((id) => pattern.test(id));
  const [only, ...rest] = matches;
  if (only === undefined || rest.length > 0) {
    throw new Error(`expected one KMS key named ${name}, found [${matches.join(', ')}]`);
  }
  return only;
}

export interface ResourceJson {
  Type: string;
  Properties: Record<string, unknown>;
  DependsOn?: string[];
  DeletionPolicy?: string;
  UpdateReplacePolicy?: string;
}

/** A resource of the synthesized template by logical ID. */
export function resource(template: Template, logicalId: string): ResourceJson {
  const all = (template.toJSON() as { Resources: Record<string, ResourceJson> }).Resources;
  const found = all[logicalId];
  if (found === undefined) throw new Error(`no resource ${logicalId}`);
  return found;
}

export function outputs(template: Template): Record<string, { Value: unknown }> {
  return (template.toJSON() as { Outputs: Record<string, { Value: unknown }> }).Outputs;
}
