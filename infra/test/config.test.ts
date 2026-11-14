import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { App } from 'aws-cdk-lib';
import { describe, expect, it } from 'vitest';
import { AuthServiceStack } from '../lib/auth-service-stack.js';
import { ConfigError, DEFAULTS, parseConfig } from '../lib/config.js';
import { CDK_CONTEXT, CERT_ARN, makeEmptyDir, makeLambdaAsset, validConfig } from './helpers.js';

/** Runs parseConfig and returns the reported problems (fails if it does not throw). */
function problems(overrides: Record<string, unknown>): readonly string[] {
  try {
    parseConfig(validConfig(overrides));
  } catch (err) {
    if (err instanceof ConfigError) return err.problems;
    throw err;
  }
  throw new Error(`expected ConfigError for ${JSON.stringify(overrides)}`);
}

function expectRejected(overrides: Record<string, unknown>, field: string, message: RegExp): void {
  const found = problems(overrides);
  expect(found.some((p) => p.startsWith(field) && message.test(p)), found.join('\n')).toBe(true);
}

describe('parseConfig: valid input', () => {
  it('accepts a valid config and applies defaults', () => {
    const cfg = parseConfig(validConfig());
    expect(cfg.issuer).toBe('https://auth.example.com');
    expect(cfg.stackName).toBe(DEFAULTS.stackName);
    expect(cfg.waf).toEqual(DEFAULTS.waf);
    expect(cfg.apiThrottle).toEqual(DEFAULTS.apiThrottle);
    expect(cfg.tlsSecurityPolicy).toBe('SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09');
    expect(cfg.manageApiGatewayCloudWatchRole).toBe(true);
    expect(cfg.keys).toEqual({
      accessToken: { active: 1, previous: [] },
      refreshToken: { active: 1, previous: [] },
      dpopNonce: { active: 1 },
    });
    expect(cfg.reservedConcurrency).toBeUndefined();
    expect(path.isAbsolute(cfg.lambdaAssetPath)).toBe(true);
  });

  it('resolves a relative lambdaAssetPath against baseDir', () => {
    const asset = makeLambdaAsset();
    const cfg = parseConfig(validConfig({ lambdaAssetPath: path.basename(asset) }), { baseDir: path.dirname(asset) });
    expect(cfg.lambdaAssetPath).toBe(asset);
  });

  it('accepts audiences with a path and canonical android origins', () => {
    const cfg = parseConfig(
      validConfig({
        audiences: ['https://api.example.com', 'https://api.example.com/v2/'],
        allowedOrigins: ['https://example.com', 'android:apk-key-hash:pMgTzG00TdlP-4y_H37hwHl9RgZoKLL91aBHk6wmaF4'],
      }),
    );
    expect(cfg.audiences).toEqual(['https://api.example.com', 'https://api.example.com/v2/']);
  });

  it('accepts key generations with previous keys', () => {
    const cfg = parseConfig(validConfig({ keys: { accessToken: { active: 2, previous: [1] } } }));
    expect(cfg.keys.accessToken).toEqual({ active: 2, previous: [1] });
    expect(cfg.keys.refreshToken).toEqual({ active: 1, previous: [] });
  });

  it('accepts config/example.json (with a real asset directory)', () => {
    const example = JSON.parse(
      readFileSync(path.join(import.meta.dirname, '..', 'config', 'example.json'), 'utf8'),
    ) as Record<string, unknown>;
    const cfg = parseConfig({ ...example, lambdaAssetPath: makeLambdaAsset() });
    expect(cfg.issuer).toBe('https://auth.example.com');
  });
});

describe('parseConfig: rejects invalid input', () => {
  it('rejects a non-object config', () => {
    expect(() => parseConfig('nope')).toThrow(ConfigError);
    expect(() => parseConfig(null)).toThrow(/must be an object/);
  });

  it('rejects unknown properties (typos)', () => {
    expectRejected({ corsOrigin: ['https://app.example.com'] }, 'corsOrigin', /unknown property/);
  });

  it('rejects non-https CORS origins', () => {
    expectRejected({ corsOrigins: ['http://app.example.com'] }, 'corsOrigins[0]', /must use https/);
  });

  it('rejects CORS origins that are not bare canonical origins', () => {
    expectRejected({ corsOrigins: ['https://app.example.com/'] }, 'corsOrigins[0]', /canonical form/);
    expectRejected({ corsOrigins: ['https://app.example.com/login'] }, 'corsOrigins[0]', /canonical form/);
    expectRejected({ corsOrigins: ['https://App.example.com'] }, 'corsOrigins[0]', /canonical form/);
    expectRejected({ corsOrigins: ['https://app.example.com:443'] }, 'corsOrigins[0]', /canonical form/);
    expectRejected({ corsOrigins: ['https://127.0.0.1'] }, 'corsOrigins[0]', /DNS host name/);
    expectRejected({ corsOrigins: ['*'] }, 'corsOrigins[0]', /not a valid URL origin/);
  });

  it('rejects empty lists', () => {
    expectRejected({ audiences: [] }, 'audiences', /at least one entry/);
    expectRejected({ clientIds: [] }, 'clientIds', /at least one entry/);
    expectRejected({ allowedOrigins: [] }, 'allowedOrigins', /at least one entry/);
    expectRejected({ corsOrigins: [] }, 'corsOrigins', /at least one entry/);
  });

  it('rejects duplicates and commas in list entries', () => {
    expectRejected({ clientIds: ['web', 'web'] }, 'clientIds[1]', /duplicate/);
    expectRejected({ audiences: ['https://api.example.com/a,b'] }, 'audiences[0]', /comma/);
  });

  it('rejects malformed audiences', () => {
    expectRejected({ audiences: ['http://api.example.com'] }, 'audiences[0]', /https/);
    expectRejected({ audiences: ['https://api.example.com/#x'] }, 'audiences[0]', /fragment/);
    expectRejected({ audiences: ['https://api.example.com/?a=1'] }, 'audiences[0]', /query/);
    expectRejected({ audiences: ['https://user@api.example.com'] }, 'audiences[0]', /user info/);
    expectRejected({ audiences: ['api.example.com'] }, 'audiences[0]', /not a valid absolute URI/);
    expectRejected({ audiences: ['https://API.example.com'] }, 'audiences[0]', /canonical/);
  });

  it('rejects listing the issuer as an audience', () => {
    expectRejected({ audiences: ['https://auth.example.com'] }, 'audiences[0]', /issuer is always an allowed audience/);
  });

  it('rejects invalid client IDs', () => {
    expectRejected({ clientIds: ['web app'] }, 'clientIds[0]', /must be 1-64 characters/);
    expectRejected({ clientIds: [''] }, 'clientIds[0]', /must not be empty/);
    expectRejected({ clientIds: [42] }, 'clientIds[0]', /must be a string/);
  });

  it('rejects WebAuthn origins that cannot use the RP ID', () => {
    expectRejected({ allowedOrigins: ['https://app.example.org'] }, 'allowedOrigins[0]', /cannot use RP ID/);
    expectRejected({ allowedOrigins: ['https://notexample.com'] }, 'allowedOrigins[0]', /cannot use RP ID/);
    expectRejected({ allowedOrigins: ['http://app.example.com'] }, 'allowedOrigins[0]', /https/);
  });

  it('rejects malformed Android origins', () => {
    expectRejected({ allowedOrigins: ['android:apk-key-hash:short'] }, 'allowedOrigins[0]', /base64url SHA-256/);
    // 43 chars but non-canonical (non-zero trailing bits).
    expectRejected(
      { allowedOrigins: ['android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB'] },
      'allowedOrigins[0]',
      /base64url SHA-256/,
    );
    expectRejected(
      { allowedOrigins: ['android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='] },
      'allowedOrigins[0]',
      /base64url SHA-256/,
    );
  });

  it('rejects invalid DNS names', () => {
    expectRejected({ domainName: 'Auth.Example.com' }, 'domainName', /not a valid DNS name/);
    expectRejected({ domainName: 'auth.example.com.' }, 'domainName', /not a valid DNS name/);
    expectRejected({ domainName: '10.0.0.1' }, 'domainName', /not a valid DNS name/);
    expectRejected({ domainName: 'localhost' }, 'domainName', /not a valid DNS name/);
    expectRejected({ rpId: 'https://example.com' }, 'rpId', /not a valid DNS name/);
  });

  it('rejects account, region and certificate mismatches', () => {
    expectRejected({ account: '1234' }, 'account', /12-digit/);
    expectRejected({ region: 'Europe' }, 'region', /not an AWS region/);
    expectRejected({ certificateArn: 'arn:aws:acm:eu-west-1:111122223333:cert/x' }, 'certificateArn', /not an ACM/);
    expectRejected(
      { certificateArn: CERT_ARN.replace('eu-west-1', 'us-east-1') },
      'certificateArn',
      /must equal the stack region/,
    );
    expectRejected(
      { certificateArn: CERT_ARN.replace('111122223333', '999999999999') },
      'certificateArn',
      /must equal the stack account/,
    );
  });

  it('rejects a hosted zone that does not contain the domain', () => {
    expectRejected({ hostedZone: { id: 'Z0123456789ABCDEFGHIJ', name: 'example.org' } }, 'hostedZone.name', /not inside/);
    expectRejected({ hostedZone: { id: 'bad', name: 'example.com' } }, 'hostedZone.id', /hosted zone ID/);
    expectRejected({ hostedZone: { id: 'Z0123456789ABCDEFGHIJ' } }, 'hostedZone.name', /must be a string/);
  });

  it('rejects an invalid RP name', () => {
    expectRejected({ rpName: '' }, 'rpName', /must not be empty/);
    expectRejected({ rpName: 'x'.repeat(65) }, 'rpName', /64 bytes/);
    expectRejected({ rpName: 'Bad\nName' }, 'rpName', /control characters/);
  });

  it('rejects a missing or incomplete Lambda asset', () => {
    expectRejected({ lambdaAssetPath: '/nonexistent/auth-service' }, 'lambdaAssetPath', /not a directory/);
    expectRejected({ lambdaAssetPath: makeEmptyDir() }, 'lambdaAssetPath', /bootstrap.*does not exist/);
    expectRejected(
      { lambdaAssetPath: makeLambdaAsset({ executable: false }) },
      'lambdaAssetPath',
      /not executable/,
    );
  });

  it('rejects invalid WAF limits', () => {
    expectRejected({ waf: { rateLimitPerIp: 5 } }, 'waf.rateLimitPerIp', /between 10 and/);
    expectRejected({ waf: { rateLimitPerIp: 100, sensitiveRateLimitPerIp: 100 } }, 'waf.sensitiveRateLimitPerIp', /lower than/);
    expectRejected({ waf: { evaluationWindowSeconds: 30 } }, 'waf.evaluationWindowSeconds', /one of 60, 120, 300, 600/);
    expectRejected({ waf: { rateLimitPerIp: 1.5 } }, 'waf.rateLimitPerIp', /integer/);
  });

  it('rejects invalid stage throttling and reserved concurrency', () => {
    expectRejected({ apiThrottle: { rateLimit: 0 } }, 'apiThrottle.rateLimit', /between/);
    expectRejected({ apiThrottle: { burstLimit: 10_000 } }, 'apiThrottle.burstLimit', /between/);
    expectRejected({ reservedConcurrency: 0 }, 'reservedConcurrency', /between 1/);
  });

  it('rejects legacy or unknown TLS policies', () => {
    expectRejected({ tlsSecurityPolicy: 'TLS_1_2' }, 'tlsSecurityPolicy', /must be one of/);
    expectRejected({ tlsSecurityPolicy: 'SecurityPolicy_TLS13_1_2_PQ_2025_09' }, 'tlsSecurityPolicy', /must be one of/);
  });

  it('rejects inconsistent key generations', () => {
    expectRejected({ keys: { accessToken: { active: 1, previous: [1] } } }, 'keys.accessToken.previous[0]', /active generation/);
    expectRejected({ keys: { refreshToken: { active: 3, previous: [2, 2] } } }, 'keys.refreshToken.previous[1]', /duplicate/);
    expectRejected({ keys: { refreshToken: { active: 5, previous: [1, 2, 3, 4] } } }, 'keys.refreshToken.previous', /at most 3/);
    expectRejected({ keys: { dpopNonce: { active: 0 } } }, 'keys.dpopNonce.active', /between 1/);
    expectRejected({ keys: { hmac: {} } }, 'keys.hmac', /unknown property/);
  });

  it('reports every problem at once', () => {
    const found = problems({ corsOrigins: ['http://a.example.com'], audiences: [], clientIds: ['a b'] });
    expect(found.length).toBeGreaterThanOrEqual(3);
  });

  it('fails stack synthesis with a clear message on invalid config', () => {
    const app = new App({ context: CDK_CONTEXT });
    expect(
      () => new AuthServiceStack(app, 'Bad', { config: validConfig({ corsOrigins: ['http://app.example.com'] }) }),
    ).toThrow(/Invalid auth service configuration:\n {2}- corsOrigins\[0\]: "http:\/\/app\.example\.com" must use https/);
  });
});
