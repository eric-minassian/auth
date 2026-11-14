/**
 * Typed, validated configuration for {@link AuthServiceStack}.
 *
 * Every value that ends up in the service environment (docs/protocol.md §13) or
 * in a security control (TLS policy, WAF limits, key generations) is validated
 * here, so a bad config fails synthesis with a precise message instead of
 * producing a deployable-but-broken stack.
 */
import { statSync } from 'node:fs';
import * as path from 'node:path';

/** Enhanced API Gateway TLS policies we allow (strongest first). */
export const ALLOWED_TLS_SECURITY_POLICIES = [
  // TLS 1.3 with hybrid post-quantum key exchange; TLS 1.2 limited to ECDHE + AEAD (forward secrecy).
  'SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09',
  // TLS 1.3 only.
  'SecurityPolicy_TLS13_1_3_2025_09',
  // TLS 1.3 only, FIPS cipher suites.
  'SecurityPolicy_TLS13_1_3_FIPS_2025_09',
] as const;
export type TlsSecurityPolicy = (typeof ALLOWED_TLS_SECURITY_POLICIES)[number];

/** WAF rate-based rule evaluation windows supported by AWS WAF. */
export const ALLOWED_WAF_EVALUATION_WINDOWS = [60, 120, 300, 600] as const;
export type WafEvaluationWindowSeconds = (typeof ALLOWED_WAF_EVALUATION_WINDOWS)[number];

/** AWS WAF rate-based rule limits. */
export const WAF_RATE_LIMIT_MIN = 10;
export const WAF_RATE_LIMIT_MAX = 2_000_000_000;

export const DEFAULTS = {
  stackName: 'AuthServiceStack',
  tlsSecurityPolicy: 'SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09' as TlsSecurityPolicy,
  manageApiGatewayCloudWatchRole: true,
  waf: { rateLimitPerIp: 1000, sensitiveRateLimitPerIp: 60, evaluationWindowSeconds: 300 as WafEvaluationWindowSeconds },
  apiThrottle: { rateLimit: 100, burstLimit: 200 },
} as const;

/** Maximum number of previous key generations kept for verification. */
export const MAX_PREVIOUS_KEY_GENERATIONS = 3;
export const MAX_KEY_GENERATION = 999;

// ---------------------------------------------------------------------------
// Input (what an operator writes) and output (what the stack consumes) types.
// ---------------------------------------------------------------------------

export interface HostedZoneInput {
  /** Route 53 hosted zone ID, e.g. `Z0123456789ABCDEFGHIJ`. */
  readonly id: string;
  /** Zone apex, e.g. `example.com` (no trailing dot). */
  readonly name: string;
}

export interface SigningKeyGenerationsInput {
  /** Generation number of the key that signs new tokens. */
  readonly active: number;
  /** Generations that are still accepted / published but no longer sign. */
  readonly previous?: readonly number[];
}

export interface MacKeyGenerationInput {
  readonly active: number;
}

export interface KeyGenerationsInput {
  readonly accessToken?: SigningKeyGenerationsInput;
  readonly refreshToken?: SigningKeyGenerationsInput;
  readonly dpopNonce?: MacKeyGenerationInput;
}

export interface WafInput {
  /** Requests per IP per evaluation window, all paths. */
  readonly rateLimitPerIp?: number;
  /** Requests per IP per evaluation window for `/v1/register/*` and `/v1/recover/*`. */
  readonly sensitiveRateLimitPerIp?: number;
  readonly evaluationWindowSeconds?: number;
}

export interface ApiThrottleInput {
  /** Steady-state requests per second for the whole stage. */
  readonly rateLimit?: number;
  /** Burst capacity for the whole stage. */
  readonly burstLimit?: number;
}

/** Configuration as written in a JSON config file (or passed directly in code). */
export interface AuthServiceConfigInput {
  readonly stackName?: string;
  readonly account: string;
  readonly region: string;
  /** Public host name of the service; the issuer is `https://<domainName>`. */
  readonly domainName: string;
  /** Regional ACM certificate covering `domainName` (same account and region). */
  readonly certificateArn: string;
  /** When set, A and AAAA alias records for `domainName` are created in this zone. */
  readonly hostedZone?: HostedZoneInput;
  readonly rpId: string;
  readonly rpName: string;
  readonly allowedOrigins: readonly string[];
  readonly corsOrigins: readonly string[];
  readonly audiences: readonly string[];
  readonly clientIds: readonly string[];
  /** Directory containing the `bootstrap` produced by `cargo lambda build --release --arm64`. */
  readonly lambdaAssetPath: string;
  readonly reservedConcurrency?: number;
  readonly waf?: WafInput;
  readonly apiThrottle?: ApiThrottleInput;
  readonly tlsSecurityPolicy?: string;
  /** Manage the regional, account-wide API Gateway CloudWatch Logs role (needed for access logs). */
  readonly manageApiGatewayCloudWatchRole?: boolean;
  readonly keys?: KeyGenerationsInput;
}

export interface SigningKeyGenerations {
  readonly active: number;
  readonly previous: readonly number[];
}

/** Validated, normalized configuration. */
export interface AuthServiceConfig {
  readonly stackName: string;
  readonly account: string;
  readonly region: string;
  readonly domainName: string;
  /** `https://<domainName>` — `AUTH_ISSUER`. */
  readonly issuer: string;
  readonly certificateArn: string;
  readonly hostedZone: HostedZoneInput | undefined;
  readonly rpId: string;
  readonly rpName: string;
  readonly allowedOrigins: readonly string[];
  readonly corsOrigins: readonly string[];
  readonly audiences: readonly string[];
  readonly clientIds: readonly string[];
  /** Absolute path. */
  readonly lambdaAssetPath: string;
  readonly reservedConcurrency: number | undefined;
  readonly waf: {
    readonly rateLimitPerIp: number;
    readonly sensitiveRateLimitPerIp: number;
    readonly evaluationWindowSeconds: WafEvaluationWindowSeconds;
  };
  readonly apiThrottle: { readonly rateLimit: number; readonly burstLimit: number };
  readonly tlsSecurityPolicy: TlsSecurityPolicy;
  readonly manageApiGatewayCloudWatchRole: boolean;
  readonly keys: {
    readonly accessToken: SigningKeyGenerations;
    readonly refreshToken: SigningKeyGenerations;
    readonly dpopNonce: { readonly active: number };
  };
}

export interface ParseConfigOptions {
  /** Directory that a relative `lambdaAssetPath` is resolved against (default: `process.cwd()`). */
  readonly baseDir?: string;
}

export class ConfigError extends Error {
  public readonly problems: readonly string[];

  public constructor(problems: readonly string[]) {
    super(`Invalid auth service configuration:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

// ---------------------------------------------------------------------------
// Primitive validators. Each records a problem and returns `undefined` on failure.
// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;

class Problems {
  private readonly list: string[] = [];

  public add(where: string, message: string): void {
    this.list.push(`${where}: ${message}`);
  }

  public get all(): readonly string[] {
    return this.list;
  }
}

function isPlainObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkObject(p: Problems, where: string, value: unknown, allowed: readonly string[]): Json | undefined {
  if (!isPlainObject(value)) {
    p.add(where, 'must be an object');
    return undefined;
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      p.add(where === '' ? key : `${where}.${key}`, `unknown property (allowed: ${allowed.join(', ')})`);
    }
  }
  return value;
}

function join(where: string, key: string): string {
  return where === '' ? key : `${where}.${key}`;
}

function checkString(p: Problems, where: string, value: unknown): string | undefined {
  if (typeof value !== 'string') {
    p.add(where, 'must be a string');
    return undefined;
  }
  if (value.length === 0) {
    p.add(where, 'must not be empty');
    return undefined;
  }
  if (value.trim() !== value) {
    p.add(where, 'must not have leading or trailing whitespace');
    return undefined;
  }
  return value;
}

function checkInteger(p: Problems, where: string, value: unknown, min: number, max: number): number | undefined {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    p.add(where, 'must be an integer');
    return undefined;
  }
  if (value < min || value > max) {
    p.add(where, `must be between ${String(min)} and ${String(max)}`);
    return undefined;
  }
  return value;
}

function checkBoolean(p: Problems, where: string, value: unknown): boolean | undefined {
  if (typeof value !== 'boolean') {
    p.add(where, 'must be true or false');
    return undefined;
  }
  return value;
}

/**
 * Validates a non-empty list of unique strings. Values are joined with commas
 * into the service environment (§13), so commas are rejected outright.
 */
function checkList(
  p: Problems,
  where: string,
  value: unknown,
  item: (where: string, value: string) => string | undefined,
): string[] | undefined {
  if (!Array.isArray(value)) {
    p.add(where, 'must be an array of strings');
    return undefined;
  }
  if (value.length === 0) {
    p.add(where, 'must contain at least one entry');
    return undefined;
  }
  const out: string[] = [];
  const seen = new Set<string>();
  let ok = true;
  for (const [i, raw] of (value as unknown[]).entries()) {
    const w = `${where}[${String(i)}]`;
    const s = checkString(p, w, raw);
    if (s === undefined) {
      ok = false;
      continue;
    }
    if (s.includes(',')) {
      ok = false;
      p.add(w, 'must not contain a comma (lists are passed to the service comma-separated)');
      continue;
    }
    if (seen.has(s)) {
      ok = false;
      p.add(w, `duplicate entry "${s}"`);
      continue;
    }
    seen.add(s);
    const checked = item(w, s);
    if (checked === undefined) {
      ok = false;
      continue;
    }
    out.push(checked);
  }
  return ok ? out : undefined;
}

const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** A lowercase, fully qualified DNS name with at least two labels and a non-numeric TLD. */
export function isDnsName(value: string): boolean {
  if (value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((l) => DNS_LABEL.test(l))) return false;
  const tld = labels[labels.length - 1] ?? '';
  return !/^\d+$/.test(tld);
}

function checkDnsName(p: Problems, where: string, value: unknown): string | undefined {
  const s = checkString(p, where, value);
  if (s === undefined) return undefined;
  if (!isDnsName(s)) {
    p.add(
      where,
      `"${s}" is not a valid DNS name (lowercase labels of a-z, 0-9 and '-', at least two labels, no trailing dot, not an IP address)`,
    );
    return undefined;
  }
  return s;
}

function isSameOrSubdomain(host: string, parent: string): boolean {
  return host === parent || host.endsWith(`.${parent}`);
}

/** A bare `https://host[:port]` origin in the exact form browsers serialize it. */
function checkHttpsOrigin(p: Problems, where: string, value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    p.add(where, `"${value}" is not a valid URL origin`);
    return undefined;
  }
  if (url.protocol !== 'https:') {
    p.add(where, `"${value}" must use https`);
    return undefined;
  }
  if (!isDnsName(url.hostname)) {
    p.add(where, `"${value}" must have a DNS host name`);
    return undefined;
  }
  if (url.origin !== value) {
    p.add(
      where,
      `"${value}" must be a bare origin in canonical form ("${url.origin}"): lowercase host, no default port, no path, no trailing slash`,
    );
    return undefined;
  }
  return value;
}

const ANDROID_ORIGIN_PREFIX = 'android:apk-key-hash:';
/** base64url (no padding) of a 32-byte SHA-256 digest, with zero trailing bits (canonical, §2). */
const SHA256_B64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

function checkWebAuthnOrigin(p: Problems, where: string, value: string): string | undefined {
  if (value.startsWith(ANDROID_ORIGIN_PREFIX)) {
    const hash = value.slice(ANDROID_ORIGIN_PREFIX.length);
    if (!SHA256_B64URL.test(hash)) {
      p.add(
        where,
        `"${value}" must be ${ANDROID_ORIGIN_PREFIX}<base64url SHA-256 of the signing certificate, 43 chars, no padding>`,
      );
      return undefined;
    }
    return value;
  }
  return checkHttpsOrigin(p, where, value);
}

/** An RFC 8707 resource indicator: absolute https URI, no query, no fragment, canonical. */
function checkAudience(p: Problems, where: string, value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    p.add(where, `"${value}" is not a valid absolute URI`);
    return undefined;
  }
  if (url.protocol !== 'https:') {
    p.add(where, `"${value}" must use https`);
    return undefined;
  }
  if (url.username !== '' || url.password !== '') {
    p.add(where, `"${value}" must not contain user info`);
    return undefined;
  }
  if (value.includes('#')) {
    p.add(where, `"${value}" must not contain a fragment (RFC 8707 §2)`);
    return undefined;
  }
  if (value.includes('?')) {
    p.add(where, `"${value}" must not contain a query`);
    return undefined;
  }
  if (!isDnsName(url.hostname)) {
    p.add(where, `"${value}" must have a DNS host name`);
    return undefined;
  }
  const canonical = url.pathname === '/' ? [url.origin, url.href] : [url.href];
  if (!canonical.includes(value)) {
    p.add(where, `"${value}" must be in canonical form ("${canonical[0] ?? url.href}")`);
    return undefined;
  }
  return value;
}

/** RFC 6749 client identifiers restricted to URL-safe unreserved characters. */
const CLIENT_ID = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/;

function checkClientId(p: Problems, where: string, value: string): string | undefined {
  if (!CLIENT_ID.test(value)) {
    p.add(where, `"${value}" must be 1-64 characters of A-Z, a-z, 0-9, '.', '_', '~', '-' (starting with a letter or digit)`);
    return undefined;
  }
  return value;
}

const ACCOUNT_ID = /^\d{12}$/;
const REGION = /^[a-z]{2,4}(?:-[a-z]+)+-\d{1,2}$/;
const CERTIFICATE_ARN =
  /^arn:aws[a-z-]*:acm:([a-z0-9-]+):(\d{12}):certificate\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HOSTED_ZONE_ID = /^Z[A-Z0-9]{1,31}$/;
const STACK_NAME = /^[A-Za-z][A-Za-z0-9-]{0,127}$/;

function checkLambdaAsset(p: Problems, where: string, value: unknown, baseDir: string): string | undefined {
  const s = checkString(p, where, value);
  if (s === undefined) return undefined;
  const dir = path.resolve(baseDir, s);
  const dirStat = statSync(dir, { throwIfNoEntry: false });
  if (dirStat?.isDirectory() !== true) {
    p.add(where, `"${dir}" is not a directory (build the service with \`cargo lambda build --release --arm64\`)`);
    return undefined;
  }
  const bootstrap = path.join(dir, 'bootstrap');
  const fileStat = statSync(bootstrap, { throwIfNoEntry: false });
  if (fileStat?.isFile() !== true) {
    p.add(where, `"${bootstrap}" does not exist; the directory must contain the Lambda \`bootstrap\` executable`);
    return undefined;
  }
  if (process.platform !== 'win32' && (fileStat.mode & 0o111) === 0) {
    p.add(where, `"${bootstrap}" is not executable`);
    return undefined;
  }
  return dir;
}

function checkSigningGenerations(
  p: Problems,
  where: string,
  value: unknown,
): SigningKeyGenerations | undefined {
  if (value === undefined) return { active: 1, previous: [] };
  const o = checkObject(p, where, value, ['active', 'previous']);
  if (o === undefined) return undefined;
  const active = checkInteger(p, join(where, 'active'), o.active, 1, MAX_KEY_GENERATION);
  let previous: number[] | undefined = [];
  if (o.previous !== undefined) {
    if (!Array.isArray(o.previous)) {
      p.add(join(where, 'previous'), 'must be an array of integers');
      previous = undefined;
    } else if (o.previous.length > MAX_PREVIOUS_KEY_GENERATIONS) {
      p.add(join(where, 'previous'), `must list at most ${String(MAX_PREVIOUS_KEY_GENERATIONS)} generations`);
      previous = undefined;
    } else {
      const seen = new Set<number>();
      for (const [i, g] of (o.previous as unknown[]).entries()) {
        const w = `${join(where, 'previous')}[${String(i)}]`;
        const n = checkInteger(p, w, g, 1, MAX_KEY_GENERATION);
        if (n === undefined) {
          previous = undefined;
          continue;
        }
        if (n === active) {
          p.add(w, `generation ${String(n)} is the active generation`);
          previous = undefined;
          continue;
        }
        if (seen.has(n)) {
          p.add(w, `duplicate generation ${String(n)}`);
          previous = undefined;
          continue;
        }
        seen.add(n);
        previous?.push(n);
      }
    }
  }
  if (active === undefined || previous === undefined) return undefined;
  return { active, previous };
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

const TOP_LEVEL_KEYS = [
  'stackName',
  'account',
  'region',
  'domainName',
  'certificateArn',
  'hostedZone',
  'rpId',
  'rpName',
  'allowedOrigins',
  'corsOrigins',
  'audiences',
  'clientIds',
  'lambdaAssetPath',
  'reservedConcurrency',
  'waf',
  'apiThrottle',
  'tlsSecurityPolicy',
  'manageApiGatewayCloudWatchRole',
  'keys',
] as const satisfies readonly (keyof AuthServiceConfigInput)[];

/**
 * Validates and normalizes raw configuration (e.g. parsed JSON).
 *
 * @throws ConfigError listing every problem found.
 */
export function parseConfig(input: unknown, options: ParseConfigOptions = {}): AuthServiceConfig {
  const p = new Problems();
  const baseDir = options.baseDir ?? process.cwd();
  const o = checkObject(p, '', input, TOP_LEVEL_KEYS);
  if (o === undefined) {
    throw new ConfigError(p.all.map((s) => s.replace(/^: /, 'config: ')));
  }

  const stackName =
    o.stackName === undefined ? DEFAULTS.stackName : checkString(p, 'stackName', o.stackName);
  if (stackName !== undefined && !STACK_NAME.test(stackName)) {
    p.add('stackName', `"${stackName}" must match ${STACK_NAME.source}`);
  }

  const account = checkString(p, 'account', o.account);
  if (account !== undefined && !ACCOUNT_ID.test(account)) {
    p.add('account', `"${account}" must be a 12-digit AWS account ID`);
  }
  const region = checkString(p, 'region', o.region);
  if (region !== undefined && !REGION.test(region)) {
    p.add('region', `"${region}" is not an AWS region name`);
  }

  const domainName = checkDnsName(p, 'domainName', o.domainName);

  const certificateArn = checkString(p, 'certificateArn', o.certificateArn);
  if (certificateArn !== undefined) {
    const m = CERTIFICATE_ARN.exec(certificateArn);
    if (m === null) {
      p.add('certificateArn', `"${certificateArn}" is not an ACM certificate ARN`);
    } else {
      if (region !== undefined && m[1] !== region) {
        p.add('certificateArn', `certificate region "${m[1] ?? ''}" must equal the stack region "${region}" (regional endpoint)`);
      }
      if (account !== undefined && m[2] !== account) {
        p.add('certificateArn', `certificate account "${m[2] ?? ''}" must equal the stack account "${account}"`);
      }
    }
  }

  let hostedZone: HostedZoneInput | undefined;
  if (o.hostedZone !== undefined) {
    const hz = checkObject(p, 'hostedZone', o.hostedZone, ['id', 'name']);
    if (hz !== undefined) {
      const id = checkString(p, 'hostedZone.id', hz.id);
      if (id !== undefined && !HOSTED_ZONE_ID.test(id)) {
        p.add('hostedZone.id', `"${id}" is not a Route 53 hosted zone ID`);
      }
      const name = checkDnsName(p, 'hostedZone.name', hz.name);
      if (name !== undefined && domainName !== undefined && !isSameOrSubdomain(domainName, name)) {
        p.add('hostedZone.name', `domainName "${domainName}" is not inside the hosted zone "${name}"`);
      }
      if (id !== undefined && name !== undefined) hostedZone = { id, name };
    }
  }

  const rpId = checkDnsName(p, 'rpId', o.rpId);

  const rpName = checkString(p, 'rpName', o.rpName);
  if (rpName !== undefined) {
    if (/\p{Cc}/u.test(rpName)) {
      p.add('rpName', 'must not contain control characters');
    }
    // Authenticators may truncate the RP name beyond 64 bytes (WebAuthn §6.4.1).
    if (Buffer.byteLength(rpName, 'utf8') > 64) {
      p.add('rpName', 'must be at most 64 bytes of UTF-8');
    }
  }

  const allowedOrigins = checkList(
    p,
    'allowedOrigins',
    o.allowedOrigins,
    (w, v) => {
      const origin = checkWebAuthnOrigin(p, w, v);
      if (origin !== undefined && rpId !== undefined && origin.startsWith('https://')) {
        const host = new URL(origin).hostname;
        if (!isSameOrSubdomain(host, rpId)) {
          p.add(w, `host "${host}" is not "${rpId}" or a subdomain of it, so it cannot use RP ID "${rpId}"`);
          return undefined;
        }
      }
      return origin;
    }
  );
  const corsOrigins = checkList(p, 'corsOrigins', o.corsOrigins, (w, v) => checkHttpsOrigin(p, w, v));

  const issuer = domainName === undefined ? undefined : `https://${domainName}`;
  const audiences = checkList(
    p,
    'audiences',
    o.audiences,
    (w, v) => {
      const aud = checkAudience(p, w, v);
      if (aud !== undefined && issuer !== undefined && (aud === issuer || aud === `${issuer}/`)) {
        p.add(w, 'the issuer is always an allowed audience (§6.1); do not list it');
        return undefined;
      }
      return aud;
    }
  );
  const clientIds = checkList(p, 'clientIds', o.clientIds, (w, v) => checkClientId(p, w, v));

  const lambdaAssetPath = checkLambdaAsset(p, 'lambdaAssetPath', o.lambdaAssetPath, baseDir);

  const reservedConcurrency =
    o.reservedConcurrency === undefined
      ? undefined
      : checkInteger(p, 'reservedConcurrency', o.reservedConcurrency, 1, 100_000);

  // WAF
  let waf: AuthServiceConfig['waf'] | undefined = DEFAULTS.waf;
  if (o.waf !== undefined) {
    const w = checkObject(p, 'waf', o.waf, ['rateLimitPerIp', 'sensitiveRateLimitPerIp', 'evaluationWindowSeconds']);
    if (w === undefined) {
      waf = undefined;
    } else {
      const rate =
        w.rateLimitPerIp === undefined
          ? DEFAULTS.waf.rateLimitPerIp
          : checkInteger(p, 'waf.rateLimitPerIp', w.rateLimitPerIp, WAF_RATE_LIMIT_MIN, WAF_RATE_LIMIT_MAX);
      const sensitive =
        w.sensitiveRateLimitPerIp === undefined
          ? DEFAULTS.waf.sensitiveRateLimitPerIp
          : checkInteger(p, 'waf.sensitiveRateLimitPerIp', w.sensitiveRateLimitPerIp, WAF_RATE_LIMIT_MIN, WAF_RATE_LIMIT_MAX);
      let window: WafEvaluationWindowSeconds | undefined = DEFAULTS.waf.evaluationWindowSeconds;
      if (w.evaluationWindowSeconds !== undefined) {
        window = ALLOWED_WAF_EVALUATION_WINDOWS.find((x) => x === w.evaluationWindowSeconds);
        if (window === undefined) {
          p.add('waf.evaluationWindowSeconds', `must be one of ${ALLOWED_WAF_EVALUATION_WINDOWS.join(', ')}`);
        }
      }
      if (rate !== undefined && sensitive !== undefined && sensitive >= rate) {
        p.add('waf.sensitiveRateLimitPerIp', `must be lower than waf.rateLimitPerIp (${String(rate)})`);
      }
      waf =
        rate !== undefined && sensitive !== undefined && window !== undefined
          ? { rateLimitPerIp: rate, sensitiveRateLimitPerIp: sensitive, evaluationWindowSeconds: window }
          : undefined;
    }
  }

  // Stage throttling
  let apiThrottle: AuthServiceConfig['apiThrottle'] | undefined = DEFAULTS.apiThrottle;
  if (o.apiThrottle !== undefined) {
    const t = checkObject(p, 'apiThrottle', o.apiThrottle, ['rateLimit', 'burstLimit']);
    if (t === undefined) {
      apiThrottle = undefined;
    } else {
      const rateLimit =
        t.rateLimit === undefined
          ? DEFAULTS.apiThrottle.rateLimit
          : checkInteger(p, 'apiThrottle.rateLimit', t.rateLimit, 1, 10_000);
      const burstLimit =
        t.burstLimit === undefined
          ? DEFAULTS.apiThrottle.burstLimit
          : checkInteger(p, 'apiThrottle.burstLimit', t.burstLimit, 1, 5_000);
      apiThrottle = rateLimit !== undefined && burstLimit !== undefined ? { rateLimit, burstLimit } : undefined;
    }
  }

  let tlsSecurityPolicy: TlsSecurityPolicy | undefined = DEFAULTS.tlsSecurityPolicy;
  if (o.tlsSecurityPolicy !== undefined) {
    tlsSecurityPolicy = ALLOWED_TLS_SECURITY_POLICIES.find((x) => x === o.tlsSecurityPolicy);
    if (tlsSecurityPolicy === undefined) {
      p.add('tlsSecurityPolicy', `must be one of ${ALLOWED_TLS_SECURITY_POLICIES.join(', ')}`);
    }
  }

  const manageApiGatewayCloudWatchRole =
    o.manageApiGatewayCloudWatchRole === undefined
      ? DEFAULTS.manageApiGatewayCloudWatchRole
      : checkBoolean(p, 'manageApiGatewayCloudWatchRole', o.manageApiGatewayCloudWatchRole);

  // Key generations
  let keys: AuthServiceConfig['keys'] | undefined;
  {
    const k = o.keys === undefined ? {} : checkObject(p, 'keys', o.keys, ['accessToken', 'refreshToken', 'dpopNonce']);
    if (k !== undefined) {
      const accessToken = checkSigningGenerations(p, 'keys.accessToken', k.accessToken);
      const refreshToken = checkSigningGenerations(p, 'keys.refreshToken', k.refreshToken);
      let dpopNonce: { active: number } | undefined = { active: 1 };
      if (k.dpopNonce !== undefined) {
        const d = checkObject(p, 'keys.dpopNonce', k.dpopNonce, ['active']);
        const active = d === undefined ? undefined : checkInteger(p, 'keys.dpopNonce.active', d.active, 1, MAX_KEY_GENERATION);
        dpopNonce = active === undefined ? undefined : { active };
      }
      if (accessToken !== undefined && refreshToken !== undefined && dpopNonce !== undefined) {
        keys = { accessToken, refreshToken, dpopNonce };
      }
    }
  }

  if (p.all.length > 0) {
    throw new ConfigError(p.all);
  }
  // Every field below was validated above; the guard keeps the compiler honest.
  if (
    stackName === undefined ||
    account === undefined ||
    region === undefined ||
    domainName === undefined ||
    issuer === undefined ||
    certificateArn === undefined ||
    rpId === undefined ||
    rpName === undefined ||
    allowedOrigins === undefined ||
    corsOrigins === undefined ||
    audiences === undefined ||
    clientIds === undefined ||
    lambdaAssetPath === undefined ||
    waf === undefined ||
    apiThrottle === undefined ||
    tlsSecurityPolicy === undefined ||
    manageApiGatewayCloudWatchRole === undefined ||
    keys === undefined
  ) {
    throw new ConfigError(['internal error: validation passed but a value is missing']);
  }

  return {
    stackName,
    account,
    region,
    domainName,
    issuer,
    certificateArn,
    hostedZone,
    rpId,
    rpName,
    allowedOrigins,
    corsOrigins,
    audiences,
    clientIds,
    lambdaAssetPath,
    reservedConcurrency,
    waf,
    apiThrottle,
    tlsSecurityPolicy,
    manageApiGatewayCloudWatchRole,
    keys,
  };
}
