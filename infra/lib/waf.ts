import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import type { AuthServiceConfig } from './config.js';

/** Request bodies larger than this are rejected with 413 (protocol §2, §10.8). */
export const MAX_BODY_BYTES = 64 * 1024;

/** Credential IDs are 1–1023 bytes (protocol §3, §8). */
export const MAX_CREDENTIAL_ID_BYTES = 1023;

/** Length of unpadded base64url for `n` bytes. */
export function base64urlLength(n: number): number {
  return Math.ceil((n * 4) / 3);
}

/**
 * The longest legitimate request path is
 * `DELETE /v1/account/passkeys/{base64url credential id}` (protocol §10.7):
 * 21 + 1364 = 1385 bytes. The core rule set blocks paths over 1024 bytes,
 * which would make passkeys with long (but valid) credential IDs undeletable,
 * so we enforce the exact protocol maximum instead.
 */
export const LONGEST_PATH_PREFIX = '/v1/account/passkeys/';
export const MAX_URI_PATH_BYTES = LONGEST_PATH_PREFIX.length + base64urlLength(MAX_CREDENTIAL_ID_BYTES);

/** Path prefixes protected by the stricter per-IP rate limit. */
export const SENSITIVE_PATH_PREFIXES = ['/v1/register/', '/v1/recover/'] as const;

/**
 * Core rule set rules we switch from Block to Count, with the reason. A Count
 * still emits the rule's CloudWatch metric and label.
 */
export const CORE_RULE_SET_COUNT_OVERRIDES = {
  // Blocks bodies over 8 KB. A registration response (RegistrationResponseJSON) with a
  // 1023-byte credential ID, an RSA-4096 credential key and packed self-attestation is
  // ~9-10 KB, and the protocol allows up to 64 KiB. Replaced by `BodySizeLimit`
  // (exactly 64 KiB, 413) and the service's own 64 KiB limit.
  SizeRestrictions_BODY: 'replaced by BodySizeLimit (64 KiB, protocol §2)',
  // Blocks URI paths over 1024 bytes; see MAX_URI_PATH_BYTES. Replaced by `UriPathSizeLimit`.
  SizeRestrictions_URIPATH: 'replaced by UriPathSizeLimit (1385 bytes, protocol §10.7)',
  // Blocks requests without a User-Agent header. The protocol does not require one,
  // CLI / native clients may omit it, and a PII-free service has no business
  // demanding a fingerprinting header. Abuse is handled by the rate limits.
  NoUserAgent_HEADER: 'protocol does not require a User-Agent; service never reads it',
} as const;

export const MANAGED_RULE_GROUPS = [
  'AWSManagedRulesAmazonIpReputationList',
  'AWSManagedRulesCommonRuleSet',
  'AWSManagedRulesKnownBadInputsRuleSet',
] as const;

const errorBody = (error: string, description: string): string =>
  JSON.stringify({ error, error_description: description });

export const WAF_RESPONSE_BODIES = {
  RateLimited: errorBody('rate_limited', 'Too many requests'),
  PayloadTooLarge: errorBody('payload_too_large', 'Request body is larger than 64 KiB'),
  UriTooLong: errorBody('invalid_request', 'Request URI is too long'),
} as const;
type ResponseBodyKey = keyof typeof WAF_RESPONSE_BODIES;

export interface AuthWebAclProps {
  readonly config: AuthServiceConfig;
  /** Prefix for CloudWatch metric names (alphanumeric). */
  readonly metricPrefix: string;
}

/**
 * Regional WAFv2 web ACL for the API Gateway stage.
 *
 * - No WAF logging: WAF log records contain the client IP and all headers.
 * - Sampled requests are disabled for the same reason (AWS keeps a sample of
 *   matching requests, including the client IP and headers, for 3 hours).
 *   Observability comes from the per-rule CloudWatch metrics only.
 */
export class AuthWebAcl extends Construct {
  public readonly webAcl: wafv2.CfnWebACL;

  public constructor(scope: Construct, id: string, props: AuthWebAclProps) {
    super(scope, id);
    const { config, metricPrefix } = props;

    const visibility = (name: string): wafv2.CfnWebACL.VisibilityConfigProperty => ({
      cloudWatchMetricsEnabled: true,
      metricName: `${metricPrefix}-${name}`,
      sampledRequestsEnabled: false,
    });

    const block = (
      key: ResponseBodyKey,
      responseCode: number,
    ): wafv2.CfnWebACL.RuleActionProperty => ({
      block: {
        customResponse: {
          responseCode,
          customResponseBodyKey: key,
          responseHeaders: [{ name: 'Cache-Control', value: 'no-store' }],
        },
      },
    });

    const managed = (
      priority: number,
      name: (typeof MANAGED_RULE_GROUPS)[number],
      overrides: Record<string, string> = {},
    ): wafv2.CfnWebACL.RuleProperty => ({
      name,
      priority,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name,
          ...(Object.keys(overrides).length > 0
            ? {
                ruleActionOverrides: Object.keys(overrides).map((rule) => ({
                  name: rule,
                  actionToUse: { count: {} },
                })),
              }
            : {}),
        },
      },
      visibilityConfig: visibility(name),
    });

    const sensitivePathMatch: wafv2.CfnWebACL.StatementProperty = {
      orStatement: {
        statements: SENSITIVE_PATH_PREFIXES.map((prefix) => ({
          byteMatchStatement: {
            fieldToMatch: { uriPath: {} },
            positionalConstraint: 'STARTS_WITH',
            searchString: prefix,
            // Over-matching is the safe direction for a rate limit, so normalize
            // encodings, duplicate slashes, dot segments and case first.
            textTransformations: [
              { priority: 0, type: 'URL_DECODE' },
              { priority: 1, type: 'NORMALIZE_PATH' },
              { priority: 2, type: 'LOWERCASE' },
            ],
          },
        })),
      },
    };

    this.webAcl = new wafv2.CfnWebACL(this, 'WebAcl', {
      scope: 'REGIONAL',
      description: `Auth service ${config.domainName} - managed rules, per-IP rate limits, protocol size limits`,
      defaultAction: { allow: {} },
      visibilityConfig: visibility('WebAcl'),
      // Inspect bodies up to 64 KiB so the managed body rules see entire requests and
      // BodySizeLimit can enforce the protocol limit exactly. AWS bills the larger
      // inspection only for requests whose bodies exceed the default 16 KB.
      associationConfig: {
        requestBody: { API_GATEWAY: { defaultSizeInspectionLimit: 'KB_64' } },
      },
      customResponseBodies: Object.fromEntries(
        Object.entries(WAF_RESPONSE_BODIES).map(([key, content]) => [
          key,
          { contentType: 'APPLICATION_JSON', content },
        ]),
      ),
      rules: [
        managed(0, 'AWSManagedRulesAmazonIpReputationList'),
        {
          name: 'RateLimitSensitivePaths',
          priority: 1,
          action: block('RateLimited', 429),
          statement: {
            rateBasedStatement: {
              aggregateKeyType: 'IP',
              limit: config.waf.sensitiveRateLimitPerIp,
              evaluationWindowSec: config.waf.evaluationWindowSeconds,
              scopeDownStatement: sensitivePathMatch,
            },
          },
          visibilityConfig: visibility('RateLimitSensitivePaths'),
        },
        {
          name: 'RateLimitGlobal',
          priority: 2,
          action: block('RateLimited', 429),
          statement: {
            rateBasedStatement: {
              aggregateKeyType: 'IP',
              limit: config.waf.rateLimitPerIp,
              evaluationWindowSec: config.waf.evaluationWindowSeconds,
            },
          },
          visibilityConfig: visibility('RateLimitGlobal'),
        },
        {
          name: 'BodySizeLimit',
          priority: 3,
          action: block('PayloadTooLarge', 413),
          statement: {
            sizeConstraintStatement: {
              // With a 64 KiB inspection limit, any body over the limit is "oversize";
              // MATCH treats it as a match, so nothing over 64 KiB gets through.
              fieldToMatch: { body: { oversizeHandling: 'MATCH' } },
              comparisonOperator: 'GT',
              size: MAX_BODY_BYTES,
              textTransformations: [{ priority: 0, type: 'NONE' }],
            },
          },
          visibilityConfig: visibility('BodySizeLimit'),
        },
        {
          name: 'UriPathSizeLimit',
          priority: 4,
          action: block('UriTooLong', 400),
          statement: {
            sizeConstraintStatement: {
              fieldToMatch: { uriPath: {} },
              comparisonOperator: 'GT',
              size: MAX_URI_PATH_BYTES,
              textTransformations: [{ priority: 0, type: 'NONE' }],
            },
          },
          visibilityConfig: visibility('UriPathSizeLimit'),
        },
        managed(5, 'AWSManagedRulesCommonRuleSet', CORE_RULE_SET_COUNT_OVERRIDES),
        managed(6, 'AWSManagedRulesKnownBadInputsRuleSet'),
      ],
    });
  }
}
