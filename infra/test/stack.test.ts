import { Match, type Template } from 'aws-cdk-lib/assertions';
import { beforeAll, describe, expect, it } from 'vitest';
import { ALLOWED_ACCESS_LOG_VARIABLES } from '../lib/access-log.js';
import {
  DYNAMODB_TABLE_ACTIONS,
  KEY_ADMIN_ACTIONS,
  MAC_ACTIONS,
  TABLE_KEY_SERVICE_ACTIONS,
} from '../lib/permissions.js';
import { CORE_RULE_SET_COUNT_OVERRIDES, MAX_BODY_BYTES, MAX_URI_PATH_BYTES } from '../lib/waf.js';
import {
  asArray,
  keyId,
  onlyResource,
  outputs,
  type PolicyStatementJson,
  refTarget,
  resource,
  resourcesOfType,
  synth,
  type Synthesized,
  validConfig,
} from './helpers.js';

/** Environment variables required by docs/protocol.md §13 (AUTH_LISTEN_ADDR is local-only). */
const PROTOCOL_ENV_VARS = [
  'AUTH_ISSUER',
  'AUTH_RP_ID',
  'AUTH_RP_NAME',
  'AUTH_ALLOWED_ORIGINS',
  'AUTH_CORS_ORIGINS',
  'AUTH_AUDIENCES',
  'AUTH_CLIENT_IDS',
  'AUTH_TABLE_NAME',
  'AUTH_ACCESS_TOKEN_KEY_ID',
  'AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS',
  'AUTH_REFRESH_TOKEN_KEY_ID',
  'AUTH_REFRESH_TOKEN_PREVIOUS_KEY_IDS',
  'AUTH_DPOP_NONCE_KEY_ID',
];

const CRYPTO_ACTIONS = [
  'kms:Sign',
  'kms:Verify',
  'kms:GenerateMac',
  'kms:VerifyMac',
  'kms:Encrypt',
  'kms:Decrypt',
  'kms:GenerateDataKey',
  'kms:GenerateDataKeyWithoutPlaintext',
  'kms:ReEncryptFrom',
  'kms:ReEncryptTo',
  'kms:CreateGrant',
];

let s: Synthesized;
let template: Template;
let ids: { table: string; tableKey: string; at: string; rt: string; nonce: string; role: string; fn: string };

beforeAll(() => {
  s = synth();
  template = s.template;
  ids = {
    table: onlyResource(template, 'AWS::DynamoDB::Table').id,
    tableKey: keyId(template, 'TableKey'),
    at: keyId(template, 'AccessTokenSigningKeyG1'),
    rt: keyId(template, 'RefreshTokenSigningKeyG1'),
    nonce: keyId(template, 'DpopNonceKeyG1'),
    role: Object.keys(template.findResources('AWS::IAM::Role', { Properties: { Description: Match.stringLikeRegexp('Auth service Lambda') } }))[0] ?? '',
    fn: onlyResource(template, 'AWS::Lambda::Function').id,
  };
});

function keyPolicyOf(t: Template, id: string): PolicyStatementJson[] {
  return (resource(t, id).Properties.KeyPolicy as { Statement: PolicyStatementJson[] }).Statement;
}

function keyPolicy(id: string): PolicyStatementJson[] {
  return keyPolicyOf(template, id);
}

function runtimeStatements(): PolicyStatementJson[] {
  const policies = Object.values(resourcesOfType(template, 'AWS::IAM::Policy')).filter((p) =>
    asArray(p.Properties.Roles as unknown[]).some((r) => refTarget(r) === ids.role),
  );
  expect(policies).toHaveLength(1);
  return (policies[0]?.Properties.PolicyDocument as { Statement: PolicyStatementJson[] }).Statement;
}

describe('DynamoDB table (protocol §12)', () => {
  it('has the pk/sk string key schema, TTL, PITR, deletion protection and on-demand billing', () => {
    template.hasResource('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
      Properties: {
        KeySchema: [
          { AttributeName: 'pk', KeyType: 'HASH' },
          { AttributeName: 'sk', KeyType: 'RANGE' },
        ],
        AttributeDefinitions: [
          { AttributeName: 'pk', AttributeType: 'S' },
          { AttributeName: 'sk', AttributeType: 'S' },
        ],
        BillingMode: 'PAY_PER_REQUEST',
        TimeToLiveSpecification: { AttributeName: 'ttl', Enabled: true },
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
        DeletionProtectionEnabled: true,
      },
    });
    const { props } = onlyResource(template, 'AWS::DynamoDB::Table');
    expect(props.GlobalSecondaryIndexes).toBeUndefined();
    expect(props.StreamSpecification).toBeUndefined();
  });

  it('is encrypted with the dedicated customer-managed key', () => {
    const { props } = onlyResource(template, 'AWS::DynamoDB::Table');
    const sse = props.SSESpecification as Record<string, unknown>;
    expect(sse.SSEEnabled).toBe(true);
    expect(sse.SSEType).toBe('KMS');
    expect(refTarget(sse.KMSMasterKeyId)).toBe(ids.tableKey);
  });
});

describe('KMS keys (protocol §5)', () => {
  it('creates exactly four retained keys with the right specs and usages', () => {
    const keys = template.findResources('AWS::KMS::Key');
    expect(Object.keys(keys)).toHaveLength(4);
    for (const key of Object.values(keys)) {
      expect(key.DeletionPolicy).toBe('Retain');
      expect(key.UpdateReplacePolicy).toBe('Retain');
    }
    const props = (id: string) => (keys[id] as { Properties: Record<string, unknown> }).Properties;
    expect(props(ids.tableKey)).toMatchObject({
      KeySpec: 'SYMMETRIC_DEFAULT',
      KeyUsage: 'ENCRYPT_DECRYPT',
      EnableKeyRotation: true,
    });
    for (const id of [ids.at, ids.rt]) {
      expect(props(id)).toMatchObject({ KeySpec: 'ECC_NIST_P256', KeyUsage: 'SIGN_VERIFY' });
      expect(props(id).EnableKeyRotation).toBeUndefined();
    }
    expect(props(ids.nonce)).toMatchObject({ KeySpec: 'HMAC_256', KeyUsage: 'GENERATE_VERIFY_MAC' });
    expect(ids.at).not.toBe(ids.rt);
  });

  it('has an alias for each key', () => {
    const aliases = Object.values(resourcesOfType(template, 'AWS::KMS::Alias')).map((a) => ({
      name: a.Properties.AliasName,
      target: refTarget(a.Properties.TargetKeyId),
    }));
    expect(aliases).toEqual(
      expect.arrayContaining([
        { name: 'alias/TestAuthStack/table', target: ids.tableKey },
        { name: 'alias/TestAuthStack/access-token', target: ids.at },
        { name: 'alias/TestAuthStack/refresh-token', target: ids.rt },
        { name: 'alias/TestAuthStack/dpop-nonce', target: ids.nonce },
      ]),
    );
    expect(aliases).toHaveLength(4);
  });

  it('never grants cryptographic use to the account principal', () => {
    for (const id of [ids.tableKey, ids.at, ids.rt, ids.nonce]) {
      for (const st of keyPolicy(id)) {
        const isAccount = JSON.stringify(st.Principal).includes(':root');
        if (!isAccount) continue;
        const actions = asArray(st.Action);
        const crypto = actions.filter((a) => CRYPTO_ACTIONS.includes(a));
        if (crypto.length > 0) {
          // Only the table key delegates to the account, and only through DynamoDB.
          expect(id).toBe(ids.tableKey);
          expect(st.Condition?.StringEquals?.['kms:ViaService']).toBe('dynamodb.eu-west-1.amazonaws.com');
          expect(st.Condition?.StringEquals?.['kms:CallerAccount']).toBe('111122223333');
        }
        expect(actions.some((a) => a.includes('*'))).toBe(false);
      }
      const admin = keyPolicy(id).find((st) => st.Sid === 'KeyAdministrationWithoutCryptographicUse');
      expect(asArray(admin?.Action)).toEqual([...KEY_ADMIN_ACTIONS]);
    }
  });

  it('only the service role can sign, with ES256 over a digest', () => {
    for (const id of [ids.at, ids.rt]) {
      const sign = keyPolicy(id).filter((st) => asArray(st.Action).includes('kms:Sign'));
      expect(sign).toHaveLength(1);
      expect(refTarget((sign[0]?.Principal as { AWS: unknown }).AWS)).toBe(ids.role);
      expect(sign[0]?.Condition).toEqual({
        StringEquals: { 'kms:SigningAlgorithm': 'ECDSA_SHA_256', 'kms:MessageType': 'DIGEST' },
      });
    }
  });

  it('only the service role can compute nonce MACs, with HMAC-SHA-256', () => {
    const mac = keyPolicy(ids.nonce).filter((st) => asArray(st.Action).some((a) => MAC_ACTIONS.includes(a as never)));
    expect(mac).toHaveLength(1);
    expect(asArray(mac[0]?.Action).sort()).toEqual([...MAC_ACTIONS].sort());
    expect(refTarget((mac[0]?.Principal as { AWS: unknown }).AWS)).toBe(ids.role);
    expect(mac[0]?.Condition).toEqual({ StringEquals: { 'kms:MacAlgorithm': 'HMAC_SHA_256' } });
  });

  it('lets DynamoDB create grants only for AWS resources', () => {
    const grant = keyPolicy(ids.tableKey).filter((st) => asArray(st.Action).includes('kms:CreateGrant'));
    expect(grant).toHaveLength(1);
    expect(grant[0]?.Condition?.Bool).toEqual({ 'kms:GrantIsForAWSResource': 'true' });
  });
});

describe('IAM (least privilege)', () => {
  it('the service role has no managed policies and no inline policies of its own', () => {
    const role = resource(template, ids.role).Properties;
    expect(role.ManagedPolicyArns).toBeUndefined();
    expect(role.Policies).toBeUndefined();
    expect(role.AssumeRolePolicyDocument).toEqual({
      Version: '2012-10-17',
      Statement: [{ Action: 'sts:AssumeRole', Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' } }],
    });
  });

  it('the runtime policy grants exactly the intended actions on exactly the intended resources', () => {
    const statements = runtimeStatements();
    const grants = statements.flatMap((st) => {
      expect(st.Effect).toBe('Allow');
      return asArray(st.Action).flatMap((action) =>
        asArray(st.Resource).map((r) => ({ action, resource: refTarget(r), condition: st.Condition ?? null })),
      );
    });
    const sign = { StringEquals: { 'kms:SigningAlgorithm': 'ECDSA_SHA_256', 'kms:MessageType': 'DIGEST' } };
    const logGroup = Object.keys(template.findResources('AWS::Logs::LogGroup')).find((k) => k.startsWith('ServiceLogGroup'));
    const expected = [
      ...DYNAMODB_TABLE_ACTIONS.map((action) => ({ action, resource: ids.table, condition: null })),
      ...TABLE_KEY_SERVICE_ACTIONS.map((action) => ({
        action,
        resource: ids.tableKey,
        condition: { StringEquals: { 'kms:ViaService': 'dynamodb.eu-west-1.amazonaws.com' } },
      })),
      { action: 'kms:Sign', resource: ids.at, condition: sign },
      { action: 'kms:Sign', resource: ids.rt, condition: sign },
      { action: 'kms:GetPublicKey', resource: ids.at, condition: null },
      { action: 'kms:GetPublicKey', resource: ids.rt, condition: null },
      ...MAC_ACTIONS.map((action) => ({
        action,
        resource: ids.nonce,
        condition: { StringEquals: { 'kms:MacAlgorithm': 'HMAC_SHA_256' } },
      })),
      { action: 'logs:CreateLogStream', resource: logGroup, condition: null },
      { action: 'logs:PutLogEvents', resource: logGroup, condition: null },
    ];
    const key = (g: { action: string; resource: string | undefined }) => `${g.action} ${String(g.resource)}`;
    expect(grants.map(key).sort()).toEqual(expected.map(key).sort());
    for (const g of grants) {
      expect(g.condition).toEqual(expected.find((e) => key(e) === key(g))?.condition);
    }
    expect(DYNAMODB_TABLE_ACTIONS).not.toContain('dynamodb:Scan');
  });

  it('no IAM policy anywhere in the stack uses a wildcard action or a "*" resource', () => {
    const docs: PolicyStatementJson[] = [];
    for (const p of Object.values(resourcesOfType(template, 'AWS::IAM::Policy'))) {
      docs.push(...(p.Properties.PolicyDocument as { Statement: PolicyStatementJson[] }).Statement);
    }
    for (const r of Object.values(resourcesOfType(template, 'AWS::IAM::Role'))) {
      for (const p of asArray(r.Properties.Policies as { PolicyDocument: { Statement: PolicyStatementJson[] } }[])) {
        docs.push(...p.PolicyDocument.Statement);
      }
    }
    expect(docs.length).toBeGreaterThan(0);
    for (const st of docs) {
      for (const a of asArray(st.Action)) expect(a).not.toContain('*');
      for (const r of asArray(st.Resource)) expect(r).not.toBe('*');
    }
  });

  it('API Gateway may invoke the function only from this API stage (no test-invoke)', () => {
    const perms = Object.values(resourcesOfType(template, 'AWS::Lambda::Permission'));
    expect(perms).toHaveLength(2);
    for (const p of perms) {
      expect(p.Properties.Principal).toBe('apigateway.amazonaws.com');
      const arn = JSON.stringify(p.Properties.SourceArn);
      expect(arn).toContain('execute-api');
      expect(arn).not.toContain('test-invoke-stage');
    }
  });
});

describe('Lambda', () => {
  it('runs the cargo-lambda bootstrap on arm64 / provided.al2023', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'provided.al2023',
      Architectures: ['arm64'],
      Handler: 'bootstrap',
      MemorySize: 512,
      Timeout: 10,
    });
  });

  it('sets exactly the protocol §13 environment plus the two runtime settings', () => {
    const { props } = onlyResource(template, 'AWS::Lambda::Function');
    const env = (props.Environment as { Variables: Record<string, unknown> }).Variables;
    expect(Object.keys(env).sort()).toEqual(
      [...PROTOCOL_ENV_VARS, 'AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH', 'RUST_LOG'].sort(),
    );
    expect(env).toMatchObject({
      AUTH_ISSUER: 'https://auth.example.com',
      AUTH_RP_ID: 'example.com',
      AUTH_RP_NAME: 'Example',
      AUTH_ALLOWED_ORIGINS: 'https://app.example.com,android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      AUTH_CORS_ORIGINS: 'https://app.example.com',
      AUTH_AUDIENCES: 'https://api.example.com',
      AUTH_CLIENT_IDS: 'web,ios,android,cli',
      AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS: '',
      AUTH_REFRESH_TOKEN_PREVIOUS_KEY_IDS: '',
      AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH: 'true',
      RUST_LOG: 'info',
    });
    expect(refTarget(env.AUTH_TABLE_NAME)).toBe(ids.table);
    expect(refTarget(env.AUTH_ACCESS_TOKEN_KEY_ID)).toBe(ids.at);
    expect(refTarget(env.AUTH_REFRESH_TOKEN_KEY_ID)).toBe(ids.rt);
    expect(refTarget(env.AUTH_DPOP_NONCE_KEY_ID)).toBe(ids.nonce);
  });

  it('logs to an explicit log group with 30-day retention and has no tracing', () => {
    const { props } = onlyResource(template, 'AWS::Lambda::Function');
    const logGroupId = refTarget((props.LoggingConfig as { LogGroup: unknown }).LogGroup);
    expect(logGroupId).toMatch(/^ServiceLogGroup/);
    template.hasResource('AWS::Logs::LogGroup', { Properties: { RetentionInDays: 30 }, DeletionPolicy: 'Retain' });
    for (const lg of Object.values(resourcesOfType(template, 'AWS::Logs::LogGroup'))) {
      expect(lg.Properties.RetentionInDays).toBe(30);
    }
    expect(props.TracingConfig).toBeUndefined();
  });

  it('depends on its runtime policy', () => {
    const fn = resource(template, ids.fn);
    expect(fn.DependsOn?.some((d) => d.startsWith('ServiceRuntimePolicy'))).toBe(true);
  });

  it('sets reserved concurrency only when configured', () => {
    expect(onlyResource(template, 'AWS::Lambda::Function').props.ReservedConcurrentExecutions).toBeUndefined();
    const withRc = synth(validConfig({ reservedConcurrency: 25 })).template;
    withRc.hasResourceProperties('AWS::Lambda::Function', { ReservedConcurrentExecutions: 25 });
  });
});

describe('API Gateway', () => {
  it('is a regional, dual-stack REST API with the execute-api endpoint disabled', () => {
    template.hasResourceProperties('AWS::ApiGateway::RestApi', {
      DisableExecuteApiEndpoint: true,
      EndpointConfiguration: { Types: ['REGIONAL'], IpAddressType: 'dualstack' },
      SecurityPolicy: 'SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09',
      EndpointAccessMode: 'STRICT',
    });
    expect(Object.keys(outputs(template)).some((o) => o.startsWith('ApiEndpoint'))).toBe(false);
  });

  it('proxies / and /{proxy+} (ANY) to the function', () => {
    const methods = Object.values(resourcesOfType(template, 'AWS::ApiGateway::Method'));
    expect(methods).toHaveLength(2);
    for (const m of methods) {
      expect(m.Properties.HttpMethod).toBe('ANY');
      expect(m.Properties.AuthorizationType).toBe('NONE');
      expect((m.Properties.Integration as { Type: string }).Type).toBe('AWS_PROXY');
    }
    template.hasResourceProperties('AWS::ApiGateway::Resource', { PathPart: '{proxy+}' });
  });

  it('stage prod: throttled, no execution logging, no data trace, no X-Ray', () => {
    template.hasResourceProperties('AWS::ApiGateway::Stage', {
      StageName: 'prod',
      TracingEnabled: false,
      MethodSettings: [
        {
          HttpMethod: '*',
          ResourcePath: '/*',
          LoggingLevel: 'OFF',
          DataTraceEnabled: false,
          MetricsEnabled: false,
          ThrottlingRateLimit: 100,
          ThrottlingBurstLimit: 200,
        },
      ],
    });
  });

  it('access log format excludes every identity field and only uses allowlisted variables', () => {
    const { props } = onlyResource(template, 'AWS::ApiGateway::Stage');
    const format = (props.AccessLogSetting as { Format: string }).Format;
    expect(format).not.toMatch(/sourceIp/i);
    expect(format).not.toMatch(/userAgent/i);
    expect(format).not.toMatch(/identity/i);
    expect(format).not.toMatch(/authorizer|caller|apiKey|accountId|\$context\.path/i);
    const vars = format.match(/\$context\.[A-Za-z0-9_.]+/g) ?? [];
    for (const v of vars) expect(ALLOWED_ACCESS_LOG_VARIABLES).toContain(v);
    const parsed = JSON.parse(format) as Record<string, string>;
    expect(parsed).toMatchObject({
      requestId: '$context.requestId',
      requestTime: '$context.requestTime',
      httpMethod: '$context.httpMethod',
      resourcePath: '$context.resourcePath',
      status: '$context.status',
      responseLength: '$context.responseLength',
      integrationLatency: '$context.integrationLatency',
    });
    const dest = JSON.stringify(props.AccessLogSetting);
    expect(dest).toMatch(/ApiAccessLogGroup/);
  });

  it('the stage waits for the API Gateway account CloudWatch role when it is managed', () => {
    const { id } = onlyResource(template, 'AWS::ApiGateway::Account');
    const stage = Object.values(template.findResources('AWS::ApiGateway::Stage'))[0] as { DependsOn?: string[] };
    expect(stage.DependsOn).toContain(id);
    const unmanaged = synth(validConfig({ manageApiGatewayCloudWatchRole: false })).template;
    unmanaged.resourceCountIs('AWS::ApiGateway::Account', 0);
  });

  it('gateway-generated errors use the OAuth error object and no-store', () => {
    const responses = Object.values(resourcesOfType(template, 'AWS::ApiGateway::GatewayResponse'));
    const byType = new Map(responses.map((r) => [String(r.Properties.ResponseType), r.Properties]));
    expect([...byType.keys()].sort()).toEqual(
      ['DEFAULT_4XX', 'DEFAULT_5XX', 'REQUEST_TOO_LARGE', 'THROTTLED', 'WAF_FILTERED'].sort(),
    );
    expect(byType.get('THROTTLED')).toMatchObject({ StatusCode: '429' });
    expect(byType.get('REQUEST_TOO_LARGE')).toMatchObject({ StatusCode: '413' });
    for (const r of responses) {
      expect(r.Properties.ResponseParameters).toMatchObject({ 'gatewayresponse.header.Cache-Control': "'no-store'" });
      const body = JSON.parse((r.Properties.ResponseTemplates as Record<string, string>)['application/json'] ?? '') as {
        error: string;
      };
      expect(typeof body.error).toBe('string');
    }
  });

  it('serves the issuer from the custom domain root (no stage prefix) with the strongest TLS policy', () => {
    template.hasResourceProperties('AWS::ApiGateway::DomainName', {
      DomainName: 'auth.example.com',
      RegionalCertificateArn: validConfig().certificateArn,
      EndpointConfiguration: { Types: ['REGIONAL'], IpAddressType: 'dualstack' },
      SecurityPolicy: 'SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09',
      EndpointAccessMode: 'STRICT',
    });
    const { props } = onlyResource(template, 'AWS::ApiGateway::BasePathMapping');
    expect(props.BasePath).toBeUndefined();
    expect(refTarget(props.Stage)).toMatch(/^ApiDeploymentStageprod/);
  });

  it('honours the configured TLS policy', () => {
    const t = synth(validConfig({ tlsSecurityPolicy: 'SecurityPolicy_TLS13_1_3_2025_09' })).template;
    t.hasResourceProperties('AWS::ApiGateway::DomainName', { SecurityPolicy: 'SecurityPolicy_TLS13_1_3_2025_09' });
    t.hasResourceProperties('AWS::ApiGateway::RestApi', { SecurityPolicy: 'SecurityPolicy_TLS13_1_3_2025_09' });
  });
});

describe('DNS', () => {
  it('creates A and AAAA alias records when a hosted zone is configured', () => {
    for (const type of ['A', 'AAAA']) {
      template.hasResourceProperties('AWS::Route53::RecordSet', {
        Name: 'auth.example.com.',
        Type: type,
        HostedZoneId: 'Z0123456789ABCDEFGHIJ',
        AliasTarget: Match.objectLike({ DNSName: Match.anyValue() }),
      });
    }
    template.resourceCountIs('AWS::Route53::RecordSet', 2);
  });

  it('creates no records without a hosted zone', () => {
    const config = validConfig();
    const { hostedZone: _omit, ...rest } = config as unknown as Record<string, unknown>;
    synth(rest as never).template.resourceCountIs('AWS::Route53::RecordSet', 0);
  });
});

describe('WAF', () => {
  interface Rule {
    Name: string;
    Action?: unknown;
    Statement: Record<string, unknown>;
    VisibilityConfig: Record<string, unknown>;
  }
  interface Acl {
    Scope: string;
    AssociationConfig: unknown;
    VisibilityConfig: Record<string, unknown>;
    Rules: Rule[];
  }
  let acl: Acl;
  let aclId: string;

  beforeAll(() => {
    const found = onlyResource(template, 'AWS::WAFv2::WebACL');
    acl = found.props as unknown as Acl;
    aclId = found.id;
  });

  it('is regional and associated with the prod stage', () => {
    expect(acl.Scope).toBe('REGIONAL');
    const { props } = onlyResource(template, 'AWS::WAFv2::WebACLAssociation');
    expect(refTarget(props.WebACLArn)).toBe(aclId);
    const arn = JSON.stringify(props.ResourceArn);
    expect(arn).toContain('/restapis/');
    expect(arn).toContain('/stages/');
    expect(arn).toMatch(/ApiDeploymentStageprod/);
  });

  it('contains the three managed rule groups', () => {
    const groups = acl.Rules.map((r) => (r.Statement.ManagedRuleGroupStatement as { Name?: string } | undefined)?.Name).filter(
      Boolean,
    );
    expect(groups.sort()).toEqual(
      ['AWSManagedRulesAmazonIpReputationList', 'AWSManagedRulesCommonRuleSet', 'AWSManagedRulesKnownBadInputsRuleSet'].sort(),
    );
  });

  it('switches only the documented core rules to Count', () => {
    const crs = acl.Rules.find((r) => r.Name === 'AWSManagedRulesCommonRuleSet');
    const overrides = (crs?.Statement.ManagedRuleGroupStatement as { RuleActionOverrides: { Name: string; ActionToUse: unknown }[] })
      .RuleActionOverrides;
    expect(overrides.map((o) => o.Name).sort()).toEqual(Object.keys(CORE_RULE_SET_COUNT_OVERRIDES).sort());
    for (const o of overrides) expect(o.ActionToUse).toEqual({ Count: {} });
  });

  it('has a global per-IP rate limit and a stricter one for register/recover', () => {
    const rate = (name: string) =>
      acl.Rules.find((r) => r.Name === name)?.Statement.RateBasedStatement as Record<string, unknown>;
    expect(rate('RateLimitGlobal')).toEqual({ AggregateKeyType: 'IP', Limit: 1000, EvaluationWindowSec: 300 });
    const sensitive = rate('RateLimitSensitivePaths');
    expect(sensitive).toMatchObject({ AggregateKeyType: 'IP', Limit: 60, EvaluationWindowSec: 300 });
    const scope = JSON.stringify(sensitive.ScopeDownStatement);
    expect(scope).toContain('"SearchString":"/v1/register/"');
    expect(scope).toContain('"SearchString":"/v1/recover/"');
    expect(scope).toContain('STARTS_WITH');
    for (const name of ['RateLimitGlobal', 'RateLimitSensitivePaths']) {
      expect(acl.Rules.find((r) => r.Name === name)?.Action).toMatchObject({
        Block: { CustomResponse: { ResponseCode: 429, CustomResponseBodyKey: 'RateLimited' } },
      });
    }
  });

  it('enforces the protocol body and path limits at the edge', () => {
    expect(acl.AssociationConfig).toEqual({ RequestBody: { API_GATEWAY: { DefaultSizeInspectionLimit: 'KB_64' } } });
    const body = acl.Rules.find((r) => r.Name === 'BodySizeLimit');
    expect(body?.Statement.SizeConstraintStatement).toMatchObject({
      FieldToMatch: { Body: { OversizeHandling: 'MATCH' } },
      ComparisonOperator: 'GT',
      Size: MAX_BODY_BYTES,
    });
    expect(MAX_BODY_BYTES).toBe(65536);
    expect(body?.Action).toMatchObject({ Block: { CustomResponse: { ResponseCode: 413 } } });
    const uri = acl.Rules.find((r) => r.Name === 'UriPathSizeLimit');
    expect(uri?.Statement.SizeConstraintStatement).toMatchObject({ ComparisonOperator: 'GT', Size: MAX_URI_PATH_BYTES });
    expect(MAX_URI_PATH_BYTES).toBe('/v1/account/passkeys/'.length + 1364);
  });

  it('records no client IPs: sampled requests off everywhere, no WAF logging', () => {
    expect(acl.VisibilityConfig.SampledRequestsEnabled).toBe(false);
    for (const r of acl.Rules) {
      expect(r.VisibilityConfig.SampledRequestsEnabled).toBe(false);
      expect(r.VisibilityConfig.CloudWatchMetricsEnabled).toBe(true);
    }
    template.resourceCountIs('AWS::WAFv2::LoggingConfiguration', 0);
  });

  it('uses the configured limits', () => {
    const t = synth(validConfig({ waf: { rateLimitPerIp: 5000, sensitiveRateLimitPerIp: 100, evaluationWindowSeconds: 60 } })).template;
    const rules = (onlyResource(t, 'AWS::WAFv2::WebACL').props as { Rules: Rule[] }).Rules;
    expect(rules.find((r) => r.Name === 'RateLimitGlobal')?.Statement.RateBasedStatement).toMatchObject({
      Limit: 5000,
      EvaluationWindowSec: 60,
    });
    expect(rules.find((r) => r.Name === 'RateLimitSensitivePaths')?.Statement.RateBasedStatement).toMatchObject({ Limit: 100 });
  });
});

describe('Key rotation (generations)', () => {
  let t: Template;
  beforeAll(() => {
    t = synth(
      validConfig({
        keys: { accessToken: { active: 2, previous: [1] }, refreshToken: { active: 3, previous: [2] }, dpopNonce: { active: 2 } },
      }),
    ).template;
  });

  it('keeps previous keys, publishes them via *_PREVIOUS_KEY_IDS, and signs only with the active key', () => {
    const at2 = keyId(t, 'AccessTokenSigningKeyG2');
    const at1 = keyId(t, 'AccessTokenSigningKeyG1');
    const rt3 = keyId(t, 'RefreshTokenSigningKeyG3');
    const rt2 = keyId(t, 'RefreshTokenSigningKeyG2');
    keyId(t, 'DpopNonceKeyG2');
    t.resourceCountIs('AWS::KMS::Key', 6);

    const env = (onlyResource(t, 'AWS::Lambda::Function').props.Environment as { Variables: Record<string, unknown> }).Variables;
    expect(refTarget(env.AUTH_ACCESS_TOKEN_KEY_ID)).toBe(at2);
    expect(refTarget(env.AUTH_REFRESH_TOKEN_KEY_ID)).toBe(rt3);
    expect(JSON.stringify(env.AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS)).toContain(at1);
    expect(JSON.stringify(env.AUTH_REFRESH_TOKEN_PREVIOUS_KEY_IDS)).toContain(rt2);

    const policy = (id: string) => keyPolicyOf(t, id);
    for (const prev of [at1, rt2]) {
      expect(policy(prev).some((st) => asArray(st.Action).includes('kms:Sign'))).toBe(false);
      expect(policy(prev).some((st) => st.Sid === 'ServiceReadsPublicKey')).toBe(true);
    }

    const stmts = Object.values(resourcesOfType(t, 'AWS::IAM::Policy')).flatMap(
      (p) => (p.Properties.PolicyDocument as { Statement: PolicyStatementJson[] }).Statement,
    );
    const signTargets = stmts
      .filter((st) => asArray(st.Action).includes('kms:Sign'))
      .flatMap((st) => asArray(st.Resource).map(refTarget));
    expect(signTargets.sort()).toEqual([at2, rt3].sort());
    const pubTargets = stmts
      .filter((st) => asArray(st.Action).includes('kms:GetPublicKey'))
      .flatMap((st) => asArray(st.Resource).map(refTarget));
    expect(pubTargets.sort()).toEqual([at1, at2, rt2, rt3].sort());
  });
});

describe('Outputs and stack settings', () => {
  it('exports the issuer, table and key ARNs', () => {
    const out = outputs(template);
    expect(out.IssuerUrl?.Value).toBe('https://auth.example.com');
    expect(refTarget(out.TableName?.Value)).toBe(ids.table);
    expect(refTarget(out.TableKeyArn?.Value)).toBe(ids.tableKey);
    expect(refTarget(out.AccessTokenSigningKeyArn?.Value)).toBe(ids.at);
    expect(refTarget(out.RefreshTokenSigningKeyArn?.Value)).toBe(ids.rt);
    expect(refTarget(out.DpopNonceKeyArn?.Value)).toBe(ids.nonce);
  });

  it('is pinned to the configured environment, termination-protected and sends no CDK metadata', () => {
    expect(s.stack.account).toBe('111122223333');
    expect(s.stack.region).toBe('eu-west-1');
    expect(s.stack.terminationProtection).toBe(true);
    template.resourceCountIs('AWS::CDK::Metadata', 0);
  });
});
