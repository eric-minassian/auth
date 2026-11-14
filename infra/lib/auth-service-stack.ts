import { CfnOutput, Duration, Fn, RemovalPolicy, Stack, type StackProps } from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import type * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53Targets from 'aws-cdk-lib/aws-route53-targets';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import type { Construct } from 'constructs';
import { accessLogFormat } from './access-log.js';
import { parseConfig, type AuthServiceConfig, type AuthServiceConfigInput, type TlsSecurityPolicy } from './config.js';
import { ServiceKeys } from './keys.js';
import { applyNagSuppressions } from './nag-suppressions.js';
import {
  DYNAMODB_TABLE_ACTIONS,
  GET_PUBLIC_KEY_ACTIONS,
  LOG_WRITE_ACTIONS,
  MAC_ACTIONS,
  MAC_CONDITIONS,
  SIGN_ACTIONS,
  SIGN_CONDITIONS,
  TABLE_KEY_SERVICE_ACTIONS,
} from './permissions.js';
import { AuthWebAcl } from './waf.js';

export const STAGE_NAME = 'prod';
export const LAMBDA_MEMORY_MB = 512;
export const LAMBDA_TIMEOUT_SECONDS = 10;
export const LOG_RETENTION = logs.RetentionDays.ONE_MONTH;

/** Config value → CDK enum (a compile error here means CDK dropped a policy we allow). */
const TLS_POLICIES: Record<TlsSecurityPolicy, apigw.SecurityPolicy> = {
  SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09: apigw.SecurityPolicy.TLS13_1_2_PFS_PQ_2025_09,
  SecurityPolicy_TLS13_1_3_2025_09: apigw.SecurityPolicy.TLS13_1_3_2025_09,
  SecurityPolicy_TLS13_1_3_FIPS_2025_09: apigw.SecurityPolicy.TLS13_1_3_FIPS_2025_09,
};

export interface AuthServiceStackProps extends Omit<StackProps, 'env'> {
  /** Raw configuration; validated by {@link parseConfig} before anything is created. */
  readonly config: AuthServiceConfigInput;
  /** Directory a relative `config.lambdaAssetPath` is resolved against (default: cwd). */
  readonly configBaseDir?: string;
}

/**
 * The auth service: one Lambda (Rust, custom runtime) behind a regional REST
 * API, a WAF web ACL and a custom domain; one DynamoDB table; four KMS keys.
 */
export class AuthServiceStack extends Stack {
  public readonly config: AuthServiceConfig;
  public readonly table: dynamodb.Table;
  public readonly keys: ServiceKeys;
  public readonly serviceRole: iam.Role;
  public readonly serviceFunction: lambda.Function;
  public readonly api: apigw.RestApi;
  public readonly domain: apigw.DomainName;
  public readonly webAcl: wafv2.CfnWebACL;

  public constructor(scope: Construct, id: string, props: AuthServiceStackProps) {
    const { config: rawConfig, configBaseDir, ...stackProps } = props;
    const config = parseConfig(rawConfig, configBaseDir === undefined ? {} : { baseDir: configBaseDir });
    super(scope, id, {
      description: `Passkey-only, PII-free authentication service (${config.issuer})`,
      terminationProtection: true,
      analyticsReporting: false,
      ...stackProps,
      env: { account: config.account, region: config.region },
    });
    this.config = config;

    // -----------------------------------------------------------------------
    // Service role (created first: the KMS key policies name it directly).
    // -----------------------------------------------------------------------
    this.serviceRole = new iam.Role(this, 'ServiceRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Auth service Lambda execution role (least privilege; no managed policies)',
    });

    // -----------------------------------------------------------------------
    // KMS keys (protocol §5) and the DynamoDB table (protocol §12).
    // -----------------------------------------------------------------------
    this.keys = new ServiceKeys(this, 'Keys', {
      config,
      serviceRole: this.serviceRole,
      aliasPrefix: this.stackName,
    });

    this.table = new dynamodb.Table(this, 'Table', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.keys.tableKey,
    });

    // -----------------------------------------------------------------------
    // Lambda.
    // -----------------------------------------------------------------------
    const functionLogGroup = new logs.LogGroup(this, 'ServiceLogGroup', {
      retention: LOG_RETENTION,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const runtimePolicy = new iam.Policy(this, 'ServiceRuntimePolicy', {
      roles: [this.serviceRole],
      statements: this.serviceStatements(functionLogGroup),
    });

    const joinArns = (keys: readonly kms.IKey[]): string =>
      keys.length === 0 ? '' : Fn.join(',', keys.map((k) => k.keyArn));

    this.serviceFunction = new lambda.Function(this, 'ServiceFunction', {
      description: `Auth service (${config.issuer})`,
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(config.lambdaAssetPath),
      memorySize: LAMBDA_MEMORY_MB,
      timeout: Duration.seconds(LAMBDA_TIMEOUT_SECONDS),
      role: this.serviceRole,
      logGroup: functionLogGroup,
      ...(config.reservedConcurrency === undefined
        ? {}
        : { reservedConcurrentExecutions: config.reservedConcurrency }),
      environment: {
        // docs/protocol.md §13
        AUTH_ISSUER: config.issuer,
        AUTH_RP_ID: config.rpId,
        AUTH_RP_NAME: config.rpName,
        AUTH_ALLOWED_ORIGINS: config.allowedOrigins.join(','),
        AUTH_CORS_ORIGINS: config.corsOrigins.join(','),
        AUTH_AUDIENCES: config.audiences.join(','),
        AUTH_CLIENT_IDS: config.clientIds.join(','),
        AUTH_TABLE_NAME: this.table.tableName,
        AUTH_ACCESS_TOKEN_KEY_ID: this.keys.accessToken.active.keyArn,
        AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS: joinArns(this.keys.accessToken.previous),
        AUTH_REFRESH_TOKEN_KEY_ID: this.keys.refreshToken.active.keyArn,
        AUTH_REFRESH_TOKEN_PREVIOUS_KEY_IDS: joinArns(this.keys.refreshToken.previous),
        AUTH_DPOP_NONCE_KEY_ID: this.keys.dpopNonce.keyArn,
        // lambda_http: REST API events carry the stage in the path; the custom
        // domain maps the root, so the service must not see `/prod`.
        AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH: 'true',
        RUST_LOG: 'info',
      },
    });
    // Never start the function before its permissions exist.
    this.serviceFunction.node.addDependency(runtimePolicy);

    // -----------------------------------------------------------------------
    // API Gateway (REST, regional; WAF cannot attach to HTTP APIs).
    // -----------------------------------------------------------------------
    const accessLogGroup = new logs.LogGroup(this, 'ApiAccessLogGroup', {
      retention: LOG_RETENTION,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.api = new apigw.RestApi(this, 'Api', {
      restApiName: `${this.stackName}-api`,
      description: `Auth service API (${config.issuer})`,
      endpointConfiguration: {
        types: [apigw.EndpointType.REGIONAL],
        ipAddressType: apigw.IpAddressType.DUAL_STACK,
      },
      // The only entry point is the custom domain (behind WAF, with the issuer URL).
      disableExecuteApiEndpoint: true,
      cloudWatchRole: config.manageApiGatewayCloudWatchRole,
      ...(config.manageApiGatewayCloudWatchRole ? { cloudWatchRoleRemovalPolicy: RemovalPolicy.RETAIN } : {}),
      failOnWarnings: true,
      // No minCompressionSize: compressing responses that carry tokens and recovery
      // codes next to attacker-influenced data invites BREACH-style attacks.
      deployOptions: {
        stageName: STAGE_NAME,
        accessLogDestination: new apigw.LogGroupLogDestination(accessLogGroup),
        accessLogFormat: apigw.AccessLogFormat.custom(accessLogFormat()),
        // Execution logs can include request headers (X-Forwarded-For, User-Agent)
        // and cannot be filtered, so they stay off; so does data tracing.
        loggingLevel: apigw.MethodLoggingLevel.OFF,
        dataTraceEnabled: false,
        // API Gateway X-Ray segments record the client IP and user agent.
        tracingEnabled: false,
        metricsEnabled: false,
        throttlingRateLimit: config.apiThrottle.rateLimit,
        throttlingBurstLimit: config.apiThrottle.burstLimit,
      },
    });

    // Enhanced TLS policy and STRICT endpoint access mode on the API itself
    // (not yet exposed by the L2). The disabled execute-api host still
    // negotiates TLS, so keep it aligned with the custom domain.
    const cfnApi = this.api.node.defaultChild as apigw.CfnRestApi;
    cfnApi.securityPolicy = TLS_POLICIES[config.tlsSecurityPolicy];
    cfnApi.endpointAccessMode = apigw.EndpointAccessMode.STRICT;
    // The L2 always outputs the execute-api URL, which is disabled here; the
    // issuer URL is the only valid endpoint.
    this.api.node.tryRemoveChild('Endpoint');

    const integration = new apigw.LambdaIntegration(this.serviceFunction, {
      proxy: true,
      // No console "test invoke" path into the function.
      allowTestInvoke: false,
    });
    this.api.root.addMethod('ANY', integration);
    this.api.root.addProxy({ defaultIntegration: integration, anyMethod: true });

    this.addGatewayResponses();

    // -----------------------------------------------------------------------
    // Custom domain: issuer = https://<domainName>, no stage prefix.
    // -----------------------------------------------------------------------
    this.domain = new apigw.DomainName(this, 'Domain', {
      domainName: config.domainName,
      certificate: acm.Certificate.fromCertificateArn(this, 'Certificate', config.certificateArn),
      endpointType: apigw.EndpointType.REGIONAL,
      securityPolicy: TLS_POLICIES[config.tlsSecurityPolicy],
      endpointAccessMode: apigw.EndpointAccessMode.STRICT,
    });
    (this.domain.node.defaultChild as apigw.CfnDomainName).addPropertyOverride(
      'EndpointConfiguration.IpAddressType',
      apigw.IpAddressType.DUAL_STACK,
    );
    this.domain.addBasePathMapping(this.api, { stage: this.api.deploymentStage });

    if (config.hostedZone !== undefined) {
      const zone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
        hostedZoneId: config.hostedZone.id,
        zoneName: config.hostedZone.name,
      });
      const target = route53.RecordTarget.fromAlias(new route53Targets.ApiGatewayDomain(this.domain));
      new route53.ARecord(this, 'AliasRecordA', { zone, recordName: config.domainName, target });
      new route53.AaaaRecord(this, 'AliasRecordAAAA', { zone, recordName: config.domainName, target });
    }

    // -----------------------------------------------------------------------
    // WAF.
    // -----------------------------------------------------------------------
    this.webAcl = new AuthWebAcl(this, 'Waf', {
      config,
      metricPrefix: this.stackName.replace(/[^A-Za-z0-9]/g, ''),
    }).webAcl;
    const association = new wafv2.CfnWebACLAssociation(this, 'WebAclAssociation', {
      resourceArn: this.api.deploymentStage.stageArn,
      webAclArn: this.webAcl.attrArn,
    });
    association.node.addDependency(this.api.deploymentStage);

    // -----------------------------------------------------------------------
    // Outputs.
    // -----------------------------------------------------------------------
    new CfnOutput(this, 'IssuerUrl', { value: config.issuer, description: 'AUTH_ISSUER' });
    new CfnOutput(this, 'TableName', { value: this.table.tableName });
    new CfnOutput(this, 'TableKeyArn', { value: this.keys.tableKey.keyArn });
    new CfnOutput(this, 'AccessTokenSigningKeyArn', { value: this.keys.accessToken.active.keyArn });
    new CfnOutput(this, 'RefreshTokenSigningKeyArn', { value: this.keys.refreshToken.active.keyArn });
    new CfnOutput(this, 'DpopNonceKeyArn', { value: this.keys.dpopNonce.keyArn });
    new CfnOutput(this, 'WebAclArn', { value: this.webAcl.attrArn });
    new CfnOutput(this, 'DomainAliasTarget', {
      value: this.domain.domainNameAliasDomainName,
      description: 'Regional API Gateway domain to alias (A and AAAA) when no hostedZone is configured',
    });
    new CfnOutput(this, 'DomainAliasHostedZoneId', { value: this.domain.domainNameAliasHostedZoneId });

    applyNagSuppressions({ api: this.api, manageApiGatewayCloudWatchRole: config.manageApiGatewayCloudWatchRole });
  }

  /** Every permission the Lambda has, besides those named in the KMS key policies. */
  private serviceStatements(logGroup: logs.ILogGroup): iam.PolicyStatement[] {
    const { keys, table, config } = this;
    return [
      new iam.PolicyStatement({
        sid: 'TableItems',
        actions: [...DYNAMODB_TABLE_ACTIONS],
        resources: [table.tableArn],
      }),
      new iam.PolicyStatement({
        sid: 'TableKeyThroughDynamoDb',
        actions: [...TABLE_KEY_SERVICE_ACTIONS],
        resources: [keys.tableKey.keyArn],
        conditions: { StringEquals: { 'kms:ViaService': `dynamodb.${config.region}.amazonaws.com` } },
      }),
      new iam.PolicyStatement({
        sid: 'SignAccessTokens',
        actions: [...SIGN_ACTIONS],
        resources: [keys.accessToken.active.keyArn],
        conditions: SIGN_CONDITIONS,
      }),
      new iam.PolicyStatement({
        sid: 'SignRefreshTokens',
        actions: [...SIGN_ACTIONS],
        resources: [keys.refreshToken.active.keyArn],
        conditions: SIGN_CONDITIONS,
      }),
      new iam.PolicyStatement({
        sid: 'ReadSigningPublicKeys',
        actions: [...GET_PUBLIC_KEY_ACTIONS],
        resources: [...keys.accessToken.all, ...keys.refreshToken.all].map((k) => k.keyArn),
      }),
      new iam.PolicyStatement({
        sid: 'DpopNonceMac',
        actions: [...MAC_ACTIONS],
        resources: [keys.dpopNonce.keyArn],
        conditions: MAC_CONDITIONS,
      }),
      new iam.PolicyStatement({
        sid: 'WriteOwnLogs',
        actions: [...LOG_WRITE_ACTIONS],
        // `arn:…:log-group:<name>:*` — the log-stream suffix is how AWS scopes
        // CreateLogStream/PutLogEvents to one group.
        resources: [logGroup.logGroupArn],
      }),
    ];
  }

  /**
   * Responses API Gateway generates itself (throttling, oversized payloads,
   * WAF blocks without a custom response, integration failures) use the
   * protocol's OAuth error object and `Cache-Control: no-store` (§10).
   */
  private addGatewayResponses(): void {
    const headers = {
      'Cache-Control': "'no-store'",
      'X-Content-Type-Options': "'nosniff'",
    };
    const body = (error: string, description: string): Record<string, string> => ({
      'application/json': JSON.stringify({ error, error_description: description }),
    });
    const responses: [string, apigw.ResponseType, string | undefined, string, string][] = [
      ['Default4xx', apigw.ResponseType.DEFAULT_4XX, undefined, 'invalid_request', 'The request was rejected'],
      ['Default5xx', apigw.ResponseType.DEFAULT_5XX, undefined, 'server_error', 'Internal failure'],
      ['Throttled', apigw.ResponseType.THROTTLED, '429', 'rate_limited', 'Too many requests'],
      ['RequestTooLarge', apigw.ResponseType.REQUEST_TOO_LARGE, '413', 'payload_too_large', 'Request body is larger than 64 KiB'],
      ['WafFiltered', apigw.ResponseType.WAF_FILTERED, '403', 'access_denied', 'The request was blocked'],
    ];
    for (const [id, type, statusCode, error, description] of responses) {
      this.api.addGatewayResponse(id, {
        type,
        ...(statusCode === undefined ? {} : { statusCode }),
        responseHeaders: headers,
        templates: body(error, description),
      });
    }
  }
}
