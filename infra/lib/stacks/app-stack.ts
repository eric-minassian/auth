import * as path from "node:path";
import { fileURLToPath } from "node:url";

import * as cdk from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as apigwv2 from "aws-cdk-lib/aws-apigatewayv2";
import * as integrations from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as targets from "aws-cdk-lib/aws-route53-targets";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as ses from "aws-cdk-lib/aws-ses";
import * as sns from "aws-cdk-lib/aws-sns";
import type { Construct } from "constructs";

import {
  authHost,
  emailFrom,
  issuerUrl,
  mailFromDomain,
  type AuthConfig,
} from "../../config/types.js";

const dir = path.dirname(fileURLToPath(import.meta.url));

export interface AuthAppStackProps extends cdk.StackProps {
  hostedZone: route53.IHostedZone;
  table: dynamodb.TableV2;
  signingKey: kms.Key;
}

/**
 * The replaceable application tier: ACM cert, SES sending identity, the Rust
 * Lambda, the HTTP API, the SPA bucket, and the CloudFront distribution that
 * serves both the SPA and the API on `auth.ericminassian.com`.
 */
export class AuthAppStack extends cdk.Stack {
  constructor(scope: Construct, id: string, config: AuthConfig, props: AuthAppStackProps) {
    super(scope, id, props);
    const host = authHost(config);

    // --- TLS certificate (us-east-1, DNS-validated in our zone) ---
    const certificate = new acm.Certificate(this, "Certificate", {
      domainName: host,
      validation: acm.CertificateValidation.fromDns(props.hostedZone),
    });

    // --- SES sending identity (auto-creates DKIM + MAIL FROM records) ---
    const notifications = new sns.Topic(this, "SesNotifications", {
      displayName: "auth SES bounces and complaints",
    });
    const configurationSet = new ses.ConfigurationSet(this, "SesConfigSet");
    configurationSet.addEventDestination("BounceComplaint", {
      destination: ses.EventDestination.snsTopic(notifications),
      events: [ses.EmailSendingEvent.BOUNCE, ses.EmailSendingEvent.COMPLAINT],
    });
    new ses.EmailIdentity(this, "EmailIdentity", {
      identity: ses.Identity.publicHostedZone(props.hostedZone),
      mailFromDomain: mailFromDomain(config),
      configurationSet,
    });

    // --- Rust Lambda (Lambdalith) ---
    const fn = new lambda.Function(this, "Api", {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      handler: "bootstrap",
      code: lambda.Code.fromAsset(path.join(dir, "../..", config.lambdaAssetPath)),
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: cdk.Duration.seconds(10),
      environment: {
        TABLE_NAME: props.table.tableName,
        ISSUER: issuerUrl(config),
        KMS_KEY_ID: props.signingKey.keyId,
        EMAIL_FROM: emailFrom(config),
        SES_CONFIG_SET: configurationSet.configurationSetName,
        RUST_LOG: "info",
      },
      logGroup: new logs.LogGroup(this, "ApiLogs", {
        retention: logs.RetentionDays.THREE_MONTHS,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
    });
    props.table.grantReadWriteData(fn);
    props.signingKey.grant(fn, "kms:Sign", "kms:GetPublicKey");
    // SES has no grant* on the identity. SendEmail is authorized against
    // several resources at once: the From identity (prod) and, in the sandbox,
    // the verified recipient identity (so we grant identity/*), plus the
    // configuration set the identity sends through (configuration-set/*). The
    // From address is still fixed in code via EMAIL_FROM.
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["ses:SendEmail", "ses:SendRawEmail"],
        resources: [
          `arn:aws:ses:${this.region}:${this.account}:identity/*`,
          `arn:aws:ses:${this.region}:${this.account}:configuration-set/*`,
        ],
      }),
    );

    // --- HTTP API in front of the Lambda ---
    const httpApi = new apigwv2.HttpApi(this, "HttpApi", {
      defaultIntegration: new integrations.HttpLambdaIntegration("DefaultIntegration", fn),
    });
    const stage = httpApi.defaultStage?.node.defaultChild as apigwv2.CfnStage;
    stage.defaultRouteSettings = {
      throttlingRateLimit: 25,
      throttlingBurstLimit: 50,
    };

    // --- SPA bucket (private, served via CloudFront OAC) ---
    const spaBucket = new s3.Bucket(this, "SpaBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // --- CloudFront distribution ---
    const apiOrigin = new origins.HttpOrigin(
      `${httpApi.apiId}.execute-api.${this.region}.amazonaws.com`,
      { protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY },
    );
    // Forward cookies, query strings, and the headers the API needs — plus
    // CloudFront-Viewer-Address, the tamper-proof source IP the service uses
    // for rate limiting (the leftmost X-Forwarded-For is client-spoofable).
    // Host is omitted (execute-api rejects a foreign Host). Authorization can't
    // be listed in an origin-request policy; the one endpoint that needs it
    // (/oauth/userinfo, Bearer) gets its own behavior below using the managed
    // ALL_VIEWER policy, which forwards Authorization automatically.
    const apiOriginRequestPolicy = new cloudfront.OriginRequestPolicy(
      this,
      "ApiOriginRequestPolicy",
      {
        cookieBehavior: cloudfront.OriginRequestCookieBehavior.all(),
        queryStringBehavior: cloudfront.OriginRequestQueryStringBehavior.all(),
        headerBehavior: cloudfront.OriginRequestHeaderBehavior.allowList(
          "CloudFront-Viewer-Address",
          "Origin",
          "Content-Type",
          "Accept",
          "Referer",
          "User-Agent",
          "Sec-Fetch-Site",
          "Sec-Fetch-Mode",
          "Sec-Fetch-Dest",
        ),
      },
    );
    const apiBehavior: cloudfront.BehaviorOptions = {
      origin: apiOrigin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: apiOriginRequestPolicy,
    };
    // For JWKS/discovery: cache at the edge per the origin's Cache-Control, but
    // do NOT key on (and thus forward) Host — the managed
    // UseOriginCacheControlHeaders policy whitelists Host, which execute-api
    // rejects. This custom policy keeps the TTLs unset (origin-driven) and an
    // empty key.
    const wellKnownCachePolicy = new cloudfront.CachePolicy(this, "WellKnownCachePolicy", {
      headerBehavior: cloudfront.CacheHeaderBehavior.none(),
      cookieBehavior: cloudfront.CacheCookieBehavior.none(),
      queryStringBehavior: cloudfront.CacheQueryStringBehavior.none(),
    });
    // userinfo is Bearer-authenticated, so it needs Authorization forwarded
    // (and doesn't need the viewer IP — it isn't IP rate-limited).
    const bearerBehavior: cloudfront.BehaviorOptions = {
      origin: apiOrigin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
    };

    // SPA client-side routing: rewrite extensionless paths to /index.html.
    // Only attached to the default (SPA) behavior, so it never touches the
    // extensionless API/OIDC paths, which match their own behaviors first.
    const spaRewrite = new cloudfront.Function(this, "SpaRewrite", {
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      code: cloudfront.FunctionCode.fromInline(
        "function handler(event){var r=event.request;if(r.uri.indexOf('.')===-1){r.uri='/index.html';}return r;}",
      ),
    });

    const spaSecurity = new cloudfront.ResponseHeadersPolicy(this, "SpaSecurityHeaders", {
      securityHeadersBehavior: {
        strictTransportSecurity: {
          accessControlMaxAge: cdk.Duration.days(365),
          includeSubdomains: true,
          preload: true,
          override: true,
        },
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
        contentSecurityPolicy: {
          contentSecurityPolicy:
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
          override: true,
        },
      },
    });

    const distribution = new cloudfront.Distribution(this, "Distribution", {
      domainNames: [host],
      certificate,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      defaultRootObject: "index.html",
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(spaBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: spaSecurity,
        functionAssociations: [
          { function: spaRewrite, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST },
        ],
      },
      additionalBehaviors: {
        "/api/*": apiBehavior,
        "/oauth/*": apiBehavior,
        // More specific than /oauth/* — wins for the Bearer-authenticated path.
        "/oauth/userinfo": bearerBehavior,
        "/.well-known/*": {
          ...apiBehavior,
          // Honor the origin's Cache-Control (JWKS/discovery set their own)
          // without forwarding Host.
          cachePolicy: wellKnownCachePolicy,
        },
      },
    });

    new s3deploy.BucketDeployment(this, "SpaDeployment", {
      sources: [s3deploy.Source.asset(path.join(dir, "../..", config.spaAssetPath))],
      destinationBucket: spaBucket,
      distribution,
      distributionPaths: ["/*"],
    });

    // --- DNS: point the zone apex at CloudFront ---
    const recordTarget = route53.RecordTarget.fromAlias(
      new targets.CloudFrontTarget(distribution),
    );
    new route53.ARecord(this, "AliasA", { zone: props.hostedZone, target: recordTarget });
    new route53.AaaaRecord(this, "AliasAaaa", { zone: props.hostedZone, target: recordTarget });

    new cdk.CfnOutput(this, "Issuer", { value: issuerUrl(config) });
    new cdk.CfnOutput(this, "DistributionDomain", { value: distribution.distributionDomainName });
  }
}
