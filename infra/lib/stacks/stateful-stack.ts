import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as kms from "aws-cdk-lib/aws-kms";
import * as route53 from "aws-cdk-lib/aws-route53";
import type { Construct } from "constructs";

import { authHost, type AuthConfig } from "../../config/types.js";

/**
 * Long-lived, slow-changing resources, retained across app churn:
 *
 * - the delegated public hosted zone for `auth.ericminassian.com` (the parent
 *   domain delegates this subdomain to us by pointing NS records here),
 * - the DynamoDB single table,
 * - the KMS asymmetric key used to sign JWTs.
 *
 * Deploy this first, delegate the zone's nameservers at the registrar, then
 * deploy the app stack (whose ACM/SES validation depends on the delegation).
 */
export class AuthStatefulStack extends cdk.Stack {
  readonly hostedZone: route53.IHostedZone;
  readonly table: dynamodb.TableV2;
  readonly signingKey: kms.Key;

  constructor(scope: Construct, id: string, config: AuthConfig, props?: cdk.StackProps) {
    super(scope, id, props);

    // The zone name IS the configuration, so an explicit name is correct here.
    this.hostedZone = new route53.PublicHostedZone(this, "HostedZone", {
      zoneName: authHost(config),
      comment: "Delegated subdomain zone for the auth service",
    });

    this.table = new dynamodb.TableV2(this, "Table", {
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: "ttl",
      billing: dynamodb.Billing.onDemand(),
      globalSecondaryIndexes: [
        {
          indexName: "GSI1",
          partitionKey: { name: "GSI1PK", type: dynamodb.AttributeType.STRING },
          sortKey: { name: "GSI1SK", type: dynamodb.AttributeType.STRING },
        },
      ],
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.signingKey = new kms.Key(this, "JwtSigningKey", {
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      alias: "auth-jwt-a",
      description: "ES256 signing key for auth.ericminassian.com JWTs",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // The user must copy these NS records into the parent ericminassian.com
    // zone (or registrar) to delegate the subdomain.
    new cdk.CfnOutput(this, "NameServers", {
      value: cdk.Fn.join(", ", this.hostedZone.hostedZoneNameServers ?? []),
      description: "Set these as the NS records for auth.ericminassian.com at the parent domain",
    });
    new cdk.CfnOutput(this, "HostedZoneId", { value: this.hostedZone.hostedZoneId });
    new cdk.CfnOutput(this, "TableName", { value: this.table.tableName });
    new cdk.CfnOutput(this, "SigningKeyId", { value: this.signingKey.keyId });
  }
}
