import * as cdk from "aws-cdk-lib";
import * as backup from "aws-cdk-lib/aws-backup";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as route53 from "aws-cdk-lib/aws-route53";
import type { Construct } from "constructs";

import { authHost, delegationRoleArn, type AuthConfig } from "../../config/types.js";

/**
 * Long-lived, slow-changing resources, retained across app churn:
 *
 * - the delegated public hosted zone for `auth.ericminassian.com` (the parent
 *   domain delegates this subdomain to us by pointing NS records here),
 * - the DynamoDB single table,
 * - the KMS asymmetric key used to sign JWTs.
 *
 * Deploy this first: it creates the zone and registers its `NS` delegation in
 * the parent zone (cross-account, automated). The app stack's ACM certificate
 * DNS validation depends on that delegation having propagated.
 */
export class AuthStatefulStack extends cdk.Stack {
  readonly hostedZone: route53.IHostedZone;
  readonly table: dynamodb.TableV2;
  readonly signingKey: kms.Key;
  /** Standby signing key (publish-before-sign keyring rotation). */
  readonly signingKeyB: kms.Key;

  constructor(scope: Construct, id: string, config: AuthConfig, props?: cdk.StackProps) {
    super(scope, id, props);

    // The zone name IS the configuration, so an explicit name is correct here.
    this.hostedZone = new route53.PublicHostedZone(this, "HostedZone", {
      zoneName: authHost(config),
      comment: "Delegated subdomain zone for the auth service",
    });

    // Register this zone's NS records in the parent zone, which lives in a
    // different account. The org-management account exposes a scoped role
    // (`route53-delegation-<host>`) that trusts this account and may UPSERT/DELETE
    // only this subdomain's NS record. The custom resource resolves the parent
    // zone by name. See `~/projects/aws` (DnsStack) and `docs/deploy.md`.
    new route53.CrossAccountZoneDelegationRecord(this, "Delegation", {
      delegatedZone: this.hostedZone,
      parentHostedZoneName: config.delegation.parentZoneName,
      delegationRole: iam.Role.fromRoleArn(
        this,
        "DelegationRole",
        delegationRoleArn(config),
      ),
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
      // RETAIN protects against stack deletion; this blocks DeleteTable itself
      // (console mistake, compromised deploy credentials). The table is the
      // only copy of every credential in a system whose recovery is
      // unrecoverable by design. Off in `local` so a dev can tear down freely.
      deletionProtection: config.name === "prod",
    });

    // PITR dies with the table — AWS Backup snapshots survive it (and RETAIN
    // can't help against an explicit delete + name reuse). Daily for 5 weeks,
    // monthly for a year. TODO: copy-to-second-account via the org's backup
    // vault would also hedge account compromise; needs org-level setup first
    // (see docs/deploy.md).
    if (config.name === "prod") {
      const vault = new backup.BackupVault(this, "BackupVault", {
        removalPolicy: cdk.RemovalPolicy.RETAIN,
      });
      const plan = new backup.BackupPlan(this, "BackupPlan", {
        backupVault: vault,
      });
      plan.addRule(backup.BackupPlanRule.daily());
      plan.addRule(backup.BackupPlanRule.monthly1Year());
      plan.addSelection("Table", {
        resources: [backup.BackupResource.fromDynamoDbTable(this.table)],
      });
    }

    this.signingKey = new kms.Key(this, "JwtSigningKey", {
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      alias: "auth-jwt-a",
      description: "ES256 signing key for auth.ericminassian.com JWTs",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // The standby half of the publish-before-sign keyring: always provisioned
    // and published in JWKS, signing only after the `activeSigningKey` config
    // flip (rotation runbook: docs/deploy.md).
    this.signingKeyB = new kms.Key(this, "JwtSigningKeyB", {
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      alias: "auth-jwt-b",
      description: "ES256 standby signing key for auth.ericminassian.com JWTs",
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    new cdk.CfnOutput(this, "HostedZoneId", { value: this.hostedZone.hostedZoneId });
    new cdk.CfnOutput(this, "TableName", { value: this.table.tableName });
    new cdk.CfnOutput(this, "SigningKeyId", { value: this.signingKey.keyId });
    new cdk.CfnOutput(this, "SigningKeyBId", { value: this.signingKeyB.keyId });
  }
}
