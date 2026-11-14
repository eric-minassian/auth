import { Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';
import type { AuthServiceConfig, SigningKeyGenerations } from './config.js';
import {
  GET_PUBLIC_KEY_ACTIONS,
  KEY_ADMIN_ACTIONS,
  MAC_ACTIONS,
  MAC_CONDITIONS,
  SIGN_ACTIONS,
  SIGN_CONDITIONS,
  TABLE_KEY_DYNAMODB_ACTIONS,
} from './permissions.js';

export interface SigningKeySet {
  /** Signs new tokens. */
  readonly active: kms.Key;
  /** Still accepted (refresh) / published in JWKS (access) during a rotation. */
  readonly previous: readonly kms.Key[];
  readonly all: readonly kms.Key[];
}

export interface ServiceKeysProps {
  readonly config: AuthServiceConfig;
  /** The only principal allowed to use the signing and MAC keys. */
  readonly serviceRole: iam.IRole;
  /** Alias namespace, e.g. the stack name. */
  readonly aliasPrefix: string;
}

/**
 * The four customer-managed KMS keys (protocol §5, §12).
 *
 * Key policies do not delegate cryptographic use to the account: the account
 * principal (i.e. IAM administrators and the CloudFormation execution role)
 * gets administrative actions only, and the service role is named directly in
 * the key policy for Sign / GetPublicKey / GenerateMac / VerifyMac. An IAM
 * policy elsewhere in the account granting `kms:Sign` therefore has no effect
 * on these keys.
 *
 * Signing keys are versioned by "generation" (see README, key rotation). Each
 * generation is its own key with a stable construct ID, so adding a new
 * generation never replaces an existing key.
 */
export class ServiceKeys extends Construct {
  public readonly tableKey: kms.Key;
  public readonly accessToken: SigningKeySet;
  public readonly refreshToken: SigningKeySet;
  public readonly dpopNonce: kms.Key;

  public constructor(scope: Construct, id: string, props: ServiceKeysProps) {
    super(scope, id);
    const { config, serviceRole, aliasPrefix } = props;

    const admin = (): iam.PolicyStatement =>
      new iam.PolicyStatement({
        sid: 'KeyAdministrationWithoutCryptographicUse',
        principals: [new iam.AccountRootPrincipal()],
        actions: [...KEY_ADMIN_ACTIONS],
        // In a key policy, "*" means "this key"; it is the only valid value.
        resources: ['*'],
      });

    const viaDynamoDb = {
      'kms:ViaService': `dynamodb.${config.region}.amazonaws.com`,
      'kms:CallerAccount': config.account,
    };

    this.tableKey = new kms.Key(this, 'TableKey', {
      description: `${aliasPrefix}: DynamoDB table encryption`,
      keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(365),
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN,
      policy: new iam.PolicyDocument({
        statements: [
          admin(),
          new iam.PolicyStatement({
            sid: 'UseThroughDynamoDbByAuthorizedAccountPrincipals',
            principals: [new iam.AccountRootPrincipal()],
            actions: [...TABLE_KEY_DYNAMODB_ACTIONS],
            resources: ['*'],
            conditions: { StringEquals: viaDynamoDb },
          }),
          new iam.PolicyStatement({
            sid: 'DynamoDbGrantsForTableMaintenance',
            principals: [new iam.AccountRootPrincipal()],
            actions: ['kms:CreateGrant'],
            resources: ['*'],
            conditions: {
              StringEquals: viaDynamoDb,
              Bool: { 'kms:GrantIsForAWSResource': 'true' },
            },
          }),
        ],
      }),
    });
    new kms.Alias(this, 'TableKeyAlias', { aliasName: `alias/${aliasPrefix}/table`, targetKey: this.tableKey });

    const signingKeys = (
      name: string,
      purpose: string,
      generations: SigningKeyGenerations,
    ): SigningKeySet => {
      const make = (generation: number, active: boolean): kms.Key => {
        const statements = [
          admin(),
          new iam.PolicyStatement({
            sid: 'ServiceReadsPublicKey',
            principals: [serviceRole],
            actions: [...GET_PUBLIC_KEY_ACTIONS],
            resources: ['*'],
          }),
        ];
        if (active) {
          statements.push(
            new iam.PolicyStatement({
              sid: 'ServiceSignsEs256Digests',
              principals: [serviceRole],
              actions: [...SIGN_ACTIONS],
              resources: ['*'],
              conditions: SIGN_CONDITIONS,
            }),
          );
        }
        return new kms.Key(this, `${name}G${String(generation)}`, {
          description: `${aliasPrefix}: ${purpose} signing key, generation ${String(generation)} (${active ? 'active' : 'previous, verify only'})`,
          keySpec: kms.KeySpec.ECC_NIST_P256,
          keyUsage: kms.KeyUsage.SIGN_VERIFY,
          pendingWindow: Duration.days(30),
          removalPolicy: RemovalPolicy.RETAIN,
          policy: new iam.PolicyDocument({ statements }),
        });
      };
      const active = make(generations.active, true);
      const previous = generations.previous.map((g) => make(g, false));
      return { active, previous, all: [active, ...previous] };
    };

    this.accessToken = signingKeys('AccessTokenSigningKey', 'access-token', config.keys.accessToken);
    new kms.Alias(this, 'AccessTokenSigningKeyAlias', {
      aliasName: `alias/${aliasPrefix}/access-token`,
      targetKey: this.accessToken.active,
    });

    this.refreshToken = signingKeys('RefreshTokenSigningKey', 'refresh-token', config.keys.refreshToken);
    new kms.Alias(this, 'RefreshTokenSigningKeyAlias', {
      aliasName: `alias/${aliasPrefix}/refresh-token`,
      targetKey: this.refreshToken.active,
    });

    const nonceGeneration = config.keys.dpopNonce.active;
    this.dpopNonce = new kms.Key(this, `DpopNonceKeyG${String(nonceGeneration)}`, {
      description: `${aliasPrefix}: DPoP nonce HMAC key, generation ${String(nonceGeneration)}`,
      keySpec: kms.KeySpec.HMAC_256,
      keyUsage: kms.KeyUsage.GENERATE_VERIFY_MAC,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN,
      policy: new iam.PolicyDocument({
        statements: [
          admin(),
          new iam.PolicyStatement({
            sid: 'ServiceComputesNonceMacs',
            principals: [serviceRole],
            actions: [...MAC_ACTIONS],
            resources: ['*'],
            conditions: MAC_CONDITIONS,
          }),
        ],
      }),
    });
    new kms.Alias(this, 'DpopNonceKeyAlias', {
      aliasName: `alias/${aliasPrefix}/dpop-nonce`,
      targetKey: this.dpopNonce,
    });
  }
}
