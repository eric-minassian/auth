/**
 * The exact IAM / KMS actions the stack grants. Kept in one place so the stack
 * and the tests cannot drift apart.
 */

/**
 * DynamoDB data-plane actions the service needs on its single table.
 *
 * There is no `dynamodb:TransactWriteItems` IAM action: a transaction is
 * authorized per element against PutItem / UpdateItem / DeleteItem /
 * ConditionCheckItem (DynamoDB developer guide, "Using IAM with DynamoDB
 * transactions"), so those cover TransactWriteItems.
 */
export const DYNAMODB_TABLE_ACTIONS = [
  'dynamodb:BatchGetItem',
  'dynamodb:ConditionCheckItem',
  'dynamodb:DeleteItem',
  'dynamodb:GetItem',
  'dynamodb:PutItem',
  'dynamodb:Query',
  'dynamodb:UpdateItem',
] as const;

/**
 * What the service role may do with the table CMK, and only through DynamoDB
 * (`kms:ViaService`). DynamoDB decrypts the table key with the caller's
 * credentials; it never needs a direct call from the service.
 */
export const TABLE_KEY_SERVICE_ACTIONS = [
  'kms:Decrypt',
  'kms:DescribeKey',
  'kms:Encrypt',
  'kms:GenerateDataKey',
] as const;

/**
 * What DynamoDB itself needs on the table CMK on behalf of account principals
 * (table creation by CloudFormation, backups, PITR, restores). Delegated to IAM
 * via the account principal and restricted with `kms:ViaService` +
 * `kms:CallerAccount` (DynamoDB developer guide, "Key policy for a customer
 * managed key"). `CreateGrant` is a separate statement that additionally
 * requires `kms:GrantIsForAWSResource`.
 */
export const TABLE_KEY_DYNAMODB_ACTIONS = [
  'kms:Decrypt',
  'kms:DescribeKey',
  'kms:Encrypt',
  'kms:GenerateDataKey',
  'kms:GenerateDataKeyWithoutPlaintext',
  'kms:ReEncryptFrom',
  'kms:ReEncryptTo',
] as const;

/** ES256 signing with a KMS P-256 key over a locally computed SHA-256 digest (protocol §5). */
export const SIGN_ACTIONS = ['kms:Sign'] as const;
export const SIGN_CONDITIONS = {
  StringEquals: {
    'kms:SigningAlgorithm': 'ECDSA_SHA_256',
    'kms:MessageType': 'DIGEST',
  },
} as const;

export const GET_PUBLIC_KEY_ACTIONS = ['kms:GetPublicKey'] as const;

/** DPoP nonce MAC (protocol §7.2). */
export const MAC_ACTIONS = ['kms:GenerateMac', 'kms:VerifyMac'] as const;
export const MAC_CONDITIONS = {
  StringEquals: {
    'kms:MacAlgorithm': 'HMAC_SHA_256',
  },
} as const;

/** Lambda writing to its own log group (no CreateLogGroup: the group is created by the stack). */
export const LOG_WRITE_ACTIONS = ['logs:CreateLogStream', 'logs:PutLogEvents'] as const;

/**
 * Key administration for the account (i.e. for IAM principals the account
 * authorizes, such as the CloudFormation execution role).
 *
 * Deliberately excludes every cryptographic operation (Sign, Verify,
 * GenerateMac, VerifyMac, Encrypt, Decrypt, GenerateDataKey*, ReEncrypt*) and
 * `kms:CreateGrant` (a grant could hand those operations to anyone). Only the
 * service role can sign tokens or compute nonce MACs; an administrator would
 * first have to rewrite the key policy, which is a CloudTrail-visible change.
 */
export const KEY_ADMIN_ACTIONS = [
  'kms:CancelKeyDeletion',
  'kms:CreateAlias',
  'kms:DeleteAlias',
  'kms:DescribeKey',
  'kms:DisableKey',
  'kms:DisableKeyRotation',
  'kms:EnableKey',
  'kms:EnableKeyRotation',
  'kms:GetKeyPolicy',
  'kms:GetKeyRotationStatus',
  'kms:GetPublicKey',
  'kms:ListGrants',
  'kms:ListKeyPolicies',
  'kms:ListKeyRotations',
  'kms:ListResourceTags',
  'kms:PutKeyPolicy',
  'kms:RetireGrant',
  'kms:RevokeGrant',
  'kms:RotateKeyOnDemand',
  'kms:ScheduleKeyDeletion',
  'kms:TagResource',
  'kms:UntagResource',
  'kms:UpdateAlias',
  'kms:UpdateKeyDescription',
] as const;
