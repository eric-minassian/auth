/**
 * cdk-nag acknowledgments. Each one is attached to the narrowest construct it
 * applies to and carries the reason it is safe. Anything not listed here fails
 * synthesis.
 */
import { Validations } from 'aws-cdk-lib';
import type * as apigw from 'aws-cdk-lib/aws-apigateway';
import type { IConstruct } from 'constructs';

export interface NagSuppressionTargets {
  readonly api: apigw.RestApi;
  readonly manageApiGatewayCloudWatchRole: boolean;
}

export const NAG_REASONS = {
  requestValidation:
    'The API is a single Lambda proxy (ANY / and ANY /{proxy+}) with no API Gateway models, so a request validator ' +
    'would validate nothing. The service is the normative validator (docs/protocol.md): strict JSON/form parsing, ' +
    'canonical base64url, WebAuthn and DPoP verification, and the 64 KiB body limit (also enforced at the edge by ' +
    'the WAF BodySizeLimit rule).',
  apiGatewayCloudWatchRole:
    'API Gateway needs a regional, account-wide role to write access logs to CloudWatch Logs; ' +
    'AmazonAPIGatewayPushToCloudWatchLogs is the AWS-documented policy for it. The role is shared by every REST API ' +
    'in the account and region, so it cannot be scoped to this stack without breaking other APIs, and only ' +
    'apigateway.amazonaws.com can assume it. Set manageApiGatewayCloudWatchRole=false if the account already ' +
    'manages this role.',
  executionLogging:
    'Execution logging is off on purpose: execution logs can include request headers such as X-Forwarded-For ' +
    '(client IP) and User-Agent, which the service must never record (protocol §1), and their content cannot be ' +
    'filtered. Access logs with an explicit PII-free field allowlist, Lambda logs and CloudWatch metrics provide ' +
    'the operational visibility.',
  authorization:
    'This API is the authentication server itself. Sign-up, sign-in, recovery, token refresh and discovery are ' +
    'reachable without prior credentials by definition, and the account endpoints verify DPoP-bound access tokens ' +
    'issued by this same service (RFC 9449, protocol §10.7) inside the function. There is no upstream identity ' +
    'provider for an API Gateway authorizer to delegate to.',
  cognito:
    'The service is its own passkey-based authentication server (protocol §1). A Cognito user pool would add a ' +
    'second identity store with PII-capable attributes; requests are authenticated in the function (WebAuthn, DPoP).',
} as const;

const API_GATEWAY_CLOUDWATCH_POLICY =
  'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs';

function acknowledge(construct: IConstruct, id: string, reason: string): void {
  Validations.of(construct).acknowledge({ id, reason });
}

export function applyNagSuppressions({ api, manageApiGatewayCloudWatchRole }: NagSuppressionTargets): void {
  const cfnApi = api.node.defaultChild;
  if (cfnApi === undefined) throw new Error('RestApi has no CfnRestApi child');
  acknowledge(cfnApi, 'AwsSolutions-APIG2', NAG_REASONS.requestValidation);
  acknowledge(api.deploymentStage, 'AwsSolutions-APIG6', NAG_REASONS.executionLogging);

  for (const method of api.methods) {
    acknowledge(method, 'AwsSolutions-APIG4', NAG_REASONS.authorization);
    acknowledge(method, 'AwsSolutions-COG4', NAG_REASONS.cognito);
  }

  if (manageApiGatewayCloudWatchRole) {
    const role = api.node.findChild('CloudWatchRole');
    acknowledge(role, `AwsSolutions-IAM4[${API_GATEWAY_CLOUDWATCH_POLICY}]`, NAG_REASONS.apiGatewayCloudWatchRole);
  }
}
