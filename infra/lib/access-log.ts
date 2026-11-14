/**
 * API Gateway access-log format.
 *
 * The service promises never to record IP addresses or user agents
 * (protocol §1). API Gateway's built-in formats (CLF, JSON with standard
 * fields) include `$context.identity.sourceIp` and friends, so we use an
 * explicit allowlist instead. Nothing under `$context.identity.*`,
 * `$context.authorizer.*`, or request/response overrides is ever logged, and
 * neither is `$context.path` (it carries credential IDs in
 * `DELETE /v1/account/passkeys/{credential_id}`); `resourcePath` is the route
 * template instead.
 *
 * Every value is a JSON string: API Gateway substitutes `-` for missing
 * values, which would make unquoted numbers invalid JSON.
 */
export const ACCESS_LOG_FIELDS = {
  requestId: '$context.requestId',
  extendedRequestId: '$context.extendedRequestId',
  requestTime: '$context.requestTime',
  requestTimeEpoch: '$context.requestTimeEpoch',
  httpMethod: '$context.httpMethod',
  resourcePath: '$context.resourcePath',
  protocol: '$context.protocol',
  status: '$context.status',
  responseLength: '$context.responseLength',
  responseLatency: '$context.responseLatency',
  integrationLatency: '$context.integrationLatency',
  integrationStatus: '$context.integrationStatus',
  integrationError: '$context.integration.error',
  errorType: '$context.error.responseType',
  errorMessage: '$context.error.message',
  wafResponseCode: '$context.wafResponseCode',
  tlsVersion: '$context.tlsVersion',
  cipherSuite: '$context.cipherSuite',
} as const;

/** The only `$context` variables allowed in the access-log format. */
export const ALLOWED_ACCESS_LOG_VARIABLES: readonly string[] = Object.values(ACCESS_LOG_FIELDS);

export function accessLogFormat(): string {
  return JSON.stringify(ACCESS_LOG_FIELDS);
}
