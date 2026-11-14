/** Error codes defined by the protocol (docs/protocol.md §10.8). */
export const PROTOCOL_ERROR_CODES = [
  'invalid_request',
  'invalid_client',
  'invalid_grant',
  'invalid_target',
  'invalid_dpop_proof',
  'use_dpop_nonce',
  'invalid_token',
  'insufficient_user_authentication',
  'unknown_credential',
  'webauthn_rejected',
  'too_many_passkeys',
  'last_passkey',
  'payload_too_large',
  'rate_limited',
  'server_error',
] as const;

export type ProtocolErrorCode = (typeof PROTOCOL_ERROR_CODES)[number];

/**
 * Error codes raised by the SDK itself (never sent by the server).
 *
 * - `network_error`: the request could not be sent or no response was received.
 * - `invalid_response`: the server's response did not have the expected shape.
 * - `unexpected_status`: the server answered with an unexpected HTTP status and
 *   no protocol error code.
 * - `not_signed_in`: the operation requires a session and there is none.
 * - `ceremony_cancelled`: the user dismissed the passkey prompt or it timed out
 *   (`NotAllowedError` / `AbortError`).
 * - `ceremony_failed`: the WebAuthn call failed for another reason (for example
 *   `InvalidStateError` when the authenticator already holds a passkey for the
 *   account, or `SecurityError` for an RP ID / origin mismatch).
 * - `credential_invalid`: the authenticator returned a malformed credential.
 * - `account_mismatch`: during step-up the user picked a passkey of a different
 *   account than the signed-in one.
 * - `webauthn_unsupported`: the browser has no WebAuthn support.
 * - `storage_unavailable`: IndexedDB is not available or failed.
 * - `invalid_recovery_code`: the recovery code is not well formed (§9).
 */
export const CLIENT_ERROR_CODES = [
  'network_error',
  'invalid_response',
  'unexpected_status',
  'not_signed_in',
  'ceremony_cancelled',
  'ceremony_failed',
  'credential_invalid',
  'account_mismatch',
  'webauthn_unsupported',
  'storage_unavailable',
  'invalid_recovery_code',
] as const;

export type ClientErrorCode = (typeof CLIENT_ERROR_CODES)[number];

export type AuthErrorCode = ProtocolErrorCode | ClientErrorCode;

const PROTOCOL_CODES: ReadonlySet<string> = new Set(PROTOCOL_ERROR_CODES);

export function isProtocolErrorCode(value: unknown): value is ProtocolErrorCode {
  return typeof value === 'string' && PROTOCOL_CODES.has(value);
}

export interface AuthErrorOptions {
  /** HTTP status of the response that caused the error, if any. */
  status?: number;
  /** The server's `error_description` (human readable, never contains secrets). */
  description?: string;
  /** Underlying error. */
  cause?: unknown;
}

/** Every error thrown by the SDK is an `AuthError` (or a subclass). */
export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number | undefined;
  readonly description: string | undefined;

  constructor(code: AuthErrorCode, message?: string, options: AuthErrorOptions = {}) {
    super(message ?? options.description ?? code, { cause: options.cause });
    this.name = 'AuthError';
    this.code = code;
    this.status = options.status;
    this.description = options.description;
  }
}

/**
 * The resource requires a recent passkey ceremony (RFC 9470,
 * `insufficient_user_authentication`). Call `signIn()` and retry; the account
 * helpers of the client do this automatically.
 */
export class StepUpRequiredError extends AuthError {
  /** `max_age` from the challenge: the maximum accepted age of `auth_time`, in seconds. */
  readonly maxAge: number | undefined;

  constructor(options: AuthErrorOptions & { maxAge?: number } = {}) {
    super('insufficient_user_authentication', undefined, options);
    this.name = 'StepUpRequiredError';
    this.maxAge = options.maxAge;
  }
}
