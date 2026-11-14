export { createAuthClient } from './client.js';
export type {
  AuthClient,
  AuthClientOptions,
  AuthFetchInit,
  ChangeListener,
  RecoverResult,
  Session,
  SignInOptions,
  SignUpResult,
} from './client.js';
export type { Account, Passkey } from './responses.js';
export { normalizeRecoveryCode } from './responses.js';
export {
  AuthError,
  CLIENT_ERROR_CODES,
  PROTOCOL_ERROR_CODES,
  StepUpRequiredError,
} from './errors.js';
export type {
  AuthErrorCode,
  AuthErrorOptions,
  ClientErrorCode,
  ProtocolErrorCode,
} from './errors.js';
