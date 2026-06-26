/**
 * Shared surface for `@ericminassian/auth`: error type, public user shape,
 * and the default issuer. Import the client, react, or server entry points
 * for actual functionality.
 */

export const DEFAULT_ISSUER = "https://auth.ericminassian.com";

export type AuthErrorCode =
  | "invalid_grant"
  | "login_required"
  | "token_refresh_failed"
  | "state_mismatch"
  | "network_error"
  | "invalid_token"
  | "configuration_error";

export class AuthError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message?: string) {
    super(message ?? code);
    this.name = "AuthError";
    this.code = code;
  }
}

/**
 * The authenticated subject, derived from the ID token / userinfo.
 *
 * Identity is keyed on `sub` (+ the issuer) — never on `nickname`, which is a
 * mutable, non-unique display label present only under the `profile` scope.
 * This provider issues no email; there is intentionally no `email` field.
 */
export interface User {
  sub: string;
  /** Display name (mutable, non-unique). Present only with the `profile` scope. */
  nickname?: string;
  /** Unix seconds the profile was last updated. Present only with `profile`. */
  updatedAt?: number;
}
