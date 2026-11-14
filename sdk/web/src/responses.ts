/**
 * Validation of auth-service response bodies (protocol §9, §10).
 */
import { AuthError } from './errors.js';
import {
  expectArray,
  expectBase64url,
  expectBoolean,
  expectInteger,
  expectObject,
  expectString,
  invalid,
  isToken68,
  optionalInteger,
  type JsonObject,
} from './validate.js';
import { ACCOUNT_ID_BYTES } from './webauthn.js';

export interface TokenSet {
  readonly accessToken: string;
  /** Lifetime of the access token in seconds. */
  readonly expiresIn: number;
  readonly refreshToken: string;
  /** Lifetime of the refresh token in seconds, if the server said. */
  readonly refreshExpiresIn: number | undefined;
}

/** Validates an RFC 6749 §5.1 token response with `token_type: DPoP` (protocol §10.2). */
export function parseTokenResponse(body: unknown): TokenSet {
  const o = expectObject(body, 'token response');
  const accessToken = o['access_token'];
  const refreshToken = o['refresh_token'];
  if (!isToken68(accessToken)) {
    throw invalid('access_token is missing or malformed');
  }
  if (!isToken68(refreshToken)) {
    throw invalid('refresh_token is missing or malformed');
  }
  // Token type names are case-insensitive (RFC 6749 §5.1). Anything but DPoP
  // would mean the token is not sender-constrained: refuse it.
  const tokenType = expectString(o, 'token_type', 'token response');
  if (tokenType.toLowerCase() !== 'dpop') {
    throw invalid('token_type must be DPoP');
  }
  return {
    accessToken,
    expiresIn: expectInteger(o, 'expires_in', 'token response', 1),
    refreshToken,
    refreshExpiresIn: optionalInteger(o, 'refresh_token_expires_in', 'token response', 1),
  };
}

/** A passkey registered to the account (protocol §10.7). */
export interface Passkey {
  /** base64url credential ID. */
  readonly credentialId: string;
  /** NumericDate. */
  readonly createdAt: number;
  /** NumericDate, or `null` if the server reports none. */
  readonly lastUsedAt: number | null;
  /** Authenticator AAGUID as reported by the server. */
  readonly aaguid: string;
  readonly backupEligible: boolean;
  readonly backupState: boolean;
}

export interface Account {
  /** base64url account ID (the token `sub`). */
  readonly accountId: string;
  /** NumericDate. */
  readonly createdAt: number;
  readonly passkeys: readonly Passkey[];
}

export function parsePasskey(value: unknown, what = 'passkey'): Passkey {
  const p = expectObject(value, what);
  const lastUsed = p['last_used_at'];
  return {
    credentialId: expectBase64url(p, 'credential_id', what, 1, 1023),
    createdAt: expectInteger(p, 'created_at', what),
    lastUsedAt:
      lastUsed === null || lastUsed === undefined ? null : expectInteger(p, 'last_used_at', what),
    aaguid: expectString(p, 'aaguid', what),
    backupEligible: expectBoolean(p, 'backup_eligible', what),
    backupState: expectBoolean(p, 'backup_state', what),
  };
}

export function parseAccount(body: unknown): Account {
  const o = expectObject(body, 'account');
  return {
    accountId: expectBase64url(o, 'account_id', 'account', ACCOUNT_ID_BYTES, ACCOUNT_ID_BYTES),
    createdAt: expectInteger(o, 'created_at', 'account'),
    passkeys: expectArray(o, 'passkeys', 'account').map((p, i) =>
      parsePasskey(p, `account.passkeys[${i}]`),
    ),
  };
}

/** `{"publicKey": {...}}` envelope of the options endpoints. */
export function publicKeyMember(body: unknown): unknown {
  return expectObject(body, 'options response')['publicKey'];
}

// ---------------------------------------------------------------------------
// Recovery codes (protocol §9)
// ---------------------------------------------------------------------------

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** 20 bytes = 160 bits = 32 base32 characters. */
const RECOVERY_CODE_CHARS = 32;

/**
 * Normalizes a recovery code as protocol §9 specifies (ignore `-` and
 * whitespace, uppercase, `I`/`L` -> `1`, `O` -> `0`) and returns it in the
 * canonical `XXXX-XXXX-…` form. Returns `undefined` if it is not well formed.
 */
export function normalizeRecoveryCode(input: string): string | undefined {
  if (typeof input !== 'string' || input.length > 256) {
    return undefined;
  }
  let chars = '';
  for (const raw of input) {
    if (raw === '-' || /\s/.test(raw)) {
      continue;
    }
    let c = raw.toUpperCase();
    if (c === 'I' || c === 'L') c = '1';
    else if (c === 'O') c = '0';
    if (c.length !== 1 || !CROCKFORD.includes(c)) {
      return undefined;
    }
    chars += c;
  }
  if (chars.length !== RECOVERY_CODE_CHARS) {
    return undefined;
  }
  return chars.match(/.{4}/g)?.join('-');
}

/** Validates a recovery code returned by the server. */
export function expectRecoveryCode(obj: JsonObject, key: string, what: string): string {
  const normalized = normalizeRecoveryCode(expectString(obj, key, what));
  if (normalized === undefined) {
    throw invalid(`${what}.${key} is not a valid recovery code`);
  }
  return normalized;
}

export function invalidRecoveryCode(): AuthError {
  return new AuthError(
    'invalid_recovery_code',
    'a recovery code has 32 characters from the Crockford base32 alphabet',
  );
}
