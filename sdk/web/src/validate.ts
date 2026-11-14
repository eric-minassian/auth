/**
 * Minimal runtime validation for untrusted JSON. Every server response is
 * checked with these helpers before any field is used.
 */
import { isBase64url } from './base64url.js';
import { AuthError } from './errors.js';

export type JsonObject = Record<string, unknown>;

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Thrown internally; converted to `AuthError('invalid_response')` at the API boundary. */
export function invalid(what: string): AuthError {
  return new AuthError('invalid_response', `invalid server response: ${what}`);
}

export function expectObject(value: unknown, what: string): JsonObject {
  if (!isObject(value)) {
    throw invalid(`${what} must be an object`);
  }
  return value;
}

export function expectString(obj: JsonObject, key: string, what: string): string {
  const value = obj[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw invalid(`${what}.${key} must be a non-empty string`);
  }
  return value;
}

export function optionalString(obj: JsonObject, key: string, what: string): string | undefined {
  const value = obj[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw invalid(`${what}.${key} must be a string`);
  }
  return value;
}

export function expectBase64url(
  obj: JsonObject,
  key: string,
  what: string,
  minBytes = 0,
  maxBytes = Infinity,
): string {
  const value = obj[key];
  if (!isBase64url(value, minBytes, maxBytes)) {
    throw invalid(`${what}.${key} must be base64url (${minBytes}..${maxBytes} bytes)`);
  }
  return value;
}

/** A non-negative safe integer. */
export function expectInteger(obj: JsonObject, key: string, what: string, min = 0): number {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) {
    throw invalid(`${what}.${key} must be an integer >= ${min}`);
  }
  return value;
}

export function optionalInteger(
  obj: JsonObject,
  key: string,
  what: string,
  min = 0,
): number | undefined {
  return obj[key] === undefined ? undefined : expectInteger(obj, key, what, min);
}

export function expectBoolean(obj: JsonObject, key: string, what: string): boolean {
  const value = obj[key];
  if (typeof value !== 'boolean') {
    throw invalid(`${what}.${key} must be a boolean`);
  }
  return value;
}

export function expectArray(obj: JsonObject, key: string, what: string): unknown[] {
  const value = obj[key];
  if (!Array.isArray(value)) {
    throw invalid(`${what}.${key} must be an array`);
  }
  return value;
}

/**
 * RFC 9449 §7.1 / RFC 7235 `token68`: the only characters allowed for a token in
 * an `Authorization: DPoP <token>` header. Also guarantees the value cannot
 * break out of a header line.
 */
const TOKEN68 = /^[A-Za-z0-9\-._~+/]+=*$/;

export function isToken68(value: unknown): value is string {
  return (
    typeof value === 'string' && value.length > 0 && value.length <= 8192 && TOKEN68.test(value)
  );
}
