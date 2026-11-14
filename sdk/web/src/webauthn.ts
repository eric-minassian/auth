/**
 * WebAuthn Level 3 JSON <-> binary conversion and validation.
 *
 * The conversion is implemented manually so it works in every browser and
 * with credential objects returned by password-manager extensions (which may
 * lack `toJSON()`). The output matches the Level 3 `RegistrationResponseJSON`
 * / `AuthenticationResponseJSON` forms that the server expects (protocol §8.2).
 */
import { decode, encode } from './base64url.js';
import { AuthError } from './errors.js';
import {
  expectArray,
  expectBase64url,
  expectInteger,
  expectObject,
  expectString,
  invalid,
  isObject,
  optionalString,
  type JsonObject,
} from './validate.js';

/** Account IDs are 16 random bytes (protocol §3). */
export const ACCOUNT_ID_BYTES = 16;
const MIN_CHALLENGE_BYTES = 16;
const MAX_CHALLENGE_BYTES = 64;
const MAX_CREDENTIAL_ID_BYTES = 1023;

// ---------------------------------------------------------------------------
// JSON types (WebAuthn Level 3 §5.1.8, §5.4, §5.5)
// ---------------------------------------------------------------------------

export interface CredentialDescriptorJSON {
  readonly type: string;
  readonly id: string;
  readonly transports?: readonly string[];
}

export interface CreationOptionsJSON {
  readonly rp: { readonly id?: string; readonly name: string };
  readonly user: { readonly id: string; readonly name: string; readonly displayName: string };
  readonly challenge: string;
  readonly pubKeyCredParams: readonly { readonly type: string; readonly alg: number }[];
  readonly timeout?: number;
  readonly excludeCredentials?: readonly CredentialDescriptorJSON[];
  readonly authenticatorSelection?: JsonObject;
  readonly hints?: readonly string[];
  readonly attestation?: string;
  readonly attestationFormats?: readonly string[];
  readonly extensions?: JsonObject;
}

export interface RequestOptionsJSON {
  readonly challenge: string;
  readonly timeout?: number;
  readonly rpId?: string;
  readonly allowCredentials?: readonly CredentialDescriptorJSON[];
  readonly userVerification?: string;
  readonly hints?: readonly string[];
  readonly extensions?: JsonObject;
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    attestationObject: string;
    authenticatorData?: string;
    transports?: string[];
    publicKey?: string;
    publicKeyAlgorithm?: number;
  };
  authenticatorAttachment?: string;
  clientExtensionResults: JsonObject;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
  clientExtensionResults: JsonObject;
}

// ---------------------------------------------------------------------------
// Validation of server-provided options
// ---------------------------------------------------------------------------

function optionalStringArray(obj: JsonObject, key: string, what: string): string[] | undefined {
  const value = obj[key];
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    throw invalid(`${what}.${key} must be an array of strings`);
  }
  return value;
}

function optionalObject(obj: JsonObject, key: string, what: string): JsonObject | undefined {
  const value = obj[key];
  if (value === undefined) {
    return undefined;
  }
  return expectObject(value, `${what}.${key}`);
}

function parseDescriptors(
  obj: JsonObject,
  key: string,
  what: string,
): CredentialDescriptorJSON[] | undefined {
  if (obj[key] === undefined) {
    return undefined;
  }
  return expectArray(obj, key, what).map((item, i) => {
    const d = expectObject(item, `${what}.${key}[${i}]`);
    const transports = optionalStringArray(d, 'transports', `${what}.${key}[${i}]`);
    const descriptor: CredentialDescriptorJSON = {
      type: expectString(d, 'type', `${what}.${key}[${i}]`),
      id: expectBase64url(d, 'id', `${what}.${key}[${i}]`, 1, MAX_CREDENTIAL_ID_BYTES),
    };
    return transports === undefined ? descriptor : { ...descriptor, transports };
  });
}

type Loose<T> = { [K in keyof T]: T[K] | undefined };

/** Removes keys whose value is `undefined` (for `exactOptionalPropertyTypes`). */
function compact<T extends object>(obj: Loose<T>): T {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out as T;
}

/** Validates `PublicKeyCredentialCreationOptionsJSON` from the server (protocol §8.1). */
export function parseCreationOptionsJSON(value: unknown): CreationOptionsJSON {
  const what = 'publicKey';
  const o = expectObject(value, what);
  const rp = expectObject(o['rp'], `${what}.rp`);
  const user = expectObject(o['user'], `${what}.user`);
  const params = expectArray(o, 'pubKeyCredParams', what).map((item, i) => {
    const p = expectObject(item, `${what}.pubKeyCredParams[${i}]`);
    const alg = p['alg'];
    if (typeof alg !== 'number' || !Number.isSafeInteger(alg)) {
      throw invalid(`${what}.pubKeyCredParams[${i}].alg must be an integer`);
    }
    return { type: expectString(p, 'type', `${what}.pubKeyCredParams[${i}]`), alg };
  });
  if (params.length === 0) {
    throw invalid(`${what}.pubKeyCredParams must not be empty`);
  }
  const rpId = optionalString(rp, 'id', `${what}.rp`);
  return compact<CreationOptionsJSON>({
    rp: compact<CreationOptionsJSON['rp']>({
      id: rpId === '' ? undefined : rpId,
      name: expectString(rp, 'name', `${what}.rp`),
    }),
    user: {
      id: expectBase64url(user, 'id', `${what}.user`, ACCOUNT_ID_BYTES, ACCOUNT_ID_BYTES),
      name: expectString(user, 'name', `${what}.user`),
      displayName: expectString(user, 'displayName', `${what}.user`),
    },
    challenge: expectBase64url(o, 'challenge', what, MIN_CHALLENGE_BYTES, MAX_CHALLENGE_BYTES),
    pubKeyCredParams: params,
    timeout: o['timeout'] === undefined ? undefined : expectInteger(o, 'timeout', what),
    excludeCredentials: parseDescriptors(o, 'excludeCredentials', what),
    authenticatorSelection: optionalObject(o, 'authenticatorSelection', what),
    hints: optionalStringArray(o, 'hints', what),
    attestation: optionalString(o, 'attestation', what),
    attestationFormats: optionalStringArray(o, 'attestationFormats', what),
    extensions: optionalObject(o, 'extensions', what),
  });
}

/** Validates `PublicKeyCredentialRequestOptionsJSON` from the server (protocol §8.2). */
export function parseRequestOptionsJSON(value: unknown): RequestOptionsJSON {
  const what = 'publicKey';
  const o = expectObject(value, what);
  const rpId = optionalString(o, 'rpId', what);
  return compact<RequestOptionsJSON>({
    challenge: expectBase64url(o, 'challenge', what, MIN_CHALLENGE_BYTES, MAX_CHALLENGE_BYTES),
    timeout: o['timeout'] === undefined ? undefined : expectInteger(o, 'timeout', what),
    rpId: rpId === '' ? undefined : rpId,
    allowCredentials: parseDescriptors(o, 'allowCredentials', what),
    userVerification: optionalString(o, 'userVerification', what),
    hints: optionalStringArray(o, 'hints', what),
    extensions: optionalObject(o, 'extensions', what),
  });
}

// ---------------------------------------------------------------------------
// JSON -> binary options
// ---------------------------------------------------------------------------

function toDescriptor(d: CredentialDescriptorJSON): PublicKeyCredentialDescriptor {
  const out: PublicKeyCredentialDescriptor = {
    type: d.type as PublicKeyCredentialType,
    id: decode(d.id),
  };
  if (d.transports !== undefined) {
    out.transports = [...d.transports] as AuthenticatorTransport[];
  }
  return out;
}

function prfValuesFromJSON(value: unknown, what: string): AuthenticationExtensionsPRFValues {
  const v = expectObject(value, what);
  const out: AuthenticationExtensionsPRFValues = {
    first: decode(expectBase64url(v, 'first', what)),
  };
  if (v['second'] !== undefined) {
    out.second = decode(expectBase64url(v, 'second', what));
  }
  return out;
}

/**
 * Converts extension inputs from JSON. The binary members defined by Level 3
 * (`prf`, `largeBlob.write`) are decoded; every other input is passed through.
 */
function extensionsFromJSON(json: JsonObject): AuthenticationExtensionsClientInputs {
  const out: Record<string, unknown> = { ...json };
  const prf = json['prf'];
  if (prf !== undefined) {
    const p = expectObject(prf, 'extensions.prf');
    const converted: AuthenticationExtensionsPRFInputs = {};
    if (p['eval'] !== undefined) {
      converted.eval = prfValuesFromJSON(p['eval'], 'extensions.prf.eval');
    }
    if (p['evalByCredential'] !== undefined) {
      const byCred = expectObject(p['evalByCredential'], 'extensions.prf.evalByCredential');
      converted.evalByCredential = Object.fromEntries(
        Object.entries(byCred).map(([k, v]) => [k, prfValuesFromJSON(v, `prf.evalByCredential`)]),
      );
    }
    out['prf'] = converted;
  }
  const largeBlob = json['largeBlob'];
  if (isObject(largeBlob) && largeBlob['write'] !== undefined) {
    out['largeBlob'] = {
      ...largeBlob,
      write: decode(expectBase64url(largeBlob, 'write', 'extensions.largeBlob')),
    };
  }
  return out;
}

/** `PublicKeyCredential.parseCreationOptionsFromJSON()` equivalent. */
export function toCreationOptions(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  const out: PublicKeyCredentialCreationOptions & Record<string, unknown> = {
    rp: { ...json.rp },
    user: { id: decode(json.user.id), name: json.user.name, displayName: json.user.displayName },
    challenge: decode(json.challenge),
    pubKeyCredParams: json.pubKeyCredParams.map((p) => ({
      type: p.type as PublicKeyCredentialType,
      alg: p.alg,
    })),
  };
  if (json.timeout !== undefined) out.timeout = json.timeout;
  if (json.excludeCredentials !== undefined) {
    out.excludeCredentials = json.excludeCredentials.map(toDescriptor);
  }
  if (json.authenticatorSelection !== undefined) {
    out.authenticatorSelection = { ...json.authenticatorSelection };
  }
  if (json.hints !== undefined) out['hints'] = [...json.hints];
  if (json.attestation !== undefined) {
    out.attestation = json.attestation as AttestationConveyancePreference;
  }
  if (json.attestationFormats !== undefined)
    out['attestationFormats'] = [...json.attestationFormats];
  if (json.extensions !== undefined) out.extensions = extensionsFromJSON(json.extensions);
  return out;
}

/** `PublicKeyCredential.parseRequestOptionsFromJSON()` equivalent. */
export function toRequestOptions(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  const out: PublicKeyCredentialRequestOptions & Record<string, unknown> = {
    challenge: decode(json.challenge),
  };
  if (json.timeout !== undefined) out.timeout = json.timeout;
  if (json.rpId !== undefined) out.rpId = json.rpId;
  if (json.allowCredentials !== undefined) {
    out.allowCredentials = json.allowCredentials.map(toDescriptor);
  }
  if (json.userVerification !== undefined) {
    out.userVerification = json.userVerification as UserVerificationRequirement;
  }
  if (json.hints !== undefined) out['hints'] = [...json.hints];
  if (json.extensions !== undefined) out.extensions = extensionsFromJSON(json.extensions);
  return out;
}

// ---------------------------------------------------------------------------
// Credential -> JSON
// ---------------------------------------------------------------------------

/** Views an ArrayBuffer / ArrayBufferView as bytes (also across realms). */
export function asBytes(value: unknown): Uint8Array | undefined {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Object.prototype.toString.call(value) === '[object ArrayBuffer]') {
    return new Uint8Array(value as ArrayBuffer);
  }
  return undefined;
}

function credentialInvalid(what: string, cause?: unknown): AuthError {
  return new AuthError(
    'credential_invalid',
    `authenticator returned an invalid credential: ${what}`,
    {
      cause,
    },
  );
}

function requireBytes(obj: Record<string, unknown>, key: string, what: string): Uint8Array {
  const bytes = asBytes(obj[key]);
  if (bytes === undefined) {
    throw credentialInvalid(`${what}.${key} must be binary`);
  }
  return bytes;
}

/** Calls an optional getter method; returns `undefined` if missing or failing. */
function callOptional(obj: Record<string, unknown>, method: string): unknown {
  const fn = obj[method];
  if (typeof fn !== 'function') {
    return undefined;
  }
  try {
    return (fn as () => unknown).call(obj);
  } catch {
    return undefined;
  }
}

/**
 * JSON-serializes client extension outputs as Level 3 `toJSON()` does:
 * binary values become base64url strings.
 */
export function extensionOutputsToJSON(value: unknown, depth = 0): unknown {
  if (depth > 8) {
    return undefined;
  }
  const bytes = asBytes(value);
  if (bytes !== undefined) {
    return encode(bytes);
  }
  if (Array.isArray(value)) {
    return value.map((v) => extensionOutputsToJSON(v, depth + 1));
  }
  if (isObject(value)) {
    const out: JsonObject = {};
    for (const [k, v] of Object.entries(value)) {
      const converted = extensionOutputsToJSON(v, depth + 1);
      if (converted !== undefined) {
        out[k] = converted;
      }
    }
    return out;
  }
  if (typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number') {
    return value;
  }
  return value === null ? null : undefined;
}

interface CommonParts {
  id: string;
  rawId: string;
  response: Record<string, unknown>;
  authenticatorAttachment?: string;
  clientExtensionResults: JsonObject;
}

function commonParts(credential: unknown): CommonParts {
  if (typeof credential !== 'object' || credential === null) {
    throw credentialInvalid('no credential');
  }
  const cred = credential as Record<string, unknown>;
  if (cred['type'] !== 'public-key') {
    throw credentialInvalid('type must be "public-key"');
  }
  const rawId = requireBytes(cred, 'rawId', 'credential');
  if (rawId.length < 1 || rawId.length > MAX_CREDENTIAL_ID_BYTES) {
    throw credentialInvalid('rawId must be 1..1023 bytes');
  }
  const rawIdB64 = encode(rawId);
  if (cred['id'] !== rawIdB64) {
    throw credentialInvalid('id must equal base64url(rawId)');
  }
  const response = cred['response'];
  if (typeof response !== 'object' || response === null) {
    throw credentialInvalid('missing response');
  }
  const extensions = extensionOutputsToJSON(callOptional(cred, 'getClientExtensionResults'));
  const parts: CommonParts = {
    id: rawIdB64,
    rawId: rawIdB64,
    response: response as Record<string, unknown>,
    clientExtensionResults: isObject(extensions) ? extensions : {},
  };
  const attachment = cred['authenticatorAttachment'];
  if (typeof attachment === 'string') {
    parts.authenticatorAttachment = attachment;
  }
  return parts;
}

/** Serializes the result of `navigator.credentials.create()`. */
export function registrationResponseToJSON(credential: unknown): RegistrationResponseJSON {
  const parts = commonParts(credential);
  const r = parts.response;
  const response: RegistrationResponseJSON['response'] = {
    clientDataJSON: encode(requireBytes(r, 'clientDataJSON', 'response')),
    attestationObject: encode(requireBytes(r, 'attestationObject', 'response')),
  };
  const authData = asBytes(callOptional(r, 'getAuthenticatorData'));
  if (authData !== undefined) response.authenticatorData = encode(authData);
  const transports = callOptional(r, 'getTransports');
  if (Array.isArray(transports) && transports.every((t) => typeof t === 'string')) {
    response.transports = transports;
  }
  const publicKey = asBytes(callOptional(r, 'getPublicKey'));
  if (publicKey !== undefined) response.publicKey = encode(publicKey);
  const alg = callOptional(r, 'getPublicKeyAlgorithm');
  if (typeof alg === 'number' && Number.isSafeInteger(alg)) response.publicKeyAlgorithm = alg;

  const json: RegistrationResponseJSON = {
    id: parts.id,
    rawId: parts.rawId,
    type: 'public-key',
    response,
    clientExtensionResults: parts.clientExtensionResults,
  };
  if (parts.authenticatorAttachment !== undefined) {
    json.authenticatorAttachment = parts.authenticatorAttachment;
  }
  return json;
}

/** Serializes the result of `navigator.credentials.get()`. */
export function authenticationResponseToJSON(credential: unknown): AuthenticationResponseJSON {
  const parts = commonParts(credential);
  const r = parts.response;
  const response: AuthenticationResponseJSON['response'] = {
    clientDataJSON: encode(requireBytes(r, 'clientDataJSON', 'response')),
    authenticatorData: encode(requireBytes(r, 'authenticatorData', 'response')),
    signature: encode(requireBytes(r, 'signature', 'response')),
  };
  const userHandle = r['userHandle'];
  if (userHandle !== null && userHandle !== undefined) {
    const bytes = asBytes(userHandle);
    if (bytes === undefined) {
      throw credentialInvalid('response.userHandle must be binary or null');
    }
    response.userHandle = encode(bytes);
  }
  const json: AuthenticationResponseJSON = {
    id: parts.id,
    rawId: parts.rawId,
    type: 'public-key',
    response,
    clientExtensionResults: parts.clientExtensionResults,
  };
  if (parts.authenticatorAttachment !== undefined) {
    json.authenticatorAttachment = parts.authenticatorAttachment;
  }
  return json;
}
