/**
 * WebAuthn binary formats shared by the software authenticator (producer) and
 * the fake server (verifier): authenticator data, COSE keys, attestation
 * objects and ECDSA signature encodings.
 */
import { decode as b64decode, encode as b64encode } from '../../src/base64url.js';
import { decodeCbor, decodeCborPrefix, encodeCbor, type CborValue } from './cbor.js';

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

export const COSE_ALG_ES256 = -7;

export function concatBytes(...chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

/** A copy of `bytes` in its own ArrayBuffer (what WebAuthn hands to JavaScript). */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

// ---------------------------------------------------------------------------
// COSE keys (RFC 9052 / RFC 9053): EC2 P-256 ES256
// ---------------------------------------------------------------------------

export function coseKeyFromJwk(jwk: JsonWebKey): Uint8Array<ArrayBuffer> {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.x === undefined || jwk.y === undefined) {
    throw new TypeError('expected a P-256 JWK');
  }
  return encodeCbor(
    new Map<CborValue, CborValue>([
      [1, 2], // kty: EC2
      [3, COSE_ALG_ES256], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, b64decode(jwk.x)],
      [-3, b64decode(jwk.y)],
    ]),
  );
}

export function jwkFromCoseKey(value: CborValue): JsonWebKey {
  if (!(value instanceof Map)) throw new TypeError('COSE key must be a map');
  const x = value.get(-2);
  const y = value.get(-3);
  if (
    value.get(1) !== 2 ||
    value.get(3) !== COSE_ALG_ES256 ||
    value.get(-1) !== 1 ||
    !(x instanceof Uint8Array) ||
    !(y instanceof Uint8Array) ||
    x.length !== 32 ||
    y.length !== 32
  ) {
    throw new TypeError('unsupported COSE key (only EC2 P-256 ES256)');
  }
  return { kty: 'EC', crv: 'P-256', x: b64encode(x), y: b64encode(y) };
}

// ---------------------------------------------------------------------------
// Authenticator data (WebAuthn §6.1)
// ---------------------------------------------------------------------------

export interface AttestedCredentialData {
  readonly aaguid: Uint8Array;
  readonly credentialId: Uint8Array;
  readonly publicKey: JsonWebKey;
}

export interface AuthenticatorData {
  readonly rpIdHash: Uint8Array;
  readonly flags: number;
  readonly signCount: number;
  readonly attestedCredentialData?: AttestedCredentialData;
  readonly extensions?: CborValue;
}

export function buildAuthenticatorData(params: {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  attested?: { aaguid: Uint8Array; credentialId: Uint8Array; cosePublicKey: Uint8Array };
}): Uint8Array<ArrayBuffer> {
  const header = new Uint8Array(37);
  header.set(params.rpIdHash, 0);
  header[32] = params.flags;
  new DataView(header.buffer).setUint32(33, params.signCount >>> 0, false);
  if (params.attested === undefined) {
    return header;
  }
  const { aaguid, credentialId, cosePublicKey } = params.attested;
  const len = new Uint8Array(2);
  new DataView(len.buffer).setUint16(0, credentialId.length, false);
  return concatBytes(header, aaguid, len, credentialId, cosePublicKey);
}

/** Strictly parses authenticator data; the AT/ED flags must match the content exactly. */
export function parseAuthenticatorData(data: Uint8Array): AuthenticatorData {
  if (data.length < 37) throw new TypeError('authenticator data too short');
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const flags = data[32] ?? 0;
  const result: {
    rpIdHash: Uint8Array;
    flags: number;
    signCount: number;
    attestedCredentialData?: AttestedCredentialData;
    extensions?: CborValue;
  } = {
    rpIdHash: data.slice(0, 32),
    flags,
    signCount: view.getUint32(33, false),
  };
  let offset = 37;
  if ((flags & FLAG_AT) !== 0) {
    if (data.length < offset + 18) throw new TypeError('attested credential data too short');
    const aaguid = data.slice(offset, offset + 16);
    const idLength = view.getUint16(offset + 16, false);
    offset += 18;
    if (idLength < 1 || idLength > 1023 || data.length < offset + idLength) {
      throw new TypeError('bad credential ID length');
    }
    const credentialId = data.slice(offset, offset + idLength);
    offset += idLength;
    const key = decodeCborPrefix(data, offset);
    offset = key.end;
    result.attestedCredentialData = { aaguid, credentialId, publicKey: jwkFromCoseKey(key.value) };
  }
  if ((flags & FLAG_ED) !== 0) {
    const ext = decodeCborPrefix(data, offset);
    offset = ext.end;
    result.extensions = ext.value;
  }
  if (offset !== data.length) throw new TypeError('trailing bytes in authenticator data');
  return result;
}

// ---------------------------------------------------------------------------
// Attestation object (fmt "none")
// ---------------------------------------------------------------------------

export function buildNoneAttestationObject(authData: Uint8Array): Uint8Array<ArrayBuffer> {
  return encodeCbor(
    new Map<CborValue, CborValue>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ]),
  );
}

export function parseAttestationObject(bytes: Uint8Array): {
  fmt: string;
  attStmt: Map<CborValue, CborValue>;
  authData: Uint8Array;
} {
  const value = decodeCbor(bytes);
  if (!(value instanceof Map)) throw new TypeError('attestation object must be a map');
  const fmt = value.get('fmt');
  const attStmt = value.get('attStmt');
  const authData = value.get('authData');
  if (typeof fmt !== 'string' || !(attStmt instanceof Map) || !(authData instanceof Uint8Array)) {
    throw new TypeError('malformed attestation object');
  }
  return { fmt, attStmt, authData };
}

// ---------------------------------------------------------------------------
// ECDSA signature encodings
// ---------------------------------------------------------------------------

function derInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  let value = bytes.slice(start);
  if (((value[0] ?? 0) & 0x80) !== 0) value = concatBytes(new Uint8Array([0]), value);
  return concatBytes(new Uint8Array([0x02, value.length]), value);
}

/** IEEE P1363 `r || s` (what WebCrypto produces) -> DER `ECDSA-Sig-Value` (what authenticators produce). */
export function p1363ToDer(signature: Uint8Array): Uint8Array<ArrayBuffer> {
  if (signature.length !== 64) throw new TypeError('expected a 64-byte P-256 signature');
  const r = derInteger(signature.slice(0, 32));
  const s = derInteger(signature.slice(32));
  return concatBytes(new Uint8Array([0x30, r.length + s.length]), r, s);
}

/** DER `ECDSA-Sig-Value` -> IEEE P1363 `r || s`, strictly (minimal DER only). */
export function derToP1363(der: Uint8Array): Uint8Array<ArrayBuffer> {
  const fail = (): never => {
    throw new TypeError('malformed DER ECDSA signature');
  };
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) fail();
  const out = new Uint8Array(64);
  let offset = 2;
  for (let i = 0; i < 2; i++) {
    if (der[offset] !== 0x02) fail();
    const len = der[offset + 1] ?? 0;
    const int = der.slice(offset + 2, offset + 2 + len);
    if (len === 0 || int.length !== len) fail();
    if ((int[0] ?? 0) & 0x80) fail(); // negative
    if (len > 1 && int[0] === 0 && ((int[1] ?? 0) & 0x80) === 0) fail(); // non-minimal
    const stripped = int[0] === 0 ? int.slice(1) : int;
    if (stripped.length > 32) fail();
    out.set(stripped, i * 32 + (32 - stripped.length));
    offset += 2 + len;
  }
  if (offset !== der.length) fail();
  return out;
}
