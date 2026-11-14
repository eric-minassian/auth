/**
 * Device keys and DPoP proofs (RFC 9449, protocol §7).
 */
import { encode, encodeText } from './base64url.js';
import { exportEcPublicJwk, jwkThumbprint, type EcPublicJwk } from './jwk.js';

const ECDSA_P256: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
const ES256: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

/** A device-bound P-256 key pair. The private key is never extractable. */
export interface DeviceKey {
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly jwk: EcPublicJwk;
  /** RFC 7638 thumbprint of `jwk` (the `cnf.jkt` the server binds tokens to). */
  readonly jkt: string;
}

/** Generates a new device key. The private key is created with `extractable: false`. */
export async function generateDeviceKey(): Promise<DeviceKey> {
  const pair = await crypto.subtle.generateKey(ECDSA_P256, false, ['sign', 'verify']);
  return deviceKeyFromPair(pair.privateKey, pair.publicKey);
}

/**
 * Validates a key pair (for example one read back from IndexedDB) and derives
 * its public JWK and thumbprint. Throws if the private key is extractable or is
 * not an ECDSA P-256 signing key.
 */
export async function deviceKeyFromPair(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<DeviceKey> {
  if (!isPrivateSigningKey(privateKey)) {
    throw new TypeError('device private key must be a non-extractable ECDSA P-256 signing key');
  }
  if (!isP256Key(publicKey) || publicKey.type !== 'public') {
    throw new TypeError('device public key must be an ECDSA P-256 public key');
  }
  const jwk = await exportEcPublicJwk(publicKey);
  return { privateKey, publicKey, jwk, jkt: await jwkThumbprint(jwk) };
}

function isP256Key(key: unknown): key is CryptoKey {
  if (typeof CryptoKey === 'undefined' || !(key instanceof CryptoKey)) {
    return false;
  }
  const algorithm = key.algorithm as Partial<EcKeyAlgorithm>;
  return algorithm.name === 'ECDSA' && algorithm.namedCurve === 'P-256';
}

function isPrivateSigningKey(key: unknown): key is CryptoKey {
  return (
    isP256Key(key) && key.type === 'private' && !key.extractable && key.usages.includes('sign')
  );
}

/**
 * The `htu` for a request URL (protocol §7.1): scheme, host and port in
 * canonical form (lowercase, default port omitted) followed by the path as the
 * URL parser serializes it, without query or fragment.
 */
export function htuFor(url: string | URL): string {
  const parsed = typeof url === 'string' ? new URL(url) : url;
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new TypeError('DPoP is only defined for http(s) URLs');
  }
  return parsed.origin + parsed.pathname;
}

/** `ath` = base64url(SHA-256(ASCII(access_token))) (RFC 9449 §4.2). */
export async function accessTokenHash(accessToken: string): Promise<string> {
  // Access tokens are validated as token68 (ASCII) before use, so UTF-8 == ASCII.
  return encode(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken)));
}

export function randomJti(): string {
  return encode(crypto.getRandomValues(new Uint8Array(16)));
}

export interface ProofParams {
  /** HTTP method exactly as sent. */
  readonly htm: string;
  /** See {@link htuFor}. */
  readonly htu: string;
  /** NumericDate, already corrected for clock skew. */
  readonly iat: number;
  /** The latest `DPoP-Nonce` received from this server, if any. */
  readonly nonce?: string | undefined;
  /** The access token sent with the request, if any; adds `ath`. */
  readonly accessToken?: string | undefined;
}

/** Builds a compact-serialized DPoP proof JWT signed with ES256. */
export async function createDpopProof(key: DeviceKey, params: ProofParams): Promise<string> {
  if (!Number.isSafeInteger(params.iat)) {
    throw new TypeError('iat must be an integer NumericDate');
  }
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: { kty: key.jwk.kty, crv: key.jwk.crv, x: key.jwk.x, y: key.jwk.y },
  };
  const payload: Record<string, string | number> = {
    jti: randomJti(),
    htm: params.htm,
    htu: params.htu,
    iat: params.iat,
  };
  if (params.nonce !== undefined) {
    payload['nonce'] = params.nonce;
  }
  if (params.accessToken !== undefined) {
    payload['ath'] = await accessTokenHash(params.accessToken);
  }
  const signingInput = `${encodeText(JSON.stringify(header))}.${encodeText(JSON.stringify(payload))}`;
  // WebCrypto ECDSA signatures are already the fixed-size IEEE P1363 r || s
  // form that JWS requires (RFC 7518 §3.4).
  const signature = await crypto.subtle.sign(
    ES256,
    key.privateKey,
    new TextEncoder().encode(signingInput),
  );
  if (signature.byteLength !== 64) {
    throw new Error('unexpected ECDSA signature length');
  }
  return `${signingInput}.${encode(signature)}`;
}
