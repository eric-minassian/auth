/**
 * JWK helpers and RFC 7638 JWK thumbprints.
 */
import { encode, decode } from './base64url.js';

/** The public half of a P-256 key as it appears in a DPoP proof header (protocol §7.1). */
export interface EcPublicJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
}

/**
 * Required members per key type (RFC 7638 §3.2, RFC 8037 §2 for OKP), already
 * in lexicographic order.
 */
const REQUIRED_MEMBERS: Readonly<Record<string, readonly string[]>> = {
  EC: ['crv', 'kty', 'x', 'y'],
  RSA: ['e', 'kty', 'n'],
  OKP: ['crv', 'kty', 'x'],
  oct: ['k', 'kty'],
};

/**
 * The RFC 7638 §3 canonical JSON for a JWK: only the required members, sorted
 * lexicographically by Unicode code point, no whitespace.
 */
export function thumbprintInput(key: object): string {
  const jwk = key as Readonly<Record<string, unknown>>;
  const kty = jwk['kty'];
  if (typeof kty !== 'string') {
    throw new TypeError('JWK has no "kty"');
  }
  const members = REQUIRED_MEMBERS[kty];
  if (members === undefined) {
    throw new TypeError(`unsupported JWK key type "${kty}"`);
  }
  const parts = members.map((name) => {
    const value = jwk[name];
    if (typeof value !== 'string' || value.length === 0) {
      throw new TypeError(`JWK member "${name}" is missing`);
    }
    // JSON.stringify yields the minimal RFC 8259 string form required by §3.3.
    return `${JSON.stringify(name)}:${JSON.stringify(value)}`;
  });
  return `{${parts.join(',')}}`;
}

/** RFC 7638 SHA-256 JWK thumbprint, base64url encoded (the `jkt` of protocol §3). */
export async function jwkThumbprint(jwk: object): Promise<string> {
  const input = new TextEncoder().encode(thumbprintInput(jwk));
  return encode(await crypto.subtle.digest('SHA-256', input));
}

/**
 * Exports the public key of a P-256 key pair as a minimal JWK containing only
 * `kty`, `crv`, `x` and `y` (protocol §7.1).
 */
export async function exportEcPublicJwk(publicKey: CryptoKey): Promise<EcPublicJwk> {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.x === undefined || jwk.y === undefined) {
    throw new TypeError('expected a P-256 public key');
  }
  if (jwk.d !== undefined) {
    throw new TypeError('refusing to use a JWK with private members');
  }
  if (decode(jwk.x).length !== 32 || decode(jwk.y).length !== 32) {
    throw new TypeError('P-256 coordinates must be 32 bytes');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
