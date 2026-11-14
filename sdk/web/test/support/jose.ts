/**
 * Strict JWS/JWT helpers and a DPoP proof verifier (RFC 9449 §4.3, protocol §7)
 * for the fake server. Independent from the SDK's proof builder.
 */
import { decode as b64decode, encode as b64encode, encodeText } from '../../src/base64url.js';
import { bytesEqual, sha256 } from './webauthn-format.js';

const ES256: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };
const FORBIDDEN_HEADERS = ['jku', 'x5u', 'x5c', 'crit'];
const ALLOWED_JWK_MEMBERS = new Set(['kty', 'crv', 'x', 'y', 'use', 'key_ops', 'alg', 'kid']);

export type Json = Record<string, unknown>;

function isJsonObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** RFC 7638 thumbprint of an EC P-256 JWK (implemented independently of the SDK). */
export async function thumbprint(jwk: JsonWebKey): Promise<string> {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.x === undefined || jwk.y === undefined) {
    throw new TypeError('expected an EC P-256 JWK');
  }
  return b64encode(await sha256(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`));
}

export async function signJwt(privateKey: CryptoKey, header: Json, payload: Json): Promise<string> {
  const input = `${encodeText(JSON.stringify(header))}.${encodeText(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign(ES256, privateKey, new TextEncoder().encode(input));
  return `${input}.${b64encode(sig)}`;
}

export interface DecodedJws {
  readonly header: Json;
  readonly payload: Json;
  readonly signingInput: Uint8Array<ArrayBuffer>;
  readonly signature: Uint8Array<ArrayBuffer>;
}

/** Splits and decodes a compact JWS strictly (canonical base64url, JSON objects). */
export function decodeJws(token: string): DecodedJws | undefined {
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;
  const [h, p, s] = parts as [string, string, string];
  try {
    const header: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(b64decode(h)),
    );
    const payload: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(b64decode(p)),
    );
    if (!isJsonObject(header) || !isJsonObject(payload)) return undefined;
    return {
      header,
      payload,
      signingInput: new TextEncoder().encode(`${h}.${p}`),
      signature: b64decode(s),
    };
  } catch {
    return undefined;
  }
}

export async function verifyEs256(publicKey: CryptoKey, jws: DecodedJws): Promise<boolean> {
  // JWS ES256 signatures are exactly 64 bytes (RFC 7518 §3.4); DER is rejected.
  if (jws.signature.length !== 64) return false;
  return crypto.subtle.verify(ES256, publicKey, jws.signature, jws.signingInput);
}

/** Verifies a JWT of the expected `typ` signed with ES256; returns its claims. */
export async function verifyJwt(
  token: string,
  publicKey: CryptoKey,
  typ: string,
): Promise<Json | undefined> {
  const jws = decodeJws(token);
  if (jws === undefined) return undefined;
  if (jws.header['typ'] !== typ || jws.header['alg'] !== 'ES256') return undefined;
  if (FORBIDDEN_HEADERS.some((h) => h in jws.header)) return undefined;
  return (await verifyEs256(publicKey, jws)) ? jws.payload : undefined;
}

export type DpopVerdict =
  | { readonly ok: true; readonly jkt: string; readonly claims: Json; readonly header: Json }
  | {
      readonly ok: false;
      readonly error: 'invalid_dpop_proof' | 'use_dpop_nonce';
      readonly reason: string;
    };

export interface VerifyDpopOptions {
  /** Expected `htm`. */
  readonly method: string;
  /** Expected `htu` (exact string comparison). */
  readonly htu: string;
  /** Server time, NumericDate. */
  readonly now: number;
  /** Maximum `|iat - now|` in seconds. */
  readonly maxSkew: number;
  /** When set, the proof must carry a nonce accepted by this predicate. */
  readonly acceptNonce?: (nonce: string) => Promise<boolean>;
  /** The access token presented with the request, if any (then `ath` is required). */
  readonly accessToken?: string;
  /** Seen `jkt\0jti` values (replay detection, protocol §7.3). */
  readonly seenJtis: Set<string>;
}

/** Verifies the value of a `DPoP` request header. */
export async function verifyDpopProof(
  proof: string | null,
  o: VerifyDpopOptions,
): Promise<DpopVerdict> {
  const bad = (reason: string): DpopVerdict => ({ ok: false, error: 'invalid_dpop_proof', reason });
  if (proof === null) return bad('missing DPoP header');
  if (proof.includes(',')) return bad('more than one DPoP header');
  const jws = decodeJws(proof);
  if (jws === undefined) return bad('not a compact JWS');
  const { header, payload: claims } = jws;
  if (header['typ'] !== 'dpop+jwt') return bad('typ');
  if (header['alg'] !== 'ES256') return bad('alg');
  if (FORBIDDEN_HEADERS.some((h) => h in header)) return bad('forbidden header');
  const jwk = header['jwk'];
  if (!isJsonObject(jwk)) return bad('jwk missing');
  if (Object.keys(jwk).some((k) => !ALLOWED_JWK_MEMBERS.has(k)))
    return bad('jwk has extra (private?) members');
  if (jwk['kty'] !== 'EC' || jwk['crv'] !== 'P-256') return bad('jwk kty/crv');
  const { x, y } = jwk;
  if (typeof x !== 'string' || typeof y !== 'string') return bad('jwk x/y');
  try {
    if (b64decode(x).length !== 32 || b64decode(y).length !== 32) return bad('jwk x/y length');
  } catch {
    return bad('jwk x/y encoding');
  }
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x, y },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
  } catch {
    return bad('jwk is not a P-256 point');
  }
  if (!(await verifyEs256(key, jws))) return bad('signature');
  const { jti, htm, htu, iat, nonce, ath } = claims;
  if (typeof jti !== 'string' || jti.length < 16 || jti.length > 128) return bad('jti');
  if (htm !== o.method) return bad(`htm ${String(htm)} != ${o.method}`);
  if (htu !== o.htu) return bad(`htu ${String(htu)} != ${o.htu}`);
  if (typeof iat !== 'number' || !Number.isInteger(iat)) return bad('iat');
  if (Math.abs(iat - o.now) > o.maxSkew) return bad(`iat skew ${iat - o.now}s`);
  if (o.accessToken !== undefined) {
    const expected = b64encode(await sha256(o.accessToken));
    if (
      typeof ath !== 'string' ||
      !bytesEqual(new TextEncoder().encode(ath), new TextEncoder().encode(expected))
    ) {
      return bad('ath');
    }
  } else if (ath !== undefined) {
    return bad('unexpected ath');
  }
  if (o.acceptNonce !== undefined) {
    if (typeof nonce !== 'string' || !(await o.acceptNonce(nonce))) {
      return {
        ok: false,
        error: 'use_dpop_nonce',
        reason: nonce === undefined ? 'nonce missing' : 'nonce stale',
      };
    }
  }
  const jkt = await thumbprint({ kty: 'EC', crv: 'P-256', x, y });
  const replayKey = `${jkt}\u0000${jti}`;
  if (o.seenJtis.has(replayKey)) return bad('jti replay');
  o.seenJtis.add(replayKey);
  return { ok: true, jkt, claims, header };
}
