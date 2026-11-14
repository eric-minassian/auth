/**
 * An in-memory implementation of the auth service (docs/protocol.md) and of a
 * resource server, exposed as a `fetch` function.
 *
 * It verifies everything the real service verifies that matters to a client:
 * DPoP proofs (signature, typ, alg, jwk, htm, htu, iat, nonce, ath, jti
 * uniqueness), WebAuthn attestation/assertion formats and signatures,
 * single-use challenges, DPoP-bound refresh tokens with epochs, access-token
 * audiences and step-up (RFC 9470). It issues nonces exactly as protocol §7.2
 * describes.
 */
import { decode as b64decode, encode as b64encode } from '../../src/base64url.js';
import { signJwt, thumbprint, verifyDpopProof, verifyJwt, type Json } from './jose.js';
import {
  FLAG_AT,
  FLAG_BE,
  FLAG_BS,
  FLAG_UP,
  FLAG_UV,
  bytesEqual,
  concatBytes,
  derToP1363,
  parseAttestationObject,
  parseAuthenticatorData,
  sha256,
} from './webauthn-format.js';

export interface FakeAuthServerOptions {
  readonly issuer?: string;
  readonly rpId?: string;
  readonly rpName?: string;
  /** Allowed WebAuthn origins (`AUTH_ALLOWED_ORIGINS`). */
  readonly origins?: readonly string[];
  /** Allowed audiences (`AUTH_AUDIENCES`); the first is the default and hosts the fake resource API. */
  readonly audiences?: readonly string[];
  readonly clientIds?: readonly string[];
  /** Server clock = local clock + this many seconds. */
  readonly clockSkewSeconds?: number;
}

type ChallengeKind = 'register' | 'login' | 'recover' | 'add_passkey';

interface ChallengeRecord {
  readonly kind: ChallengeKind;
  readonly accountId?: string;
  readonly expiresAt: number;
}

export interface CredentialRecord {
  readonly id: string;
  readonly publicKey: CryptoKey;
  signCount: number;
  readonly createdAt: number;
  lastUsedAt: number | null;
  readonly aaguid: Uint8Array;
  readonly backupEligible: boolean;
  backupState: boolean;
}

export interface AccountRecord {
  readonly id: string;
  readonly createdAt: number;
  epoch: number;
  readonly credentials: Map<string, CredentialRecord>;
  recoveryCode: string;
}

export interface Exchange {
  readonly method: string;
  readonly url: string;
  readonly path: string;
  readonly requestHeaders: Headers;
  readonly requestBody: string;
  readonly request: Request;
  status: number;
  responseHeaders?: Headers;
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ACCESS_TOKEN_TTL = 300;
const REFRESH_IDLE_TTL = 2_592_000;
const REFRESH_ABSOLUTE_TTL = 31_536_000;
const CEREMONY_TTL = 300;
const NONCE_WINDOW = 300;
const SKEW_AUTH = 120;
const SKEW_RESOURCE = 60;
const MAX_PASSKEYS = 20;

function crockford(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD.charAt((value << (5 - bits)) & 31);
  return out;
}

function normalizeCode(input: string): string | undefined {
  let out = '';
  for (const raw of input) {
    if (raw === '-' || raw === ' ') continue;
    let c = raw.toUpperCase();
    if (c === 'I' || c === 'L') c = '1';
    if (c === 'O') c = '0';
    if (!CROCKFORD.includes(c)) return undefined;
    out += c;
  }
  return out.length === 32 ? out : undefined;
}

function randomB64(n: number): string {
  return b64encode(crypto.getRandomValues(new Uint8Array(n)));
}

function isObject(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

class Reject extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    reason: string,
  ) {
    super(reason);
  }
}

export class FakeAuthServer {
  readonly issuer: string;
  readonly rpId: string;
  readonly rpName: string;
  readonly origins: readonly string[];
  readonly audiences: readonly string[];
  readonly clientIds: readonly string[];
  readonly apiOrigin: string;

  /** Server clock offset from the local clock (ms). */
  clockOffsetMs: number;
  /** `Date` header of the resource API is off by this much (the SDK must not use it). */
  resourceDateSkewSeconds = 0;
  /** Whether the resource API requires DPoP nonces. */
  resourceRequiresNonce = false;
  /** `STEP_UP_MAX_AGE` (seconds). */
  stepUpMaxAge = 300;
  /** Hook to inject failures; return a Response to short-circuit the request. */
  intercept:
    | ((request: Request, path: string) => Response | undefined | Promise<Response | undefined>)
    | undefined;

  readonly exchanges: Exchange[] = [];
  readonly stats = { refreshes: 0, logins: 0, registrations: 0 };
  readonly accounts = new Map<string, AccountRecord>();
  readonly #credentialIndex = new Map<string, string>();
  readonly #challenges = new Map<string, ChallengeRecord>();
  readonly #jtis = new Set<string>();
  #accessGeneration = 0;

  readonly #accessKey: CryptoKeyPair;
  readonly #accessKid: string;
  readonly #refreshKey: CryptoKeyPair;
  readonly #refreshKid: string;
  #nonceKey: CryptoKey;
  #resourceNonceKey: CryptoKey;

  private constructor(
    options: FakeAuthServerOptions,
    keys: {
      access: CryptoKeyPair;
      accessKid: string;
      refresh: CryptoKeyPair;
      refreshKid: string;
      nonce: CryptoKey;
      resourceNonce: CryptoKey;
    },
  ) {
    this.issuer = options.issuer ?? 'https://auth.example.com';
    this.rpId = options.rpId ?? 'example.com';
    this.rpName = options.rpName ?? 'Example';
    this.origins = options.origins ?? ['https://app.example.com'];
    this.audiences = options.audiences ?? ['https://api.example.com'];
    this.clientIds = options.clientIds ?? ['web'];
    this.clockOffsetMs = (options.clockSkewSeconds ?? 0) * 1000;
    this.apiOrigin = new URL(this.audiences[0] ?? 'https://api.example.com').origin;
    this.#accessKey = keys.access;
    this.#accessKid = keys.accessKid;
    this.#refreshKey = keys.refresh;
    this.#refreshKid = keys.refreshKid;
    this.#nonceKey = keys.nonce;
    this.#resourceNonceKey = keys.resourceNonce;
  }

  static async create(options: FakeAuthServerOptions = {}): Promise<FakeAuthServer> {
    const ec = { name: 'ECDSA', namedCurve: 'P-256' } as const;
    const access = await crypto.subtle.generateKey(ec, true, ['sign', 'verify']);
    const refresh = await crypto.subtle.generateKey(ec, true, ['sign', 'verify']);
    return new FakeAuthServer(options, {
      access,
      accessKid: await thumbprint(await crypto.subtle.exportKey('jwk', access.publicKey)),
      refresh,
      refreshKid: await thumbprint(await crypto.subtle.exportKey('jwk', refresh.publicKey)),
      nonce: await FakeAuthServer.#hmacKey(),
      resourceNonce: await FakeAuthServer.#hmacKey(),
    });
  }

  static #hmacKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  }

  // -------------------------------------------------------------------------
  // Test controls
  // -------------------------------------------------------------------------

  /** Server time, NumericDate. */
  now(): number {
    return Math.floor((Date.now() + this.clockOffsetMs) / 1000);
  }

  /** Moves the server clock forward. */
  advance(seconds: number): void {
    this.clockOffsetMs += seconds * 1000;
  }

  /** Invalidates every outstanding nonce. */
  async rotateNonceKeys(): Promise<void> {
    this.#nonceKey = await FakeAuthServer.#hmacKey();
    this.#resourceNonceKey = await FakeAuthServer.#hmacKey();
  }

  /** Makes every access token issued so far fail with `invalid_token`. */
  revokeAccessTokens(): void {
    this.#accessGeneration++;
  }

  /** Deletes a passkey server-side without telling the client. */
  forgetCredential(credentialId: string): void {
    const accountId = this.#credentialIndex.get(credentialId);
    if (accountId !== undefined) {
      this.accounts.get(accountId)?.credentials.delete(credentialId);
      this.#credentialIndex.delete(credentialId);
    }
  }

  /** Exchanges whose path matches. */
  requestsTo(path: string, method?: string): Exchange[] {
    return this.exchanges.filter(
      (e) => e.path === path && (method === undefined || e.method === method),
    );
  }

  // -------------------------------------------------------------------------
  // fetch
  // -------------------------------------------------------------------------

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const issuerUrl = new URL(this.issuer);
    const issuerPath = issuerUrl.pathname === '/' ? '' : issuerUrl.pathname;
    let path: string;
    let api: boolean;
    if (
      url.origin === issuerUrl.origin &&
      url.pathname === `/.well-known/oauth-authorization-server${issuerPath}`
    ) {
      path = '/.well-known/oauth-authorization-server';
      api = false;
    } else if (url.origin === issuerUrl.origin && url.pathname.startsWith(`${issuerPath}/`)) {
      path = url.pathname.slice(issuerPath.length);
      api = false;
    } else if (url.origin === this.apiOrigin) {
      path = url.pathname;
      api = true;
    } else {
      throw new TypeError('fetch failed');
    }
    const body = await request.clone().text();
    const exchange: Exchange = {
      method: request.method,
      url: request.url,
      path,
      requestHeaders: new Headers(request.headers),
      requestBody: body,
      request: request.clone(),
      status: 0,
    };
    this.exchanges.push(exchange);
    const intercepted = await this.intercept?.(request, path);
    let response: Response;
    if (intercepted !== undefined) {
      response = intercepted;
    } else {
      try {
        response = api
          ? await this.#handleApi(request, path)
          : await this.#handleAuth(request, path, body);
      } catch (error) {
        if (error instanceof Reject) {
          response = await this.#errorResponse(error.status, error.code, error.message);
        } else {
          throw error;
        }
      }
    }
    exchange.status = response.status;
    exchange.responseHeaders = new Headers(response.headers);
    return response;
  };

  // -------------------------------------------------------------------------
  // Nonces (protocol §7.2)
  // -------------------------------------------------------------------------

  async #nonce(key: CryptoKey): Promise<string> {
    const window = new Uint8Array(8);
    new DataView(window.buffer).setBigUint64(
      0,
      BigInt(Math.floor(this.now() / NONCE_WINDOW)),
      false,
    );
    const mac = new Uint8Array(
      await crypto.subtle.sign(
        'HMAC',
        key,
        concatBytes(new TextEncoder().encode('auth-dpop-nonce-v1'), window),
      ),
    );
    return b64encode(concatBytes(window, mac));
  }

  async #acceptNonce(key: CryptoKey, nonce: string): Promise<boolean> {
    let bytes: Uint8Array<ArrayBuffer>;
    try {
      bytes = b64decode(nonce);
    } catch {
      return false;
    }
    if (bytes.length !== 40) return false;
    const window = bytes.slice(0, 8);
    const w = Number(new DataView(window.buffer).getBigUint64(0, false));
    const current = Math.floor(this.now() / NONCE_WINDOW);
    if (w !== current && w !== current - 1) return false;
    return crypto.subtle.verify(
      'HMAC',
      key,
      bytes.slice(8),
      concatBytes(new TextEncoder().encode('auth-dpop-nonce-v1'), window),
    );
  }

  // -------------------------------------------------------------------------
  // Responses
  // -------------------------------------------------------------------------

  async #authHeaders(extra: Record<string, string> = {}): Promise<Headers> {
    return new Headers({
      'Cache-Control': 'no-store',
      'DPoP-Nonce': await this.#nonce(this.#nonceKey),
      Date: new Date(this.now() * 1000).toUTCString(),
      ...extra,
    });
  }

  async #json(status: number, body: Json): Promise<Response> {
    return new Response(JSON.stringify(body), {
      status,
      headers: await this.#authHeaders({ 'Content-Type': 'application/json' }),
    });
  }

  async #empty(status: number): Promise<Response> {
    return new Response(null, { status, headers: await this.#authHeaders() });
  }

  #errorResponse(status: number, code: string, description: string): Promise<Response> {
    return this.#json(status, { error: code, error_description: description });
  }

  async #challenge(
    code: string | undefined,
    description: string,
    api: boolean,
    maxAge?: number,
  ): Promise<Response> {
    let value = 'DPoP';
    if (code !== undefined) {
      value += ` error="${code}", error_description="${description.replace(/["\\]/g, '')}"`;
      if (maxAge !== undefined) value += `, max_age=${maxAge}`;
      value += ', algs="ES256"';
    } else {
      value += ' algs="ES256"';
    }
    const headers = api ? await this.#apiHeaders() : await this.#authHeaders();
    headers.set('WWW-Authenticate', value);
    return new Response(null, { status: 401, headers });
  }

  async #apiHeaders(): Promise<Headers> {
    const headers = new Headers({
      'Cache-Control': 'no-store',
      Date: new Date((this.now() + this.resourceDateSkewSeconds) * 1000).toUTCString(),
    });
    if (this.resourceRequiresNonce)
      headers.set('DPoP-Nonce', await this.#nonce(this.#resourceNonceKey));
    return headers;
  }

  // -------------------------------------------------------------------------
  // Request parsing
  // -------------------------------------------------------------------------

  static #jsonBody(request: Request, body: string): Json {
    if (request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/json') {
      throw new Reject(400, 'invalid_request', 'content type must be application/json');
    }
    let value: unknown;
    try {
      value = JSON.parse(body);
    } catch {
      throw new Reject(400, 'invalid_request', 'malformed JSON');
    }
    if (!isObject(value)) throw new Reject(400, 'invalid_request', 'body must be an object');
    return value;
  }

  #checkClient(clientId: unknown): string {
    if (typeof clientId !== 'string' || !this.clientIds.includes(clientId)) {
      throw new Reject(400, 'invalid_client', 'unknown client_id');
    }
    return clientId;
  }

  #checkResource(resource: unknown): string {
    if (resource === undefined) return this.audiences[0] ?? this.issuer;
    if (
      typeof resource !== 'string' ||
      (resource !== this.issuer && !this.audiences.includes(resource))
    ) {
      throw new Reject(400, 'invalid_target', 'resource not allowed');
    }
    return resource;
  }

  /** DPoP for token-style endpoints: errors are 400 JSON. */
  async #tokenProof(request: Request, path: string): Promise<string> {
    const verdict = await verifyDpopProof(request.headers.get('dpop'), {
      method: request.method,
      htu: this.issuer + path,
      now: this.now(),
      maxSkew: SKEW_AUTH,
      acceptNonce: (n) => this.#acceptNonce(this.#nonceKey, n),
      seenJtis: this.#jtis,
    });
    if (!verdict.ok) throw new Reject(400, verdict.error, verdict.reason);
    return verdict.jkt;
  }

  /** Resource-style authentication: `Authorization: DPoP` + proof with `ath`. */
  async #authenticate(
    request: Request,
    options: {
      audience: string;
      htu: string;
      api: boolean;
      requireNonce: boolean;
      maxSkew: number;
      stepUp: boolean;
    },
  ): Promise<{ claims: Json; account: AccountRecord | undefined } | Response> {
    const match = /^DPoP ([A-Za-z0-9\-._~+/]+=*)$/i.exec(
      request.headers.get('authorization') ?? '',
    );
    if (match?.[1] === undefined) return this.#challenge(undefined, '', options.api);
    const token = match[1];
    const nonceKey = options.api ? this.#resourceNonceKey : this.#nonceKey;
    const verdict = await verifyDpopProof(request.headers.get('dpop'), {
      method: request.method,
      htu: options.htu,
      now: this.now(),
      maxSkew: options.maxSkew,
      ...(options.requireNonce
        ? { acceptNonce: (n: string) => this.#acceptNonce(nonceKey, n) }
        : {}),
      accessToken: token,
      seenJtis: this.#jtis,
    });
    if (!verdict.ok) return this.#challenge(verdict.error, verdict.reason, options.api);
    const claims = await verifyJwt(token, this.#accessKey.publicKey, 'at+jwt');
    const now = this.now();
    const cnf = claims?.['cnf'];
    const account =
      typeof claims?.['sub'] === 'string' ? this.accounts.get(claims['sub']) : undefined;
    if (
      claims?.['iss'] !== this.issuer ||
      claims['aud'] !== options.audience ||
      typeof claims['exp'] !== 'number' ||
      claims['exp'] <= now ||
      !isObject(cnf) ||
      cnf['jkt'] !== verdict.jkt ||
      claims['gen'] !== this.#accessGeneration ||
      (!options.api && account === undefined)
    ) {
      return this.#challenge('invalid_token', 'the access token is invalid', options.api);
    }
    const authTime = claims['auth_time'];
    if (options.stepUp && (typeof authTime !== 'number' || now - authTime > this.stepUpMaxAge)) {
      return this.#challenge(
        'insufficient_user_authentication',
        'A recent passkey sign-in is required',
        options.api,
        this.stepUpMaxAge,
      );
    }
    return { claims, account };
  }

  async #account(
    request: Request,
    path: string,
    stepUp: boolean,
  ): Promise<AccountRecord | Response> {
    const result = await this.#authenticate(request, {
      audience: this.issuer,
      htu: this.issuer + path,
      api: false,
      requireNonce: true,
      maxSkew: SKEW_AUTH,
      stepUp,
    });
    if (result instanceof Response) return result;
    if (result.account === undefined)
      return this.#challenge('invalid_token', 'no such account', false);
    return result.account;
  }

  // -------------------------------------------------------------------------
  // WebAuthn verification
  // -------------------------------------------------------------------------

  #consumeChallenge(clientData: Json, expectedType: string, kind: ChallengeKind): ChallengeRecord {
    if (clientData['type'] !== expectedType)
      throw new Reject(400, 'webauthn_rejected', 'clientData.type');
    const challenge = clientData['challenge'];
    const record = typeof challenge === 'string' ? this.#challenges.get(challenge) : undefined;
    if (record === undefined || typeof challenge !== 'string') {
      throw new Reject(400, 'invalid_grant', 'unknown or used challenge');
    }
    this.#challenges.delete(challenge); // single use, consumed before verification
    if (record.kind !== kind || record.expiresAt <= this.now()) {
      throw new Reject(400, 'invalid_grant', 'challenge expired or of the wrong kind');
    }
    if (typeof clientData['origin'] !== 'string' || !this.origins.includes(clientData['origin'])) {
      throw new Reject(400, 'webauthn_rejected', 'origin not allowed');
    }
    if (clientData['crossOrigin'] !== undefined && clientData['crossOrigin'] !== false) {
      throw new Reject(400, 'webauthn_rejected', 'crossOrigin');
    }
    if (clientData['topOrigin'] !== undefined)
      throw new Reject(400, 'webauthn_rejected', 'topOrigin');
    return record;
  }

  static #b64(obj: Json, key: string): Uint8Array<ArrayBuffer> {
    const value = obj[key];
    if (typeof value !== 'string') throw new Reject(400, 'invalid_request', `${key} missing`);
    try {
      return b64decode(value);
    } catch {
      throw new Reject(400, 'invalid_request', `${key} is not canonical base64url`);
    }
  }

  static #clientData(response: Json): { json: Json; bytes: Uint8Array<ArrayBuffer> } {
    const bytes = FakeAuthServer.#b64(response, 'clientDataJSON');
    let json: unknown;
    try {
      json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } catch {
      throw new Reject(400, 'webauthn_rejected', 'clientDataJSON');
    }
    if (!isObject(json)) throw new Reject(400, 'webauthn_rejected', 'clientDataJSON');
    return { json, bytes };
  }

  static #credentialEnvelope(credential: unknown): {
    cred: Json;
    response: Json;
    rawId: Uint8Array<ArrayBuffer>;
  } {
    if (!isObject(credential) || !isObject(credential['response'])) {
      throw new Reject(400, 'invalid_request', 'credential missing');
    }
    if (credential['type'] !== 'public-key') throw new Reject(400, 'webauthn_rejected', 'type');
    const rawId = FakeAuthServer.#b64(credential, 'rawId');
    if (rawId.length < 1 || rawId.length > 1023)
      throw new Reject(400, 'webauthn_rejected', 'rawId length');
    if (credential['id'] !== b64encode(rawId))
      throw new Reject(400, 'webauthn_rejected', 'id != rawId');
    return { cred: credential, response: credential['response'], rawId };
  }

  async #verifyRegistration(
    credential: unknown,
    kind: ChallengeKind,
  ): Promise<{ challenge: ChallengeRecord; record: CredentialRecord }> {
    const { response, rawId } = FakeAuthServer.#credentialEnvelope(credential);
    const clientData = FakeAuthServer.#clientData(response);
    const challenge = this.#consumeChallenge(clientData.json, 'webauthn.create', kind);
    let attestation: ReturnType<typeof parseAttestationObject>;
    let authData: ReturnType<typeof parseAuthenticatorData>;
    try {
      attestation = parseAttestationObject(FakeAuthServer.#b64(response, 'attestationObject'));
      authData = parseAuthenticatorData(attestation.authData);
    } catch (error) {
      if (error instanceof Reject) throw error;
      throw new Reject(400, 'webauthn_rejected', `malformed attestation: ${String(error)}`);
    }
    if (attestation.fmt !== 'none' || attestation.attStmt.size !== 0) {
      throw new Reject(400, 'webauthn_rejected', 'attestation format');
    }
    this.#checkFlags(authData, true);
    if (!bytesEqual(authData.rpIdHash, await sha256(this.rpId)))
      throw new Reject(400, 'webauthn_rejected', 'rpIdHash');
    const attested = authData.attestedCredentialData;
    if (attested === undefined || !bytesEqual(attested.credentialId, rawId)) {
      throw new Reject(400, 'webauthn_rejected', 'credential ID mismatch');
    }
    const id = b64encode(rawId);
    if (this.#credentialIndex.has(id))
      throw new Reject(400, 'webauthn_rejected', 'credential already registered');
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      attested.publicKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    return {
      challenge,
      record: {
        id,
        publicKey,
        signCount: authData.signCount,
        createdAt: this.now(),
        lastUsedAt: null,
        aaguid: attested.aaguid,
        backupEligible: (authData.flags & FLAG_BE) !== 0,
        backupState: (authData.flags & FLAG_BS) !== 0,
      },
    };
  }

  #checkFlags(authData: ReturnType<typeof parseAuthenticatorData>, registration: boolean): void {
    const f = authData.flags;
    if ((f & FLAG_UP) === 0 || (f & FLAG_UV) === 0)
      throw new Reject(400, 'webauthn_rejected', 'UP/UV');
    if ((f & FLAG_BS) !== 0 && (f & FLAG_BE) === 0)
      throw new Reject(400, 'webauthn_rejected', 'BS without BE');
    if (registration !== ((f & FLAG_AT) !== 0))
      throw new Reject(400, 'webauthn_rejected', 'AT flag');
  }

  #addCredential(account: AccountRecord, record: CredentialRecord): void {
    account.credentials.set(record.id, record);
    this.#credentialIndex.set(record.id, account.id);
  }

  #newRecoveryCode(account: AccountRecord): string {
    const code = crockford(crypto.getRandomValues(new Uint8Array(20)));
    account.recoveryCode = code;
    return code.match(/.{4}/g)?.join('-') ?? code;
  }

  async #issueTokens(
    account: AccountRecord,
    session: {
      jkt: string;
      authTime: number;
      cid: string;
      sid: string;
      resource: string;
      clientId: string;
    },
  ): Promise<Json> {
    const now = this.now();
    const accessToken = await signJwt(
      this.#accessKey.privateKey,
      { alg: 'ES256', typ: 'at+jwt', kid: this.#accessKid },
      {
        iss: this.issuer,
        sub: account.id,
        aud: session.resource,
        client_id: session.clientId,
        iat: now,
        exp: now + ACCESS_TOKEN_TTL,
        jti: randomB64(16),
        auth_time: session.authTime,
        amr: ['pop', 'mfa'],
        cnf: { jkt: session.jkt },
        gen: this.#accessGeneration,
      },
    );
    const refreshExp = Math.min(now + REFRESH_IDLE_TTL, session.authTime + REFRESH_ABSOLUTE_TTL);
    const refreshToken = await signJwt(
      this.#refreshKey.privateKey,
      { alg: 'ES256', typ: 'rt+jwt', kid: this.#refreshKid },
      {
        iss: this.issuer,
        aud: this.issuer,
        sub: account.id,
        client_id: session.clientId,
        iat: now,
        exp: refreshExp,
        jti: randomB64(16),
        sid: session.sid,
        auth_time: session.authTime,
        cid: session.cid,
        epoch: account.epoch,
        cnf: { jkt: session.jkt },
      },
    );
    return {
      access_token: accessToken,
      token_type: 'DPoP',
      expires_in: ACCESS_TOKEN_TTL,
      refresh_token: refreshToken,
      refresh_token_expires_in: refreshExp - now,
    };
  }

  #creationOptions(accountId: string, challenge: string, exclude: readonly string[]): Json {
    const short = crockford(b64decode(accountId)).slice(0, 4);
    const name = `${this.rpName} · ${short}`;
    return {
      rp: { id: this.rpId, name: this.rpName },
      user: { id: accountId, name, displayName: name },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -8 },
        { type: 'public-key', alg: -257 },
      ],
      timeout: 300000,
      excludeCredentials: exclude.map((id) => ({ type: 'public-key', id })),
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      attestation: 'none',
      extensions: { credProps: true },
    };
  }

  #newChallenge(kind: ChallengeKind, accountId?: string): string {
    const challenge = randomB64(32);
    this.#challenges.set(challenge, {
      kind,
      ...(accountId === undefined ? {} : { accountId }),
      expiresAt: this.now() + CEREMONY_TTL,
    });
    return challenge;
  }

  static #passkeyJson(c: CredentialRecord): Json {
    const hex = [...c.aaguid].map((b) => b.toString(16).padStart(2, '0')).join('');
    return {
      credential_id: c.id,
      created_at: c.createdAt,
      last_used_at: c.lastUsedAt,
      aaguid: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
      backup_eligible: c.backupEligible,
      backup_state: c.backupState,
    };
  }

  // -------------------------------------------------------------------------
  // Auth service routes
  // -------------------------------------------------------------------------

  async #handleAuth(request: Request, path: string, body: string): Promise<Response> {
    if (body.length > 65_536)
      return this.#errorResponse(413, 'payload_too_large', 'body too large');
    const route = `${request.method} ${path}`;
    switch (route) {
      case 'GET /.well-known/oauth-authorization-server': {
        const headers = await this.#authHeaders({
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=300',
        });
        return new Response(
          JSON.stringify({
            issuer: this.issuer,
            token_endpoint: `${this.issuer}/v1/token`,
            jwks_uri: `${this.issuer}/.well-known/jwks.json`,
            grant_types_supported: ['refresh_token'],
            response_types_supported: [],
            token_endpoint_auth_methods_supported: ['none'],
            dpop_signing_alg_values_supported: ['ES256'],
            authorization_response_iss_parameter_supported: false,
          }),
          { status: 200, headers },
        );
      }
      case 'POST /v1/register/options': {
        FakeAuthServer.#jsonBody(request, body);
        const accountId = randomB64(16);
        const challenge = this.#newChallenge('register', accountId);
        return this.#json(200, { publicKey: this.#creationOptions(accountId, challenge, []) });
      }
      case 'POST /v1/register/verify': {
        const json = FakeAuthServer.#jsonBody(request, body);
        const jkt = await this.#tokenProof(request, path);
        const clientId = this.#checkClient(json['client_id']);
        const resource = this.#checkResource(json['resource']);
        const { challenge, record } = await this.#verifyRegistration(
          json['credential'],
          'register',
        );
        const accountId = challenge.accountId ?? '';
        const account: AccountRecord = {
          id: accountId,
          createdAt: this.now(),
          epoch: 0,
          credentials: new Map(),
          recoveryCode: '',
        };
        this.accounts.set(accountId, account);
        this.#addCredential(account, record);
        const recoveryCode = this.#newRecoveryCode(account);
        this.stats.registrations++;
        const tokens = await this.#issueTokens(account, {
          jkt,
          authTime: this.now(),
          cid: record.id,
          sid: randomB64(16),
          resource,
          clientId,
        });
        return this.#json(201, { ...tokens, account_id: accountId, recovery_code: recoveryCode });
      }
      case 'POST /v1/login/options': {
        FakeAuthServer.#jsonBody(request, body);
        const challenge = this.#newChallenge('login');
        return this.#json(200, {
          publicKey: {
            challenge,
            rpId: this.rpId,
            timeout: 300000,
            allowCredentials: [],
            userVerification: 'required',
          },
        });
      }
      case 'POST /v1/login/verify':
        return this.#loginVerify(request, path, body);
      case 'POST /v1/token':
        return this.#token(request, path, body);
      case 'POST /v1/recover/options': {
        const json = FakeAuthServer.#jsonBody(request, body);
        const code =
          typeof json['recovery_code'] === 'string'
            ? normalizeCode(json['recovery_code'])
            : undefined;
        const account = [...this.accounts.values()].find(
          (a) => code !== undefined && a.recoveryCode === code,
        );
        if (account === undefined) throw new Reject(400, 'invalid_grant', 'unknown recovery code');
        const challenge = this.#newChallenge('recover', account.id);
        return this.#json(200, { publicKey: this.#creationOptions(account.id, challenge, []) });
      }
      case 'POST /v1/recover/verify': {
        const json = FakeAuthServer.#jsonBody(request, body);
        const jkt = await this.#tokenProof(request, path);
        const clientId = this.#checkClient(json['client_id']);
        const resource = this.#checkResource(json['resource']);
        const { challenge, record } = await this.#verifyRegistration(json['credential'], 'recover');
        const account = this.accounts.get(challenge.accountId ?? '');
        if (account === undefined) throw new Reject(400, 'invalid_grant', 'account gone');
        for (const id of account.credentials.keys()) this.#credentialIndex.delete(id);
        account.credentials.clear();
        this.#addCredential(account, record);
        account.epoch++;
        const recoveryCode = this.#newRecoveryCode(account);
        const tokens = await this.#issueTokens(account, {
          jkt,
          authTime: this.now(),
          cid: record.id,
          sid: randomB64(16),
          resource,
          clientId,
        });
        return this.#json(200, { ...tokens, recovery_code: recoveryCode });
      }
      case 'GET /v1/account': {
        const account = await this.#account(request, path, false);
        if (account instanceof Response) return account;
        return this.#json(200, {
          account_id: account.id,
          created_at: account.createdAt,
          passkeys: [...account.credentials.values()].map((c) => FakeAuthServer.#passkeyJson(c)),
        });
      }
      case 'POST /v1/account/passkeys/options': {
        const account = await this.#account(request, path, true);
        if (account instanceof Response) return account;
        FakeAuthServer.#jsonBody(request, body);
        const challenge = this.#newChallenge('add_passkey', account.id);
        return this.#json(200, {
          publicKey: this.#creationOptions(account.id, challenge, [...account.credentials.keys()]),
        });
      }
      case 'POST /v1/account/passkeys/verify': {
        const account = await this.#account(request, path, true);
        if (account instanceof Response) return account;
        const json = FakeAuthServer.#jsonBody(request, body);
        const { challenge, record } = await this.#verifyRegistration(
          json['credential'],
          'add_passkey',
        );
        if (challenge.accountId !== account.id)
          throw new Reject(400, 'invalid_grant', 'challenge for another account');
        if (account.credentials.size >= MAX_PASSKEYS)
          throw new Reject(409, 'too_many_passkeys', 'limit reached');
        this.#addCredential(account, record);
        return this.#json(201, FakeAuthServer.#passkeyJson(record));
      }
      case 'POST /v1/account/logout-all': {
        const account = await this.#account(request, path, false);
        if (account instanceof Response) return account;
        account.epoch++;
        return this.#empty(204);
      }
      case 'POST /v1/account/recovery-code': {
        const account = await this.#account(request, path, true);
        if (account instanceof Response) return account;
        return this.#json(200, { recovery_code: this.#newRecoveryCode(account) });
      }
      case 'DELETE /v1/account': {
        const account = await this.#account(request, path, true);
        if (account instanceof Response) return account;
        for (const id of account.credentials.keys()) this.#credentialIndex.delete(id);
        this.accounts.delete(account.id);
        return this.#empty(204);
      }
      default:
        break;
    }
    const removal = /^\/v1\/account\/passkeys\/([A-Za-z0-9_-]+)$/.exec(path);
    if (request.method === 'DELETE' && removal?.[1] !== undefined) {
      const account = await this.#account(request, path, true);
      if (account instanceof Response) return account;
      if (!account.credentials.has(removal[1]))
        throw new Reject(404, 'invalid_request', 'no such passkey');
      if (account.credentials.size === 1)
        throw new Reject(409, 'last_passkey', 'cannot remove the only passkey');
      account.credentials.delete(removal[1]);
      this.#credentialIndex.delete(removal[1]);
      return this.#empty(204);
    }
    return this.#errorResponse(404, 'invalid_request', `no route ${route}`);
  }

  async #loginVerify(request: Request, path: string, body: string): Promise<Response> {
    const json = FakeAuthServer.#jsonBody(request, body);
    const jkt = await this.#tokenProof(request, path);
    const clientId = this.#checkClient(json['client_id']);
    const resource = this.#checkResource(json['resource']);
    const { response, rawId } = FakeAuthServer.#credentialEnvelope(json['credential']);
    const clientData = FakeAuthServer.#clientData(response);
    this.#consumeChallenge(clientData.json, 'webauthn.get', 'login');
    const authDataBytes = FakeAuthServer.#b64(response, 'authenticatorData');
    let authData: ReturnType<typeof parseAuthenticatorData>;
    try {
      authData = parseAuthenticatorData(authDataBytes);
    } catch {
      throw new Reject(400, 'webauthn_rejected', 'authenticator data');
    }
    if (!bytesEqual(authData.rpIdHash, await sha256(this.rpId)))
      throw new Reject(400, 'webauthn_rejected', 'rpIdHash');
    this.#checkFlags(authData, false);
    const id = b64encode(rawId);
    const accountId = this.#credentialIndex.get(id);
    const account = accountId === undefined ? undefined : this.accounts.get(accountId);
    const stored = account?.credentials.get(id);
    if (account === undefined || stored === undefined) {
      return this.#json(401, {
        error: 'unknown_credential',
        error_description: 'this passkey is not registered',
        credential_id: id,
      });
    }
    const userHandle = response['userHandle'];
    if (typeof userHandle !== 'string' || userHandle !== account.id) {
      throw new Reject(400, 'webauthn_rejected', 'userHandle');
    }
    let signature: Uint8Array<ArrayBuffer>;
    try {
      signature = derToP1363(FakeAuthServer.#b64(response, 'signature'));
    } catch {
      throw new Reject(400, 'webauthn_rejected', 'signature encoding');
    }
    const signed = concatBytes(authDataBytes, await sha256(clientData.bytes));
    if (
      !(await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        stored.publicKey,
        signature,
        signed,
      ))
    ) {
      throw new Reject(400, 'webauthn_rejected', 'signature');
    }
    if (
      !(stored.signCount === 0 && authData.signCount === 0) &&
      authData.signCount <= stored.signCount
    ) {
      throw new Reject(400, 'webauthn_rejected', 'signature counter did not increase');
    }
    stored.signCount = authData.signCount;
    stored.lastUsedAt = this.now();
    stored.backupState = (authData.flags & FLAG_BS) !== 0;
    this.stats.logins++;
    const tokens = await this.#issueTokens(account, {
      jkt,
      authTime: this.now(),
      cid: id,
      sid: randomB64(16),
      resource,
      clientId,
    });
    return this.#json(200, tokens);
  }

  async #token(request: Request, path: string, body: string): Promise<Response> {
    if (
      request.headers.get('content-type')?.split(';')[0]?.trim() !==
      'application/x-www-form-urlencoded'
    ) {
      throw new Reject(400, 'invalid_request', 'token endpoint takes a form body');
    }
    const form = new URLSearchParams(body);
    const jkt = await this.#tokenProof(request, path);
    if (form.get('grant_type') !== 'refresh_token')
      throw new Reject(400, 'invalid_request', 'grant_type');
    const clientId = this.#checkClient(form.get('client_id') ?? undefined);
    const resource = this.#checkResource(form.get('resource') ?? undefined);
    const claims = await verifyJwt(
      form.get('refresh_token') ?? '',
      this.#refreshKey.publicKey,
      'rt+jwt',
    );
    const now = this.now();
    const cnf = claims?.['cnf'];
    const account =
      typeof claims?.['sub'] === 'string' ? this.accounts.get(claims['sub']) : undefined;
    if (
      claims?.['iss'] !== this.issuer ||
      claims['aud'] !== this.issuer ||
      claims['client_id'] !== clientId ||
      typeof claims['exp'] !== 'number' ||
      now >= claims['exp'] ||
      typeof claims['iat'] !== 'number' ||
      claims['iat'] > now + SKEW_AUTH ||
      !isObject(cnf) ||
      cnf['jkt'] !== jkt ||
      account === undefined ||
      typeof claims['cid'] !== 'string' ||
      !account.credentials.has(claims['cid']) ||
      claims['epoch'] !== account.epoch ||
      typeof claims['auth_time'] !== 'number' ||
      typeof claims['sid'] !== 'string'
    ) {
      throw new Reject(400, 'invalid_grant', 'refresh token rejected');
    }
    this.stats.refreshes++;
    return this.#json(
      200,
      await this.#issueTokens(account, {
        jkt,
        authTime: claims['auth_time'],
        cid: claims['cid'],
        sid: claims['sid'],
        resource,
        clientId,
      }),
    );
  }

  // -------------------------------------------------------------------------
  // Resource API routes (audience = audiences[0])
  // -------------------------------------------------------------------------

  async #handleApi(request: Request, path: string): Promise<Response> {
    const audience = this.audiences[0] ?? '';
    const stepUp = path === '/sensitive';
    if (!['/hello', '/sensitive', '/echo'].includes(path)) {
      return new Response('not found', { status: 404, headers: await this.#apiHeaders() });
    }
    const result = await this.#authenticate(request, {
      audience,
      htu: this.apiOrigin + path,
      api: true,
      requireNonce: this.resourceRequiresNonce,
      maxSkew: SKEW_RESOURCE,
      stepUp,
    });
    if (result instanceof Response) return result;
    const headers = await this.#apiHeaders();
    headers.set('Content-Type', 'application/json');
    const payload: Json = { sub: result.claims['sub'], path };
    if (path === '/echo') payload['body'] = await request.text();
    return new Response(JSON.stringify(payload), { status: 200, headers });
  }
}
