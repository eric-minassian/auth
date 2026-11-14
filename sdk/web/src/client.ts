/**
 * The auth client: passkey ceremonies, device-bound sessions and DPoP-protected
 * requests (docs/protocol.md).
 */
import { isBase64url } from './base64url.js';
import { ServerClock } from './clock.js';
import { deviceKeyFromPair, generateDeviceKey, type DeviceKey } from './dpop.js';
import { AuthError, StepUpRequiredError } from './errors.js';
import { exportEcPublicJwk, jwkThumbprint } from './jwk.js';
import { SingleFlight, withExclusiveLock } from './locks.js';
import {
  ceremonyError,
  credentialsContainer,
  isImmediateGetAvailable,
  isNotAllowed,
  signalAllAcceptedCredentials,
  signalUnknownCredential,
  type ImmediateCredentialRequestOptions,
} from './platform.js';
import {
  expectRecoveryCode,
  invalidRecoveryCode,
  normalizeRecoveryCode,
  parseAccount,
  parsePasskey,
  parseTokenResponse,
  publicKeyMember,
  type Account,
  type Passkey,
  type TokenSet,
} from './responses.js';
import { IndexedDbSessionStore, type StoredSession } from './store.js';
import {
  CLOCK_RETRY_THRESHOLD_MS,
  DpopTransport,
  errorFromResponse,
  readJson,
  type FetchLike,
} from './transport.js';
import { expectBase64url, expectObject, invalid, isObject } from './validate.js';
import {
  ACCOUNT_ID_BYTES,
  authenticationResponseToJSON,
  parseCreationOptionsJSON,
  parseRequestOptionsJSON,
  registrationResponseToJSON,
  toCreationOptions,
  toRequestOptions,
  type AuthenticationResponseJSON,
  type CreationOptionsJSON,
  type RegistrationResponseJSON,
  type RequestOptionsJSON,
} from './webauthn.js';
import { dpopChallenge } from './www-authenticate.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface AuthClientOptions {
  /**
   * The auth service's issuer URL (`AUTH_ISSUER`), e.g. `https://auth.example.com`.
   * Must be canonical: https (http only for loopback hosts), lowercase host, no
   * default port, no trailing slash, query or fragment.
   */
  readonly issuer: string;
  /** OAuth client ID (`AUTH_CLIENT_IDS`). Defaults to `"web"`. */
  readonly clientId?: string;
  /**
   * Resource indicator (RFC 8707) used by {@link AuthClient.fetch} when the
   * request does not name one, and for the access token issued at sign-in.
   * When omitted, `fetch()` requires an explicit `resource`.
   */
  readonly defaultResource?: string;
  /** `fetch` implementation. Defaults to the global `fetch`. */
  readonly fetch?: (input: Request) => Promise<Response>;
  /** IndexedDB database name. Defaults to `"auth-web"`. */
  readonly storageName?: string;
}

export interface Session {
  /** base64url account ID (the access token `sub`). */
  readonly accountId: string;
}

export interface SignUpResult {
  readonly accountId: string;
  /**
   * The account's recovery code (protocol §9). Show it to the user exactly once;
   * the SDK does not keep it.
   */
  readonly recoveryCode: string;
}

export type RecoverResult = SignUpResult;

export interface SignInOptions {
  /**
   * Use Immediate UI mode where the browser supports it: if this device has no
   * passkey for the site, `signIn` resolves to `null` without showing the
   * modal passkey sheet. Where Immediate UI is not supported, `signIn` resolves
   * to `null` without any prompt. Must be called from a user gesture.
   */
  readonly immediate?: boolean;
}

export type AuthFetchInit = RequestInit & {
  /** Resource indicator (RFC 8707) of the API; defaults to `defaultResource`. */
  resource?: string;
};

export type ChangeListener = (session: Session | null) => void;

export interface AuthClient {
  readonly issuer: string;
  /** The current session as known to this client (synchronous; see {@link restore}). */
  readonly session: Session | null;
  /**
   * Silently restores the session stored on this device (no UI). Resolves to
   * `null` when there is no session or the server rejected it (expired, signed
   * out everywhere, passkey removed, account deleted). Rejects with an
   * `AuthError` on transient failures (network, rate limiting, server errors),
   * leaving the stored session intact.
   */
  restore(): Promise<Session | null>;
  /** Creates a new anonymous account with a passkey and signs in on this device. */
  signUp(): Promise<SignUpResult>;
  /** Signs in with a passkey. */
  signIn(options?: { readonly immediate?: false }): Promise<Session>;
  /** Signs in with a passkey; resolves to `null` in immediate mode when no passkey is available. */
  signIn(options: SignInOptions): Promise<Session | null>;
  /** Whether `signIn({ immediate: true })` can use Immediate UI mode in this browser. */
  isImmediateSignInAvailable(): Promise<boolean>;
  /**
   * `fetch` with a DPoP-bound access token for `init.resource` (or
   * `defaultResource`). The request URL must be on the resource's origin and
   * use https (http only for loopback). Redirects are not followed unless
   * `init.redirect` says otherwise (a DPoP proof is bound to one URL).
   *
   * @throws StepUpRequiredError when the resource requires a recent passkey ceremony.
   */
  fetch(input: RequestInfo | URL, init?: AuthFetchInit): Promise<Response>;
  /** Signs out on this device: destroys the device key and every token (protocol §6.3). */
  signOut(): Promise<void>;
  /** Revokes every session of the account on every device, then signs out here. */
  signOutEverywhere(): Promise<void>;
  getAccount(): Promise<Account>;
  /** Registers an additional passkey (step-up handled automatically). */
  addPasskey(): Promise<Passkey>;
  /** Removes a passkey (step-up handled automatically). */
  removePasskey(credentialId: string): Promise<void>;
  /** Replaces the recovery code and returns the new one (step-up handled automatically). */
  rotateRecoveryCode(): Promise<string>;
  /**
   * Recovers an account with its recovery code: registers a new passkey that
   * replaces all others, revokes every session and returns a new recovery code.
   */
  recover(recoveryCode: string): Promise<RecoverResult>;
  /** Deletes the account (step-up handled automatically) and signs out. */
  deleteAccount(): Promise<void>;
  /** Subscribes to sign-in / sign-out (also from other tabs). Returns an unsubscribe function. */
  onChange(listener: ChangeListener): () => void;
  /** Releases the client's cross-tab channel and database connection. */
  close(): void;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

const LOCK_PREFIX = '@eric-minassian/auth-web';
const DEFAULT_STORAGE_NAME = 'auth-web';
/** Refresh access tokens this long before they expire. */
const ACCESS_TOKEN_MARGIN_MS = 30_000;
const CLIENT_ID_SYNTAX = /^[A-Za-z0-9._~-]{1,64}$/;

interface ActiveSession {
  readonly key: DeviceKey;
  readonly refreshToken: string;
  readonly refreshExpiresAt: number | null;
  readonly accountId: string;
  readonly rpId: string | null;
}

interface AccessToken {
  readonly token: string;
  /** Local epoch ms. */
  readonly expiresAt: number;
  /** The key the token is bound to (`cnf.jkt`). */
  readonly key: DeviceKey;
}

interface CallResult {
  readonly response: Response;
  readonly json: unknown;
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '[::1]' ||
    /^127(?:\.\d{1,3}){3}$/.test(hostname)
  );
}

function isSecureUrl(url: URL): boolean {
  return url.protocol === 'https:' || (url.protocol === 'http:' && isLoopbackHost(url.hostname));
}

function parseIssuer(issuer: unknown): string {
  if (typeof issuer !== 'string') {
    throw new TypeError('issuer must be a string');
  }
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    throw new TypeError('issuer must be an absolute URL');
  }
  if (!isSecureUrl(url)) {
    throw new TypeError('issuer must use https (http is only allowed for loopback hosts)');
  }
  if (url.username !== '' || url.password !== '' || issuer.includes('?') || issuer.includes('#')) {
    throw new TypeError('issuer must not contain credentials, a query or a fragment');
  }
  const canonical = url.origin + (url.pathname === '/' ? '' : url.pathname);
  if (canonical !== issuer || canonical.endsWith('/')) {
    throw new TypeError(
      `issuer must be canonical, without a trailing slash (e.g. "${canonical.replace(/\/+$/, '')}")`,
    );
  }
  return issuer;
}

function parseResource(resource: unknown, what: string): string {
  if (typeof resource !== 'string') {
    throw new TypeError(`${what} must be a string`);
  }
  let url: URL;
  try {
    url = new URL(resource);
  } catch {
    throw new TypeError(`${what} must be an absolute URI (RFC 8707)`);
  }
  if (resource.includes('#') || url.hash !== '') {
    throw new TypeError(`${what} must not contain a fragment (RFC 8707)`);
  }
  return resource;
}

/**
 * Refuses to send an access token where it does not belong: over plaintext
 * http to a non-loopback host, or to a different origin than the resource's.
 */
function assertTokenDestination(url: URL, resource: string): void {
  if (!isSecureUrl(url)) {
    throw new TypeError('refusing to send an access token over an insecure connection');
  }
  const resourceUrl = new URL(resource);
  if (
    (resourceUrl.protocol === 'https:' || resourceUrl.protocol === 'http:') &&
    resourceUrl.origin !== url.origin
  ) {
    throw new TypeError(
      `refusing to send an access token for ${resourceUrl.origin} to ${url.origin}; pass the matching "resource"`,
    );
  }
}

function reportListenerError(error: unknown): void {
  const report = (globalThis as { reportError?: (e: unknown) => void }).reportError;
  if (typeof report === 'function') {
    report(error);
  } else {
    setTimeout(() => {
      throw error;
    }, 0);
  }
}

class AuthClientImpl implements AuthClient {
  readonly issuer: string;
  readonly #clientId: string;
  readonly #defaultResource: string | undefined;
  /** Audience of the access token obtained with a new session. */
  readonly #sessionResource: string;
  readonly #store: IndexedDbSessionStore;
  readonly #lockName: string;
  readonly #clock = new ServerClock();
  readonly #transport: DpopTransport;
  readonly #refreshFlight = new SingleFlight<string>();
  readonly #clockFlight = new SingleFlight<'clock'>();
  readonly #issuerOrigin: string;
  readonly #accessTokens = new Map<string, AccessToken>();
  readonly #listeners = new Set<ChangeListener>();
  readonly #channel: BroadcastChannel | undefined;
  #active: ActiveSession | null = null;
  #lastEmitted: string | null = null;

  constructor(options: AuthClientOptions) {
    if (typeof options !== 'object' || (options as unknown) === null) {
      throw new TypeError('createAuthClient requires an options object');
    }
    this.issuer = parseIssuer(options.issuer);
    const clientId = options.clientId ?? 'web';
    if (typeof clientId !== 'string' || !CLIENT_ID_SYNTAX.test(clientId)) {
      throw new TypeError('clientId must be a short identifier');
    }
    this.#clientId = clientId;
    this.#defaultResource =
      options.defaultResource === undefined
        ? undefined
        : parseResource(options.defaultResource, 'defaultResource');
    this.#sessionResource = this.#defaultResource ?? this.issuer;

    const storageName = options.storageName ?? DEFAULT_STORAGE_NAME;
    if (typeof storageName !== 'string' || storageName.length === 0) {
      throw new TypeError('storageName must be a non-empty string');
    }
    // One record per (client, issuer) so several configurations can coexist.
    const recordKey = `${clientId} ${this.issuer}`;
    this.#store = new IndexedDbSessionStore(storageName, recordKey);
    this.#lockName = `${LOCK_PREFIX}:${storageName}:${recordKey}`;

    let fetchImpl: FetchLike;
    if (options.fetch !== undefined) {
      if (typeof options.fetch !== 'function') {
        throw new TypeError('fetch must be a function');
      }
      fetchImpl = options.fetch;
    } else {
      const globalFetch = (globalThis as { fetch?: typeof fetch }).fetch;
      if (typeof globalFetch !== 'function') {
        throw new TypeError('no fetch implementation available');
      }
      // Call unbound to avoid "Illegal invocation" in browsers.
      fetchImpl = (request) => globalFetch.call(globalThis, request);
    }
    this.#issuerOrigin = new URL(this.issuer).origin;
    this.#transport = new DpopTransport(fetchImpl, this.#clock, this.#issuerOrigin);

    if (typeof BroadcastChannel === 'function') {
      this.#channel = new BroadcastChannel(this.#lockName);
      this.#channel.onmessage = (event: MessageEvent<unknown>) => {
        if (isObject(event.data) && event.data['type'] === 'session-changed') {
          this.#syncFromStore().catch(() => undefined);
        }
      };
    }
  }

  get session(): Session | null {
    return this.#active === null ? null : { accountId: this.#active.accountId };
  }

  // -------------------------------------------------------------------------
  // Session state
  // -------------------------------------------------------------------------

  #setActive(next: ActiveSession | null): void {
    if (next?.key.jkt !== this.#active?.key.jkt) {
      // Access tokens are bound to the previous key; they are useless now.
      this.#accessTokens.clear();
    }
    this.#active = next;
    this.#emit();
  }

  #emit(): void {
    const id = this.#active?.accountId ?? null;
    if (id === this.#lastEmitted) {
      return;
    }
    this.#lastEmitted = id;
    const session = this.session;
    for (const listener of [...this.#listeners]) {
      try {
        listener(session);
      } catch (error) {
        reportListenerError(error);
      }
    }
  }

  #broadcast(): void {
    try {
      this.#channel?.postMessage({ type: 'session-changed' });
    } catch {
      // Closed channel: nothing to notify.
    }
  }

  static async #recordJkt(record: StoredSession): Promise<string> {
    return jwkThumbprint(await exportEcPublicJwk(record.publicKey));
  }

  /** Loads the stored session (possibly written by another tab) and adopts it. */
  async #syncFromStore(): Promise<ActiveSession | null> {
    const record = await this.#store.load();
    if (record === undefined) {
      this.#setActive(null);
      return null;
    }
    const current = this.#active;
    if (
      current !== null &&
      current.refreshToken === record.refreshToken &&
      current.key.jkt === (await AuthClientImpl.#recordJkt(record))
    ) {
      return current;
    }
    let key: DeviceKey;
    try {
      key = await deviceKeyFromPair(record.privateKey, record.publicKey);
    } catch {
      // Not a non-extractable P-256 key: never use it.
      await this.#store.clear();
      this.#setActive(null);
      return null;
    }
    const next: ActiveSession = {
      key,
      refreshToken: record.refreshToken,
      refreshExpiresAt: record.refreshExpiresAt,
      accountId: record.accountId,
      rpId: record.rpId,
    };
    this.#setActive(next);
    return next;
  }

  async #requireActive(): Promise<ActiveSession> {
    const active = this.#active ?? (await this.#syncFromStore());
    if (active === null) {
      throw new AuthError('not_signed_in', 'there is no session on this device');
    }
    return active;
  }

  static #toRecord(session: ActiveSession): StoredSession {
    return {
      v: 1,
      privateKey: session.key.privateKey,
      publicKey: session.key.publicKey,
      refreshToken: session.refreshToken,
      refreshExpiresAt: session.refreshExpiresAt,
      accountId: session.accountId,
      rpId: session.rpId,
    };
  }

  /** Persists a session that was just established by a passkey ceremony. */
  async #startSession(
    key: DeviceKey,
    tokens: TokenSet,
    accountId: string,
    rpId: string | null,
  ): Promise<Session> {
    const now = this.#clock.localNow();
    const next: ActiveSession = {
      key,
      refreshToken: tokens.refreshToken,
      refreshExpiresAt:
        tokens.refreshExpiresIn === undefined ? null : now + tokens.refreshExpiresIn * 1000,
      accountId,
      rpId,
    };
    await withExclusiveLock(this.#lockName, async () => {
      await this.#store.save(AuthClientImpl.#toRecord(next));
      this.#refreshFlight.clear();
      this.#setActive(next);
      this.#accessTokens.set(this.#sessionResource, {
        token: tokens.accessToken,
        expiresAt: now + tokens.expiresIn * 1000,
        key,
      });
    });
    this.#broadcast();
    return { accountId };
  }

  /** Destroys the local session. The caller must hold the lock. */
  async #wipeLocked(): Promise<void> {
    try {
      await this.#store.clear();
    } finally {
      this.#refreshFlight.clear();
      this.#setActive(null);
      this.#broadcast();
    }
  }

  // -------------------------------------------------------------------------
  // HTTP
  // -------------------------------------------------------------------------

  #request(
    path: string,
    method: 'GET' | 'POST' | 'DELETE',
    body?: URLSearchParams | object,
  ): Request {
    const headers = new Headers({ Accept: 'application/json' });
    let payload: string | null = null;
    if (body instanceof URLSearchParams) {
      headers.set('Content-Type', 'application/x-www-form-urlencoded');
      payload = body.toString();
    } else if (body !== undefined) {
      headers.set('Content-Type', 'application/json');
      payload = JSON.stringify(body);
    }
    return new Request(this.issuer + path, {
      method,
      headers,
      body: payload,
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      // The auth service never learns which page the user is on.
      referrerPolicy: 'no-referrer',
    });
  }

  /** Calls a token-style auth-service endpoint, with a DPoP proof when `key` is given. */
  async #call(path: string, body: URLSearchParams | object, key?: DeviceKey): Promise<CallResult> {
    const response = await this.#transport.send(this.#request(path, 'POST', body), { key });
    return { response, json: await readJson(response) };
  }

  static #ok(result: CallResult): unknown {
    if (!result.response.ok) {
      throw errorFromResponse(result.response, result.json);
    }
    return result.json;
  }

  #invalidateAccessToken(resource: string, token: string): void {
    if (this.#accessTokens.get(resource)?.token === token) {
      this.#accessTokens.delete(resource);
    }
  }

  async #accessToken(resource: string): Promise<AccessToken> {
    const cached = this.#accessTokens.get(resource);
    if (
      cached !== undefined &&
      cached.expiresAt - ACCESS_TOKEN_MARGIN_MS > this.#clock.localNow()
    ) {
      return cached;
    }
    return this.#refreshFlight.run(resource, () => this.#refresh(resource));
  }

  /** Obtains a new access token with the refresh token (protocol §10.5). */
  #refresh(resource: string): Promise<AccessToken> {
    return withExclusiveLock(this.#lockName, async () => {
      // Another tab may have signed out, signed in or refreshed meanwhile.
      const active = await this.#syncFromStore();
      if (active === null) {
        throw new AuthError('not_signed_in', 'there is no session on this device');
      }
      const now = this.#clock.localNow();
      const cached = this.#accessTokens.get(resource);
      if (cached?.key.jkt === active.key.jkt && cached.expiresAt - ACCESS_TOKEN_MARGIN_MS > now) {
        return cached;
      }
      if (active.refreshExpiresAt !== null && now >= active.refreshExpiresAt) {
        await this.#wipeLocked();
        throw new AuthError('invalid_grant', 'the session has expired');
      }
      const result = await this.#call(
        '/v1/token',
        new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: active.refreshToken,
          client_id: this.#clientId,
          resource,
        }),
        active.key,
      );
      if (!result.response.ok) {
        const error = errorFromResponse(result.response, result.json);
        if (error.code === 'invalid_grant') {
          // Expired, revoked (sign out everywhere, passkey removed, recovery)
          // or account deleted: the session is dead.
          await this.#wipeLocked();
        }
        throw error;
      }
      const tokens = parseTokenResponse(result.json);
      const receivedAt = this.#clock.localNow();
      const next: ActiveSession = {
        ...active,
        refreshToken: tokens.refreshToken,
        refreshExpiresAt:
          tokens.refreshExpiresIn === undefined
            ? active.refreshExpiresAt
            : receivedAt + tokens.refreshExpiresIn * 1000,
      };
      // Without the Web Locks API another tab could have replaced the session
      // during the request: never resurrect a record that changed.
      const stored = await this.#store.load();
      if (stored === undefined || (await AuthClientImpl.#recordJkt(stored)) !== active.key.jkt) {
        await this.#syncFromStore();
        throw new AuthError('not_signed_in', 'the session changed during refresh');
      }
      await this.#store.save(AuthClientImpl.#toRecord(next));
      this.#active = next;
      const entry: AccessToken = {
        token: tokens.accessToken,
        expiresAt: receivedAt + tokens.expiresIn * 1000,
        key: active.key,
      };
      this.#accessTokens.set(resource, entry);
      return entry;
    });
  }

  /**
   * Re-estimates the server clock from a fresh auth-service response (the RFC
   * 8414 metadata, fetched with `no-store`). Returns whether the estimate moved
   * enough to explain a rejected proof `iat`.
   */
  #resyncClock(): Promise<boolean> {
    return this.#clockFlight.run('clock', async () => {
      const issuer = new URL(this.issuer);
      // RFC 8414 §3.1: the well-known segment goes between host and issuer path.
      const url = `${issuer.origin}/.well-known/oauth-authorization-server${issuer.pathname === '/' ? '' : issuer.pathname}`;
      const before = this.#clock.offsetMs;
      try {
        const response = await this.#transport.send(
          new Request(url, {
            headers: { Accept: 'application/json' },
            mode: 'cors',
            credentials: 'omit',
            cache: 'no-store',
            redirect: 'error',
            referrerPolicy: 'no-referrer',
          }),
        );
        await response.body?.cancel().catch(() => undefined);
      } catch {
        return false;
      }
      return Math.abs(this.#clock.offsetMs - before) >= CLOCK_RETRY_THRESHOLD_MS;
    });
  }

  /**
   * Sends `base` with an access token for `resource`. Retries once if a
   * resource server rejected the proof and the clock estimate was stale;
   * refreshes and retries once on `invalid_token`; throws
   * `StepUpRequiredError` on `insufficient_user_authentication`.
   */
  async #resourceFetch(base: Request, resource: string): Promise<Response> {
    let token = await this.#accessToken(resource);
    let response = await this.#transport.send(base, { key: token.key, accessToken: token.token });
    if (
      response.status === 401 &&
      new URL(base.url).origin !== this.#issuerOrigin &&
      dpopChallenge(response.headers)?.error === 'invalid_dpop_proof' &&
      (await this.#resyncClock())
    ) {
      // The auth service's own responses already carry its Date; resource
      // servers' may be absent or cached, so their rejections trigger a resync.
      await response.body?.cancel().catch(() => undefined);
      response = await this.#transport.send(base, { key: token.key, accessToken: token.token });
    }
    if (response.status === 401 && dpopChallenge(response.headers)?.error === 'invalid_token') {
      this.#invalidateAccessToken(resource, token.token);
      await response.body?.cancel().catch(() => undefined);
      token = await this.#accessToken(resource);
      response = await this.#transport.send(base, { key: token.key, accessToken: token.token });
    }
    if (response.status === 401) {
      const challenge = dpopChallenge(response.headers);
      if (challenge?.error === 'insufficient_user_authentication') {
        await response.body?.cancel().catch(() => undefined);
        const options: { status: number; description?: string; maxAge?: number } = { status: 401 };
        if (challenge.errorDescription !== undefined)
          options.description = challenge.errorDescription;
        if (challenge.maxAge !== undefined) options.maxAge = challenge.maxAge;
        throw new StepUpRequiredError(options);
      }
    }
    return response;
  }

  /** Calls the account API (resource = issuer, protocol §10.7). */
  async #account(method: 'GET' | 'POST' | 'DELETE', path: string, body?: object): Promise<unknown> {
    const response = await this.#resourceFetch(this.#request(path, method, body), this.issuer);
    return AuthClientImpl.#ok({ response, json: await readJson(response) });
  }

  /** Runs `operation`; on `StepUpRequiredError` performs a passkey sign-in for the same account and retries once. */
  async #withStepUp<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (!(error instanceof StepUpRequiredError)) {
        throw error;
      }
      const active = await this.#requireActive();
      await this.#signIn(false, active.accountId);
      return operation();
    }
  }

  // -------------------------------------------------------------------------
  // WebAuthn
  // -------------------------------------------------------------------------

  static async #create(options: CreationOptionsJSON): Promise<RegistrationResponseJSON> {
    const container = credentialsContainer();
    let credential: Credential | null;
    try {
      credential = await container.create({ publicKey: toCreationOptions(options) });
    } catch (error) {
      throw ceremonyError(error);
    }
    if (credential === null) {
      throw new AuthError('ceremony_failed', 'no passkey was created');
    }
    return registrationResponseToJSON(credential);
  }

  static async #get(
    options: RequestOptionsJSON,
    immediate: boolean,
  ): Promise<AuthenticationResponseJSON | null> {
    const container = credentialsContainer();
    const request: ImmediateCredentialRequestOptions = { publicKey: toRequestOptions(options) };
    if (immediate) {
      // Only set after feature detection; no `signal` (invalid in immediate mode).
      request.uiMode = 'immediate';
    }
    let credential: Credential | null;
    try {
      credential = await container.get(request);
    } catch (error) {
      if (immediate && isNotAllowed(error)) {
        // No passkey on this device (or the user dismissed the immediate UI).
        return null;
      }
      throw ceremonyError(error);
    }
    if (credential === null) {
      if (immediate) {
        return null;
      }
      throw new AuthError('ceremony_failed', 'no passkey was returned');
    }
    return authenticationResponseToJSON(credential);
  }

  /** After a definitive 4xx, a freshly created passkey belongs to nothing: ask the credential manager to drop it. */
  static async #discardOrphan(
    error: unknown,
    rpId: string | undefined,
    credentialId: string,
  ): Promise<void> {
    if (
      rpId !== undefined &&
      error instanceof AuthError &&
      error.status !== undefined &&
      error.status >= 400 &&
      error.status < 500
    ) {
      await signalUnknownCredential(rpId, credentialId);
    }
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  async restore(): Promise<Session | null> {
    const active = await this.#syncFromStore();
    if (active === null) {
      return null;
    }
    try {
      await this.#accessToken(this.#sessionResource);
    } catch (error) {
      if (
        error instanceof AuthError &&
        (error.code === 'invalid_grant' || error.code === 'not_signed_in')
      ) {
        return null;
      }
      throw error;
    }
    return this.session;
  }

  async signUp(): Promise<SignUpResult> {
    credentialsContainer();
    // The ceremony is bound to this device key from the options request on
    // (protocol §8), so the passkey response cannot be redeemed with any other key.
    const key = await generateDeviceKey();
    const publicKey = parseCreationOptionsJSON(
      publicKeyMember(AuthClientImpl.#ok(await this.#call('/v1/register/options', {}, key))),
    );
    const credential = await AuthClientImpl.#create(publicKey);
    const result = await this.#call(
      '/v1/register/verify',
      { client_id: this.#clientId, resource: this.#sessionResource, credential },
      key,
    );
    let body: unknown;
    try {
      body = AuthClientImpl.#ok(result);
    } catch (error) {
      await AuthClientImpl.#discardOrphan(error, publicKey.rp.id, credential.id);
      throw error;
    }
    const tokens = parseTokenResponse(body);
    const obj = expectObject(body, 'register response');
    const accountId = expectBase64url(
      obj,
      'account_id',
      'register response',
      ACCOUNT_ID_BYTES,
      ACCOUNT_ID_BYTES,
    );
    if (accountId !== publicKey.user.id) {
      throw invalid('account_id does not match the user handle of the new passkey');
    }
    const recoveryCode = expectRecoveryCode(obj, 'recovery_code', 'register response');
    await this.#startSession(key, tokens, accountId, publicKey.rp.id ?? null);
    return { accountId, recoveryCode };
  }

  signIn(options?: { readonly immediate?: false }): Promise<Session>;
  signIn(options: SignInOptions): Promise<Session | null>;
  signIn(options: SignInOptions = {}): Promise<Session | null> {
    return this.#signIn(options.immediate === true);
  }

  async #signIn(immediate: boolean, requireAccountId?: string): Promise<Session | null> {
    if (immediate && !(await isImmediateGetAvailable())) {
      return null;
    }
    credentialsContainer();
    // Bound to this device key from the options request on (protocol §8).
    const key = await generateDeviceKey();
    const publicKey = parseRequestOptionsJSON(
      publicKeyMember(AuthClientImpl.#ok(await this.#call('/v1/login/options', {}, key))),
    );
    const assertion = await AuthClientImpl.#get(publicKey, immediate);
    if (assertion === null) {
      return null;
    }
    const userHandle = assertion.response.userHandle;
    if (!isBase64url(userHandle, ACCOUNT_ID_BYTES, ACCOUNT_ID_BYTES)) {
      throw new AuthError('credential_invalid', 'the passkey did not return a valid user handle');
    }
    if (requireAccountId !== undefined && userHandle !== requireAccountId) {
      // Never let a step-up silently switch accounts (the retried operation
      // would then act on the other account).
      throw new AuthError('account_mismatch', 'the passkey belongs to a different account');
    }
    const result = await this.#call(
      '/v1/login/verify',
      { client_id: this.#clientId, resource: this.#sessionResource, credential: assertion },
      key,
    );
    if (!result.response.ok) {
      const error = errorFromResponse(result.response, result.json);
      if (error.code === 'unknown_credential' && publicKey.rpId !== undefined) {
        const reported = isObject(result.json) ? result.json['credential_id'] : undefined;
        if (reported === assertion.id) {
          await signalUnknownCredential(publicKey.rpId, assertion.id);
        }
      }
      throw error;
    }
    return this.#startSession(
      key,
      parseTokenResponse(result.json),
      userHandle,
      publicKey.rpId ?? null,
    );
  }

  isImmediateSignInAvailable(): Promise<boolean> {
    return isImmediateGetAvailable();
  }

  async fetch(input: RequestInfo | URL, init: AuthFetchInit = {}): Promise<Response> {
    const { resource: requested, ...requestInit } = init;
    const resource =
      requested === undefined ? this.#defaultResource : parseResource(requested, 'resource');
    if (resource === undefined) {
      throw new TypeError('no resource: pass init.resource or configure defaultResource');
    }
    requestInit.redirect ??= 'error';
    const base = new Request(input, requestInit);
    assertTokenDestination(new URL(base.url), resource);
    return this.#resourceFetch(base, resource);
  }

  async signOut(): Promise<void> {
    await withExclusiveLock(this.#lockName, () => this.#wipeLocked());
  }

  async signOutEverywhere(): Promise<void> {
    await this.#account('POST', '/v1/account/logout-all', {});
    await this.signOut();
  }

  async getAccount(): Promise<Account> {
    const active = await this.#requireActive();
    const account = parseAccount(await this.#account('GET', '/v1/account'));
    if (account.accountId !== active.accountId) {
      throw invalid('account_id does not match the session');
    }
    if (active.rpId !== null) {
      await signalAllAcceptedCredentials(
        active.rpId,
        account.accountId,
        account.passkeys.map((p) => p.credentialId),
      );
    }
    return account;
  }

  addPasskey(): Promise<Passkey> {
    return this.#withStepUp(async () => {
      const active = await this.#requireActive();
      credentialsContainer();
      const publicKey = parseCreationOptionsJSON(
        publicKeyMember(await this.#account('POST', '/v1/account/passkeys/options', {})),
      );
      if (publicKey.user.id !== active.accountId) {
        throw invalid('passkey options are for a different account');
      }
      const credential = await AuthClientImpl.#create(publicKey);
      try {
        return parsePasskey(
          await this.#account('POST', '/v1/account/passkeys/verify', { credential }),
        );
      } catch (error) {
        await AuthClientImpl.#discardOrphan(error, publicKey.rp.id, credential.id);
        throw error;
      }
    });
  }

  async removePasskey(credentialId: string): Promise<void> {
    if (!isBase64url(credentialId, 1, 1023)) {
      throw new TypeError('credentialId must be a base64url credential ID');
    }
    await this.#withStepUp(() => this.#account('DELETE', `/v1/account/passkeys/${credentialId}`));
    const rpId = this.#active?.rpId;
    if (rpId !== undefined && rpId !== null) {
      await signalUnknownCredential(rpId, credentialId);
    }
  }

  rotateRecoveryCode(): Promise<string> {
    return this.#withStepUp(async () => {
      const body = expectObject(
        await this.#account('POST', '/v1/account/recovery-code', {}),
        'recovery code response',
      );
      return expectRecoveryCode(body, 'recovery_code', 'recovery code response');
    });
  }

  async recover(recoveryCode: string): Promise<RecoverResult> {
    const normalized = normalizeRecoveryCode(recoveryCode);
    if (normalized === undefined) {
      throw invalidRecoveryCode();
    }
    credentialsContainer();
    // Bound to this device key from the options request on (protocol §8).
    const key = await generateDeviceKey();
    const publicKey = parseCreationOptionsJSON(
      publicKeyMember(
        AuthClientImpl.#ok(
          await this.#call('/v1/recover/options', { recovery_code: normalized }, key),
        ),
      ),
    );
    const credential = await AuthClientImpl.#create(publicKey);
    const result = await this.#call(
      '/v1/recover/verify',
      { client_id: this.#clientId, resource: this.#sessionResource, credential },
      key,
    );
    let body: unknown;
    try {
      body = AuthClientImpl.#ok(result);
    } catch (error) {
      await AuthClientImpl.#discardOrphan(error, publicKey.rp.id, credential.id);
      throw error;
    }
    const tokens = parseTokenResponse(body);
    const newCode = expectRecoveryCode(
      expectObject(body, 'recover response'),
      'recovery_code',
      'recover response',
    );
    const accountId = publicKey.user.id;
    const rpId = publicKey.rp.id ?? null;
    await this.#startSession(key, tokens, accountId, rpId);
    if (rpId !== null) {
      // Every other passkey of the account was removed by the recovery.
      await signalAllAcceptedCredentials(rpId, accountId, [credential.id]);
    }
    return { accountId, recoveryCode: newCode };
  }

  async deleteAccount(): Promise<void> {
    await this.#withStepUp(() => this.#account('DELETE', '/v1/account'));
    const active = this.#active;
    if (active !== null && active.rpId !== null) {
      // No credential of this user is accepted any more.
      await signalAllAcceptedCredentials(active.rpId, active.accountId, []);
    }
    await this.signOut();
  }

  onChange(listener: ChangeListener): () => void {
    if (typeof listener !== 'function') {
      throw new TypeError('listener must be a function');
    }
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  close(): void {
    this.#channel?.close();
    this.#store.close();
  }
}

/** Creates an auth client. See {@link AuthClientOptions}. */
export function createAuthClient(options: AuthClientOptions): AuthClient {
  return new AuthClientImpl(options);
}
