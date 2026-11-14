import { describe, expect, test, vi } from 'vitest';
import { decode } from '../src/base64url.js';
import { createAuthClient, AuthError, StepUpRequiredError, type Session } from '../src/index.js';
import { generateDeviceKey, createDpopProof } from '../src/dpop.js';
import type { StoredSession } from '../src/store.js';
import { APP_ORIGIN, peekJwt, setup } from './harness.js';

const API = 'https://api.example.com';

async function readRecord(
  dbName = 'auth-web',
  key = 'web https://auth.example.com',
): Promise<StoredSession | undefined> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(dbName);
    req.onsuccess = () => {
      resolve(req.result);
    };
    req.onerror = () => {
      reject(new Error('open failed'));
    };
  });
  try {
    if (!db.objectStoreNames.contains('sessions')) return undefined;
    return await new Promise((resolve) => {
      const req = db.transaction('sessions').objectStore('sessions').get(key);
      req.onsuccess = () => {
        resolve(req.result as StoredSession | undefined);
      };
    });
  } finally {
    db.close();
  }
}

describe('createAuthClient', () => {
  test.each([
    'https://auth.example.com/',
    'https://Auth.example.com',
    'https://auth.example.com:443',
    'http://auth.example.com',
    'https://auth.example.com?x=1',
    'https://auth.example.com#f',
    'https://user:pw@auth.example.com',
    'auth.example.com',
    'https://auth.example.com/base/',
  ])('rejects issuer %j', (issuer) => {
    expect(() => createAuthClient({ issuer })).toThrow(TypeError);
  });

  test.each([
    'https://auth.example.com',
    'https://example.com/auth',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
  ])('accepts issuer %j', (issuer) => {
    createAuthClient({ issuer, fetch: () => Promise.reject(new Error('unused')) }).close();
  });

  test('validates clientId, defaultResource and fetch', () => {
    const issuer = 'https://auth.example.com';
    expect(() => createAuthClient({ issuer, clientId: 'has space' })).toThrow(TypeError);
    expect(() => createAuthClient({ issuer, defaultResource: '/relative' })).toThrow(TypeError);
    expect(() =>
      createAuthClient({ issuer, defaultResource: 'https://api.example.com#x' }),
    ).toThrow(TypeError);
    expect(() => createAuthClient({ issuer, fetch: 5 as never })).toThrow(TypeError);
  });
});

describe('signUp', () => {
  test('registers, persists a non-extractable device key and the refresh token, and signs in', async () => {
    const { client, server, authenticator } = await setup();
    const changes: (Session | null)[] = [];
    client.onChange((s) => changes.push(s));

    const { accountId, recoveryCode } = await client.signUp();

    expect(decode(accountId)).toHaveLength(16);
    expect(recoveryCode).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
    expect(server.accounts.get(accountId)?.credentials.size).toBe(1);
    expect(authenticator.credentials).toHaveLength(1);
    expect(client.session).toEqual({ accountId });
    expect(changes).toEqual([{ accountId }]);

    const record = await readRecord();
    expect(record?.accountId).toBe(accountId);
    expect(record?.rpId).toBe('example.com');
    expect(record?.privateKey).toBeInstanceOf(CryptoKey);
    expect(record?.privateKey.extractable).toBe(false);
    expect(record?.privateKey.type).toBe('private');
    expect(peekJwt(record?.refreshToken ?? '').header['typ']).toBe('rt+jwt');
    // Access tokens are never persisted.
    expect(JSON.stringify(Object.keys(record ?? {}))).not.toContain('access');
  });

  test('sends well-formed, privacy-preserving requests', async () => {
    const { client, server } = await setup();
    await client.signUp();
    const [options] = server.requestsTo('/v1/register/options');
    const verifies = server.requestsTo('/v1/register/verify');
    expect(options?.requestHeaders.get('dpop')).toBeNull();
    expect(options?.requestHeaders.get('authorization')).toBeNull();
    expect(JSON.parse(options?.requestBody ?? '')).toEqual({});
    expect(verifies).toHaveLength(1); // nonce from the options response, no retry needed
    const verify = verifies[0];
    expect(verify?.requestHeaders.get('content-type')).toBe('application/json');
    const body = JSON.parse(verify?.requestBody ?? '') as Record<string, unknown>;
    expect(body).toMatchObject({ client_id: 'web', resource: API });
    expect(body['credential']).toMatchObject({ type: 'public-key' });
    const proof = peekJwt(verify?.requestHeaders.get('dpop') ?? '');
    expect(proof.payload).toMatchObject({
      htm: 'POST',
      htu: 'https://auth.example.com/v1/register/verify',
    });
    expect(proof.payload['nonce']).toBe(options?.responseHeaders?.get('dpop-nonce'));
    expect(proof.payload['ath']).toBeUndefined();
    for (const exchange of server.exchanges) {
      expect(exchange.request.credentials).toBe('omit');
      expect(exchange.request.cache).toBe('no-store');
      expect(exchange.request.redirect).toBe('error');
      expect(exchange.request.referrerPolicy).toBe('no-referrer');
    }
  });

  test('passes the server options to the authenticator unchanged', async () => {
    const { client, authenticator } = await setup();
    await client.signUp();
    const call = authenticator.calls.find((c) => c.kind === 'create');
    const pk = (call?.options as CredentialCreationOptions).publicKey;
    expect(pk?.rp).toEqual({ id: 'example.com', name: 'Example' });
    expect(pk?.authenticatorSelection).toEqual({
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    });
    expect(pk?.attestation).toBe('none');
    expect(pk?.extensions).toEqual({ credProps: true });
    expect(pk?.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -8, -257]);
  });

  test('a cancelled prompt rejects with ceremony_cancelled and creates nothing', async () => {
    const { client, server, authenticator } = await setup();
    authenticator.onPrompt = () => false;
    await expect(client.signUp()).rejects.toMatchObject({ code: 'ceremony_cancelled' });
    expect(server.requestsTo('/v1/register/verify')).toHaveLength(0);
    expect(client.session).toBeNull();
    expect(await readRecord()).toBeUndefined();
  });

  test('a rejected registration signals the orphaned passkey as unknown', async () => {
    const { client, server, authenticator } = await setup();
    server.intercept = (_req, path) =>
      path === '/v1/register/verify'
        ? new Response(JSON.stringify({ error: 'webauthn_rejected' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          })
        : undefined;
    await expect(client.signUp()).rejects.toMatchObject({ code: 'webauthn_rejected', status: 400 });
    expect(authenticator.signals).toEqual([
      { kind: 'unknown', rpId: 'example.com', credentialId: expect.any(String) as string },
    ]);
    expect(authenticator.credentials).toHaveLength(0);
    expect(await readRecord()).toBeUndefined();
  });

  test('rejects a register response whose account_id differs from the passkey user handle', async () => {
    const { client, server } = await setup();
    server.intercept = async (req, path) => {
      if (path !== '/v1/register/verify') return undefined;
      server.intercept = undefined;
      const res = await server.fetch(req);
      const body = (await res.json()) as Record<string, unknown>;
      return new Response(JSON.stringify({ ...body, account_id: 'AAAAAAAAAAAAAAAAAAAAAA' }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });
    };
    await expect(client.signUp()).rejects.toMatchObject({ code: 'invalid_response' });
    expect(client.session).toBeNull();
  });

  test('fails with webauthn_unsupported without WebAuthn', async () => {
    const { client } = await setup();
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'PublicKeyCredential');
    Reflect.deleteProperty(globalThis, 'PublicKeyCredential');
    try {
      await expect(client.signUp()).rejects.toMatchObject({ code: 'webauthn_unsupported' });
      await expect(client.signIn()).rejects.toMatchObject({ code: 'webauthn_unsupported' });
    } finally {
      if (saved !== undefined) Object.defineProperty(globalThis, 'PublicKeyCredential', saved);
    }
  });
});

describe('signIn', () => {
  test('signs in with a discoverable passkey using a fresh device key', async () => {
    const { client, server } = await setup();
    const { accountId } = await client.signUp();
    const firstJkt = (await readRecord())?.publicKey;
    await client.signOut();
    const session = await client.signIn();
    expect(session).toEqual({ accountId });
    expect(server.stats.logins).toBe(1);
    const record = await readRecord();
    expect(record?.publicKey).not.toBe(firstJkt);
    const verify = server.requestsTo('/v1/login/verify')[0];
    const body = JSON.parse(verify?.requestBody ?? '') as {
      credential: { response: Record<string, string> };
    };
    expect(body.credential.response['userHandle']).toBe(accountId);
    // Fetching works with the new session.
    expect((await client.fetch(`${API}/hello`)).status).toBe(200);
  });

  test('unknown_credential: signals the credential manager and throws', async () => {
    const { client, server, authenticator } = await setup();
    await client.signUp();
    const credentialId =
      server.accounts.values().next().value?.credentials.keys().next().value ?? '';
    server.forgetCredential(credentialId);
    await client.signOut();
    await expect(client.signIn()).rejects.toMatchObject({
      code: 'unknown_credential',
      status: 401,
    });
    expect(authenticator.signals).toContainEqual({
      kind: 'unknown',
      rpId: 'example.com',
      credentialId,
    });
    expect(authenticator.credentials).toHaveLength(0);
    expect(client.session).toBeNull();
  });

  test('without the Signal API, unknown_credential still throws', async () => {
    const { client, server } = await setup({ authenticator: { signalApi: false } });
    await client.signUp();
    server.forgetCredential(
      server.accounts.values().next().value?.credentials.keys().next().value ?? '',
    );
    await expect(client.signIn()).rejects.toMatchObject({ code: 'unknown_credential' });
  });

  test('cancelled → ceremony_cancelled; other DOMExceptions → ceremony_failed', async () => {
    const { client, authenticator } = await setup();
    await expect(client.signIn()).rejects.toMatchObject({ code: 'ceremony_cancelled' }); // no passkeys
    await client.signUp();
    authenticator.get = () => Promise.reject(new DOMException('bad rp', 'SecurityError'));
    const error = await client.signIn().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthError);
    expect(error).toMatchObject({ code: 'ceremony_failed' });
    expect((error as AuthError).cause).toBeInstanceOf(DOMException);
  });

  test('maps server errors (rate limiting) to AuthError', async () => {
    const { client, server } = await setup();
    server.intercept = () => new Response(null, { status: 429 });
    await expect(client.signIn()).rejects.toMatchObject({ code: 'rate_limited', status: 429 });
  });
});

describe('Immediate UI mode', () => {
  test('unsupported browser: resolves null without prompting or calling the server', async () => {
    const { client, server, authenticator } = await setup({
      authenticator: { immediateGet: false },
    });
    await client.signUp();
    await client.signOut();
    const before = server.exchanges.length;
    expect(await client.isImmediateSignInAvailable()).toBe(false);
    expect(await client.signIn({ immediate: true })).toBeNull();
    expect(authenticator.calls.filter((c) => c.kind === 'get')).toHaveLength(0);
    expect(server.exchanges).toHaveLength(before);
  });

  test('no getClientCapabilities: not detected', async () => {
    const { client, authenticator } = await setup({
      authenticator: { immediateGet: true, clientCapabilities: false },
    });
    expect(await client.isImmediateSignInAvailable()).toBe(false);
    expect(await client.signIn({ immediate: true })).toBeNull();
    expect(authenticator.calls).toHaveLength(0);
  });

  test('supported, no passkey on this device: uiMode is passed and the result is null', async () => {
    const { client, authenticator } = await setup({ authenticator: { immediateGet: true } });
    let prompted = false;
    authenticator.onPrompt = () => {
      prompted = true;
      return true;
    };
    expect(await client.isImmediateSignInAvailable()).toBe(true);
    expect(await client.signIn({ immediate: true })).toBeNull();
    const options = authenticator.calls.at(-1)?.options as CredentialRequestOptions & {
      uiMode?: string;
    };
    expect(options.uiMode).toBe('immediate');
    expect(options.mediation).toBeUndefined();
    expect('signal' in options).toBe(false);
    expect(prompted).toBe(false);
  });

  test('supported, passkey present: signs in', async () => {
    const { client, authenticator } = await setup({ authenticator: { immediateGet: true } });
    const { accountId } = await client.signUp();
    await client.signOut();
    expect(await client.signIn({ immediate: true })).toEqual({ accountId });
    expect((authenticator.calls.at(-1)?.options as { uiMode?: string }).uiMode).toBe('immediate');
  });

  test('a regular signIn never sets uiMode', async () => {
    const { client, authenticator } = await setup({ authenticator: { immediateGet: true } });
    await client.signUp();
    await client.signIn();
    expect((authenticator.calls.at(-1)?.options as { uiMode?: string }).uiMode).toBeUndefined();
  });

  test('a non-NotAllowed failure in immediate mode still throws', async () => {
    const { client, authenticator } = await setup({ authenticator: { immediateGet: true } });
    authenticator.get = () => Promise.reject(new DOMException('x', 'SecurityError'));
    await expect(client.signIn({ immediate: true })).rejects.toMatchObject({
      code: 'ceremony_failed',
    });
  });
});

describe('restore', () => {
  test('returns null without a stored session', async () => {
    const { client, server } = await setup();
    expect(await client.restore()).toBeNull();
    expect(server.exchanges).toHaveLength(0);
  });

  test('restores silently in a new tab with one refresh', async () => {
    const { client, newTab, server, authenticator } = await setup();
    const { accountId } = await client.signUp();
    const tab = newTab();
    const changes: (Session | null)[] = [];
    tab.onChange((s) => changes.push(s));
    expect(await tab.restore()).toEqual({ accountId });
    expect(server.stats.refreshes).toBe(1);
    expect(authenticator.calls.filter((c) => c.kind === 'get')).toHaveLength(0); // no UI
    expect(changes).toEqual([{ accountId }]);
    // The refresh request is a proper RFC 6749 §6 / RFC 9449 §5 request.
    const refresh = server.requestsTo('/v1/token').at(-1);
    expect(refresh?.requestHeaders.get('content-type')).toBe('application/x-www-form-urlencoded');
    const form = new URLSearchParams(refresh?.requestBody);
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('client_id')).toBe('web');
    expect(form.get('resource')).toBe(API);
    expect(peekJwt(form.get('refresh_token') ?? '').header['typ']).toBe('rt+jwt');
    expect(peekJwt(refresh?.requestHeaders.get('dpop') ?? '').payload['ath']).toBeUndefined();
  });

  test('a revoked session (epoch changed) restores to null and is wiped', async () => {
    const { client, newTab, server } = await setup();
    const { accountId } = await client.signUp();
    const account = server.accounts.get(accountId);
    if (account) account.epoch++;
    const tab = newTab();
    expect(await tab.restore()).toBeNull();
    expect(await readRecord()).toBeUndefined();
    expect(tab.session).toBeNull();
  });

  test('a transient failure rejects and keeps the stored session', async () => {
    const { client, newTab, server } = await setup();
    await client.signUp();
    server.intercept = () => {
      throw new TypeError('fetch failed');
    };
    const tab = newTab();
    await expect(tab.restore()).rejects.toMatchObject({ code: 'network_error' });
    expect(await readRecord()).toBeDefined();
    server.intercept = () => new Response(null, { status: 503 });
    await expect(tab.restore()).rejects.toMatchObject({ code: 'server_error' });
    server.intercept = undefined;
    expect(await tab.restore()).not.toBeNull();
  });

  test('an unusable stored key (extractable) is discarded', async () => {
    const { client, newTab } = await setup();
    await client.signUp();
    const record = await readRecord();
    const extractable = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    await new Promise<void>((resolve) => {
      const req = indexedDB.open('auth-web');
      req.onsuccess = () => {
        const tx = req.result.transaction('sessions', 'readwrite');
        tx.objectStore('sessions').put(
          { ...record, privateKey: extractable.privateKey, publicKey: extractable.publicKey },
          'web https://auth.example.com',
        );
        tx.oncomplete = () => {
          req.result.close();
          resolve();
        };
      };
    });
    expect(await newTab().restore()).toBeNull();
    expect(await readRecord()).toBeUndefined();
  });

  test('a locally expired refresh token restores to null without a request', async () => {
    const { client, newTab, server } = await setup();
    await client.signUp();
    const before = server.exchanges.length;
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 31 * 24 * 3600 * 1000);
    expect(await newTab().restore()).toBeNull();
    expect(server.exchanges).toHaveLength(before);
    expect(await readRecord()).toBeUndefined();
  });
});

describe('fetch', () => {
  test('sends the access token with a DPoP proof bound to method, URL and token', async () => {
    const { client, server } = await setup();
    await client.signUp();
    const res = await client.fetch(`${API}/hello?q=1#frag`, { headers: { 'X-Test': '1' } });
    expect(res.status).toBe(200);
    const exchange = server.exchanges.at(-1);
    const auth = exchange?.requestHeaders.get('authorization') ?? '';
    expect(auth).toMatch(/^DPoP [\w-]+\.[\w-]+\.[\w-]+$/);
    const proof = peekJwt(exchange?.requestHeaders.get('dpop') ?? '').payload;
    expect(proof).toMatchObject({ htm: 'GET', htu: `${API}/hello` });
    expect(proof['ath']).toBeTypeOf('string');
    expect(exchange?.requestHeaders.get('x-test')).toBe('1');
    expect(exchange?.request.redirect).toBe('error');
    const token = peekJwt(auth.slice(5));
    expect(token.header['typ']).toBe('at+jwt');
    expect(token.payload['aud']).toBe(API);
  });

  test('retries once with the resource server nonce and replays the body', async () => {
    const { client, server } = await setup();
    await client.signUp();
    server.resourceRequiresNonce = true;
    const res = await client.fetch(`${API}/echo`, { method: 'POST', body: 'hello body' });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ body: 'hello body' });
    const attempts = server.requestsTo('/echo');
    expect(attempts.map((a) => a.status)).toEqual([401, 200]);
    // The next request uses the stored nonce right away.
    await client.fetch(`${API}/hello`);
    expect(server.requestsTo('/hello').map((a) => a.status)).toEqual([200]);
  });

  test('accepts a Request object as input', async () => {
    const { client, server } = await setup();
    await client.signUp();
    server.resourceRequiresNonce = true;
    const res = await client.fetch(
      new Request(`${API}/echo`, { method: 'POST', body: 'from request' }),
    );
    expect(await res.json()).toMatchObject({ body: 'from request' });
  });

  test('on invalid_token refreshes once and retries', async () => {
    const { client, server } = await setup();
    await client.signUp();
    server.revokeAccessTokens();
    const res = await client.fetch(`${API}/hello`);
    expect(res.status).toBe(200);
    expect(server.stats.refreshes).toBe(1);
    expect(server.requestsTo('/hello').map((e) => e.status)).toEqual([401, 200]);
  });

  test('returns the final 401 when the retried token is rejected too', async () => {
    const { client, server } = await setup();
    await client.signUp();
    server.intercept = (_req, path) =>
      path === '/hello'
        ? new Response(null, {
            status: 401,
            headers: { 'WWW-Authenticate': 'DPoP error="invalid_token"' },
          })
        : undefined;
    const res = await client.fetch(`${API}/hello`);
    expect(res.status).toBe(401);
    expect(server.requestsTo('/hello')).toHaveLength(2);
    expect(server.stats.refreshes).toBe(1);
  });

  test('refresh is single-flight within a tab', async () => {
    const { client, newTab, server } = await setup();
    await client.signUp();
    const tab = newTab();
    const responses = await Promise.all(Array.from({ length: 8 }, () => tab.fetch(`${API}/hello`)));
    expect(responses.every((r) => r.status === 200)).toBe(true);
    expect(server.stats.refreshes).toBe(1);
  });

  test('keeps working after the access token expired and the server clock moved', async () => {
    const { client, server } = await setup();
    await client.signUp();
    server.advance(400); // access token (300 s) expired; nonce windows moved
    const res = await client.fetch(`${API}/hello`);
    expect(res.status).toBe(200);
    expect(server.stats.refreshes).toBe(1);
  });

  test('throws StepUpRequiredError when the resource demands a recent sign-in', async () => {
    const { client, server } = await setup();
    await client.signUp();
    expect((await client.fetch(`${API}/sensitive`)).status).toBe(200);
    server.advance(301);
    const error = await client.fetch(`${API}/sensitive`).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StepUpRequiredError);
    expect(error).toMatchObject({
      code: 'insufficient_user_authentication',
      maxAge: 300,
      status: 401,
    });
    await client.signIn();
    expect((await client.fetch(`${API}/sensitive`)).status).toBe(200);
  });

  test('refuses to send tokens to another origin or over plaintext http', async () => {
    const { client, server } = await setup();
    await client.signUp();
    const before = server.exchanges.length;
    await expect(client.fetch('https://evil.example/steal')).rejects.toThrow(TypeError);
    await expect(client.fetch('http://api.example.com/hello')).rejects.toThrow(TypeError);
    await expect(
      client.fetch(`${API}/hello`, { resource: 'https://other.example.com' }),
    ).rejects.toThrow(TypeError);
    expect(server.exchanges).toHaveLength(before);
  });

  test('requires a resource when no default is configured', async () => {
    const { newTab } = await setup();
    const tab = newTab({ defaultResource: undefined as never });
    await expect(tab.fetch(`${API}/hello`)).rejects.toThrow(/resource/);
  });

  test('without a session throws not_signed_in', async () => {
    const { client } = await setup();
    await expect(client.fetch(`${API}/hello`)).rejects.toMatchObject({ code: 'not_signed_in' });
  });

  test('requests the token for an explicit resource (RFC 8707)', async () => {
    const { client, server } = await setup({
      server: { audiences: [API, 'https://other.example.com'] },
    });
    await client.signUp();
    // The fake only hosts the first audience: the token request succeeds, the API call cannot connect.
    await expect(
      client.fetch('https://other.example.com/x', { resource: 'https://other.example.com' }),
    ).rejects.toMatchObject({ code: 'network_error' });
    const form = new URLSearchParams(server.requestsTo('/v1/token').at(-1)?.requestBody);
    expect(form.get('resource')).toBe('https://other.example.com');
  });
});

describe('clock skew (protocol §7.4)', () => {
  test.each([3600, -3600, 86_400])('works with a server clock off by %i s', async (skew) => {
    const { client, newTab, server } = await setup({ server: { clockSkewSeconds: skew } });
    await client.signUp();
    const proof = peekJwt(
      server.requestsTo('/v1/register/verify')[0]?.requestHeaders.get('dpop') ?? '',
    );
    expect(Math.abs((proof.payload['iat'] as number) - server.now())).toBeLessThanOrEqual(5);
    // A fresh tab has no estimate yet: its first proof is rejected for iat, corrected and retried.
    const tab = newTab();
    expect(await tab.restore()).not.toBeNull();
    expect((await tab.fetch(`${API}/hello`)).status).toBe(200);
  });

  test('ignores the resource server Date header', async () => {
    const { client, server } = await setup();
    await client.signUp();
    server.resourceDateSkewSeconds = 7200;
    await client.fetch(`${API}/hello`);
    await client.fetch(`${API}/hello`);
    const proof = peekJwt(server.exchanges.at(-1)?.requestHeaders.get('dpop') ?? '');
    expect(Math.abs((proof.payload['iat'] as number) - server.now())).toBeLessThanOrEqual(5);
  });
});

describe('signOut', () => {
  test('destroys the device key, the refresh token and the access tokens', async () => {
    const { client, server } = await setup();
    const changes: (Session | null)[] = [];
    const { accountId } = await client.signUp();
    client.onChange((s) => changes.push(s));
    const stolen = await readRecord();

    await client.signOut();

    expect(await readRecord()).toBeUndefined();
    expect(client.session).toBeNull();
    expect(changes).toEqual([null]);
    await expect(client.fetch(`${API}/hello`)).rejects.toMatchObject({ code: 'not_signed_in' });
    await expect(client.restore()).resolves.toBeNull();

    // A copy of the refresh token is useless without the (destroyed) device key.
    const attackerKey = await generateDeviceKey();
    const nonceRes = await server.fetch(`${server.issuer}/v1/login/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    const proof = await createDpopProof(attackerKey, {
      htm: 'POST',
      htu: `${server.issuer}/v1/token`,
      iat: server.now(),
      nonce: nonceRes.headers.get('dpop-nonce') ?? undefined,
    });
    const res = await server.fetch(`${server.issuer}/v1/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: proof },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: stolen?.refreshToken ?? '',
        client_id: 'web',
      }).toString(),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_grant' });
    expect(server.accounts.has(accountId)).toBe(true); // nothing server-side was needed
  });

  test('onChange unsubscribe stops notifications; listener errors do not break others', async () => {
    const { client } = await setup();
    const reported: unknown[] = [];
    vi.stubGlobal('reportError', (e: unknown) => reported.push(e));
    const calls: (Session | null)[] = [];
    client.onChange(() => {
      throw new Error('listener bug');
    });
    const unsubscribe = client.onChange((s) => calls.push(s));
    await client.signUp();
    unsubscribe();
    await client.signOut();
    expect(calls).toHaveLength(1);
    expect(reported).toHaveLength(2);
  });
});

describe('response validation', () => {
  test.each([
    ['token_type Bearer', { token_type: 'Bearer' }],
    ['missing refresh_token', { refresh_token: undefined }],
    ['access token with header-breaking characters', { access_token: 'abc\r\nX-Evil: 1' }],
    ['non-integer expires_in', { expires_in: 'soon' }],
  ])('rejects a token response with %s', async (_name, patch) => {
    const { client, server } = await setup();
    server.intercept = async (req, path) => {
      if (path !== '/v1/register/verify') return undefined;
      server.intercept = undefined;
      const body = (await (await server.fetch(req)).json()) as Record<string, unknown>;
      return new Response(JSON.stringify({ ...body, ...patch }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      });
    };
    await expect(client.signUp()).rejects.toMatchObject({ code: 'invalid_response' });
    expect(client.session).toBeNull();
    expect(await readRecord()).toBeUndefined();
  });

  test('rejects malformed options', async () => {
    const { client, server } = await setup();
    server.intercept = (_req, path) =>
      path === '/v1/login/options'
        ? new Response(JSON.stringify({ publicKey: { challenge: 'short' } }), {
            headers: { 'Content-Type': 'application/json' },
          })
        : undefined;
    await expect(client.signIn()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  test('a credential created on a non-allowed origin is rejected by the server', async () => {
    // Same host, different port: the browser allows the RP ID, the server's exact origin match does not.
    const { client, authenticator } = await setup({
      authenticator: { origin: 'https://app.example.com:8443' },
    });
    expect(authenticator.origin).not.toBe(APP_ORIGIN);
    await expect(client.signUp()).rejects.toMatchObject({ code: 'webauthn_rejected' });
    expect(client.session).toBeNull();
  });
});
