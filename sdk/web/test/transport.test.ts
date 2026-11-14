import { describe, expect, test, vi } from 'vitest';
import { ServerClock } from '../src/clock.js';
import { generateDeviceKey } from '../src/dpop.js';
import { AuthError, StepUpRequiredError } from '../src/errors.js';
import { DpopTransport, errorFromResponse, readJson } from '../src/transport.js';
import { peekJwt } from './harness.js';

const ISSUER = 'https://auth.example.com';

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function proofOf(request: Request) {
  const proof = request.headers.get('dpop');
  if (proof === null) throw new Error('no proof');
  return peekJwt(proof).payload;
}

describe('DpopTransport', () => {
  test('retries once on the 400 JSON use_dpop_nonce challenge with the new nonce', async () => {
    const seen: Request[] = [];
    const fetchImpl = vi.fn((request: Request) => {
      seen.push(request);
      return Promise.resolve(
        seen.length === 1
          ? json(400, { error: 'use_dpop_nonce' }, { 'DPoP-Nonce': 'nonce-1' })
          : json(200, { ok: true }, { 'DPoP-Nonce': 'nonce-2' }),
      );
    });
    const transport = new DpopTransport(fetchImpl, new ServerClock(), new URL(ISSUER).origin);
    const key = await generateDeviceKey();
    const response = await transport.send(
      new Request(`${ISSUER}/v1/token`, { method: 'POST', body: 'grant_type=refresh_token' }),
      { key },
    );
    expect(response.status).toBe(200);
    const [first, second] = seen;
    if (first === undefined || second === undefined) throw new Error('expected two attempts');
    expect(proofOf(first)['nonce']).toBeUndefined();
    expect(proofOf(second)['nonce']).toBe('nonce-1');
    expect(proofOf(first)['jti']).not.toBe(proofOf(second)['jti']);
    // The body is replayed on retry.
    expect(await second.text()).toBe('grant_type=refresh_token');
    expect(transport.nonceFor(new URL(ISSUER).origin)).toBe('nonce-2');
  });

  test('retries once on the 401 WWW-Authenticate use_dpop_nonce challenge', async () => {
    const seen: Request[] = [];
    const transport = new DpopTransport(
      (request) => {
        seen.push(request);
        return Promise.resolve(
          seen.length === 1
            ? new Response(null, {
                status: 401,
                headers: {
                  'WWW-Authenticate': 'DPoP error="use_dpop_nonce", algs="ES256"',
                  'DPoP-Nonce': 'rs-1',
                },
              })
            : new Response('ok'),
        );
      },
      new ServerClock(),
      new URL(ISSUER).origin,
    );
    const key = await generateDeviceKey();
    const response = await transport.send(new Request('https://api.example.com/x'), {
      key,
      accessToken: 'tok',
    });
    expect(response.status).toBe(200);
    expect(seen.map((r) => proofOf(r)['nonce'])).toEqual([undefined, 'rs-1']);
    expect(seen.every((r) => r.headers.get('authorization') === 'DPoP tok')).toBe(true);
    expect(seen.every((r) => typeof proofOf(r)['ath'] === 'string')).toBe(true);
  });

  test('retries at most once, and not without a new nonce', async () => {
    const challenge = () => json(400, { error: 'use_dpop_nonce' }, { 'DPoP-Nonce': 'same' });
    const fetchImpl = vi.fn(() => Promise.resolve(challenge()));
    const transport = new DpopTransport(fetchImpl, new ServerClock(), ISSUER);
    const key = await generateDeviceKey();
    const response = await transport.send(new Request(`${ISSUER}/v1/token`, { method: 'POST' }), {
      key,
    });
    expect(response.status).toBe(400);
    expect(fetchImpl).toHaveBeenCalledTimes(2); // second attempt already sent "same"; no third

    const noNonce = vi.fn(() => Promise.resolve(json(400, { error: 'use_dpop_nonce' })));
    const t2 = new DpopTransport(noNonce, new ServerClock(), ISSUER);
    expect(
      (await t2.send(new Request(`${ISSUER}/v1/token`, { method: 'POST' }), { key })).status,
    ).toBe(400);
    expect(noNonce).toHaveBeenCalledTimes(1);
  });

  test('ignores nonces with invalid syntax', async () => {
    const transport = new DpopTransport(
      () => Promise.resolve(new Response(null, { headers: { 'DPoP-Nonce': 'has space' } })),
      new ServerClock(),
      ISSUER,
    );
    await transport.send(new Request(`${ISSUER}/x`));
    expect(transport.nonceFor(ISSUER)).toBeUndefined();
  });

  test('corrects iat from the issuer Date header and retries an iat-rejected proof once', async () => {
    const serverOffset = 2 * 3600 * 1000; // server is two hours ahead
    const seen: Request[] = [];
    const clock = new ServerClock();
    const transport = new DpopTransport(
      (request) => {
        seen.push(request);
        const iat = proofOf(request)['iat'] as number;
        const serverNow = Math.floor((Date.now() + serverOffset) / 1000);
        const headers = { Date: new Date(serverNow * 1000).toUTCString(), 'DPoP-Nonce': 'n' };
        return Promise.resolve(
          Math.abs(iat - serverNow) > 120
            ? json(400, { error: 'invalid_dpop_proof' }, headers)
            : json(200, {}, headers),
        );
      },
      clock,
      ISSUER,
    );
    const key = await generateDeviceKey();
    const response = await transport.send(new Request(`${ISSUER}/v1/token`, { method: 'POST' }), {
      key,
    });
    expect(response.status).toBe(200);
    expect(seen).toHaveLength(2);
    expect(Math.abs(clock.offsetMs - serverOffset)).toBeLessThan(2000);
  });

  test('does not learn the clock from other origins', async () => {
    const clock = new ServerClock();
    const transport = new DpopTransport(
      () => Promise.resolve(new Response(null, { headers: { Date: new Date(0).toUTCString() } })),
      clock,
      ISSUER,
    );
    await transport.send(new Request('https://api.example.com/x'));
    expect(clock.offsetMs).toBe(0);
  });

  test('wraps network failures, but lets aborts through', async () => {
    const key = await generateDeviceKey();
    const failing = new DpopTransport(
      () => Promise.reject(new TypeError('fetch failed')),
      new ServerClock(),
      ISSUER,
    );
    await expect(failing.send(new Request(`${ISSUER}/x`), { key })).rejects.toMatchObject({
      code: 'network_error',
    });
    const aborting = new DpopTransport(
      () => Promise.reject(new DOMException('aborted', 'AbortError')),
      new ServerClock(),
      ISSUER,
    );
    await expect(aborting.send(new Request(`${ISSUER}/x`))).rejects.toMatchObject({
      name: 'AbortError',
    });
  });

  test('invokes the fetch implementation unbound', async () => {
    let receiver: unknown = 'unset';
    function strictFetch(this: unknown) {
      // eslint-disable-next-line @typescript-eslint/no-this-alias -- recording the receiver is the point of this test
      receiver = this;
      return Promise.resolve(new Response('ok'));
    }
    const transport = new DpopTransport(strictFetch, new ServerClock(), ISSUER);
    await transport.send(new Request(`${ISSUER}/x`));
    expect(receiver).toBeUndefined();
  });
});

describe('error mapping', () => {
  test.each([
    [400, { error: 'invalid_grant' }, 'invalid_grant'],
    [400, { error: 'webauthn_rejected', error_description: 'bad' }, 'webauthn_rejected'],
    [409, { error: 'too_many_passkeys' }, 'too_many_passkeys'],
    [409, { error: 'last_passkey' }, 'last_passkey'],
    [401, { error: 'unknown_credential', credential_id: 'AQ' }, 'unknown_credential'],
    [400, { error: 'something_new' }, 'unexpected_status'],
    [429, undefined, 'rate_limited'],
    [413, undefined, 'payload_too_large'],
    [500, undefined, 'server_error'],
    [503, { error: 'server_error' }, 'server_error'],
    [404, undefined, 'unexpected_status'],
  ])('%i %j -> %s', (status, body, code) => {
    const error = errorFromResponse(new Response(null, { status }), body);
    expect(error).toBeInstanceOf(AuthError);
    expect(error.code).toBe(code);
    expect(error.status).toBe(status);
  });

  test('uses the WWW-Authenticate DPoP error when the body has none', () => {
    const response = new Response(null, {
      status: 401,
      headers: {
        'WWW-Authenticate': 'DPoP error="invalid_token", error_description="expired", algs="ES256"',
      },
    });
    const error = errorFromResponse(response, undefined);
    expect(error.code).toBe('invalid_token');
    expect(error.description).toBe('expired');
  });

  test('insufficient_user_authentication becomes StepUpRequiredError with max_age', () => {
    const response = new Response(null, {
      status: 401,
      headers: {
        'WWW-Authenticate':
          'DPoP error="insufficient_user_authentication", error_description="sign in again", max_age=300, algs="ES256"',
      },
    });
    const error = errorFromResponse(response, undefined);
    expect(error).toBeInstanceOf(StepUpRequiredError);
    expect(error).toMatchObject({
      code: 'insufficient_user_authentication',
      maxAge: 300,
      status: 401,
    });
  });

  test('readJson tolerates empty, non-JSON and malformed bodies', async () => {
    expect(await readJson(new Response(null, { status: 204 }))).toBeUndefined();
    expect(
      await readJson(new Response('<html>', { headers: { 'Content-Type': 'text/html' } })),
    ).toBeUndefined();
    expect(
      await readJson(new Response('{bad', { headers: { 'Content-Type': 'application/json' } })),
    ).toBeUndefined();
    expect(
      await readJson(
        new Response('{"a":1}', {
          headers: { 'Content-Type': 'application/problem+json; charset=utf-8' },
        }),
      ),
    ).toEqual({ a: 1 });
  });
});
