import { describe, expect, test } from 'vitest';
import { decode, encode } from '../src/base64url.js';
import {
  accessTokenHash,
  createDpopProof,
  deviceKeyFromPair,
  generateDeviceKey,
  htuFor,
} from '../src/dpop.js';
import { jwkThumbprint } from '../src/jwk.js';
import { verifyDpopProof } from './support/index.js';
import { peekJwt } from './harness.js';

describe('device key', () => {
  test('is a non-extractable ECDSA P-256 key pair', async () => {
    const key = await generateDeviceKey();
    expect(key.privateKey.extractable).toBe(false);
    expect(key.privateKey.type).toBe('private');
    expect(key.privateKey.usages).toEqual(['sign']);
    expect(key.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
    await expect(crypto.subtle.exportKey('jwk', key.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('pkcs8', key.privateKey)).rejects.toThrow();
    expect(Object.keys(key.jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(key.jkt).toBe(await jwkThumbprint(key.jwk));
  });

  test('deviceKeyFromPair refuses extractable private keys and wrong algorithms', async () => {
    const extractable = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    await expect(deviceKeyFromPair(extractable.privateKey, extractable.publicKey)).rejects.toThrow(
      /non-extractable/,
    );
    const p384 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
      'sign',
      'verify',
    ]);
    await expect(deviceKeyFromPair(p384.privateKey, p384.publicKey)).rejects.toThrow();
    const good = await generateDeviceKey();
    await expect(deviceKeyFromPair(good.publicKey, good.publicKey)).rejects.toThrow();
  });
});

describe('htu', () => {
  test.each([
    ['https://Auth.Example.COM/v1/token', 'https://auth.example.com/v1/token'],
    ['https://auth.example.com:443/v1/token?x=1#frag', 'https://auth.example.com/v1/token'],
    ['http://localhost:8080/v1/token', 'http://localhost:8080/v1/token'],
    ['https://auth.example.com:8443/a/./b/../c', 'https://auth.example.com:8443/a/c'],
    ['https://api.example.com', 'https://api.example.com/'],
    ['https://api.example.com/a%2Fb', 'https://api.example.com/a%2Fb'],
  ])('%s -> %s', (url, expected) => {
    expect(htuFor(url)).toBe(expected);
  });

  test('rejects non-http(s) URLs', () => {
    expect(() => htuFor('ftp://example.com/x')).toThrow(TypeError);
  });
});

describe('DPoP proof (RFC 9449 §4.2, protocol §7.1)', () => {
  test('has the exact header and claims, and a valid ES256 signature', async () => {
    const key = await generateDeviceKey();
    const iat = Math.floor(Date.now() / 1000);
    const proof = await createDpopProof(key, {
      htm: 'POST',
      htu: 'https://auth.example.com/v1/token',
      iat,
      nonce: 'server-nonce',
    });
    const { header, payload } = peekJwt(proof);
    expect(header).toEqual({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk });
    expect(Object.keys(payload).sort()).toEqual(['htm', 'htu', 'iat', 'jti', 'nonce']);
    expect(payload).toMatchObject({
      htm: 'POST',
      htu: 'https://auth.example.com/v1/token',
      iat,
      nonce: 'server-nonce',
    });
    expect(decode(payload['jti'] as string)).toHaveLength(16);

    const [h, p, s] = proof.split('.') as [string, string, string];
    const signature = decode(s);
    expect(signature).toHaveLength(64); // IEEE P1363 r || s, not DER
    expect(
      await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key.publicKey,
        signature,
        new TextEncoder().encode(`${h}.${p}`),
      ),
    ).toBe(true);
  });

  test('omits nonce and ath when not given', async () => {
    const key = await generateDeviceKey();
    const proof = await createDpopProof(key, { htm: 'GET', htu: 'https://a.example/x', iat: 1 });
    expect(Object.keys(peekJwt(proof).payload).sort()).toEqual(['htm', 'htu', 'iat', 'jti']);
  });

  test('ath = base64url(SHA-256(access token))', async () => {
    const key = await generateDeviceKey();
    const token = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln';
    const proof = await createDpopProof(key, {
      htm: 'GET',
      htu: 'https://api.example.com/hello',
      iat: 1,
      accessToken: token,
    });
    const expected = encode(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
    expect(peekJwt(proof).payload['ath']).toBe(expected);
    expect(await accessTokenHash(token)).toBe(expected);
  });

  test('uses a fresh jti for every proof', async () => {
    const key = await generateDeviceKey();
    const jtis = new Set<unknown>();
    for (let i = 0; i < 50; i++) {
      const proof = await createDpopProof(key, { htm: 'GET', htu: 'https://a.example/', iat: 1 });
      jtis.add(peekJwt(proof).payload['jti']);
    }
    expect(jtis.size).toBe(50);
  });

  test('is accepted by an independent strict verifier', async () => {
    const key = await generateDeviceKey();
    const now = Math.floor(Date.now() / 1000);
    const seenJtis = new Set<string>();
    const proof = await createDpopProof(key, {
      htm: 'GET',
      htu: 'https://api.example.com/hello',
      iat: now,
      nonce: 'n-1',
      accessToken: 'tok',
    });
    const verdict = await verifyDpopProof(proof, {
      method: 'GET',
      htu: 'https://api.example.com/hello',
      now,
      maxSkew: 60,
      acceptNonce: (n) => Promise.resolve(n === 'n-1'),
      accessToken: 'tok',
      seenJtis,
    });
    expect(verdict).toMatchObject({ ok: true, jkt: key.jkt });
    // Replaying the same proof is rejected.
    const replay = await verifyDpopProof(proof, {
      method: 'GET',
      htu: 'https://api.example.com/hello',
      now,
      maxSkew: 60,
      accessToken: 'tok',
      seenJtis,
    });
    expect(replay).toMatchObject({ ok: false, error: 'invalid_dpop_proof', reason: 'jti replay' });
  });

  test('rejects a non-integer iat', async () => {
    const key = await generateDeviceKey();
    await expect(
      createDpopProof(key, { htm: 'GET', htu: 'https://a.example/', iat: 1.5 }),
    ).rejects.toThrow();
  });
});
