import { createHash } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { exportEcPublicJwk, jwkThumbprint, thumbprintInput } from '../src/jwk.js';

describe('RFC 7638 JWK thumbprint', () => {
  test('RFC 7638 §3.1 example (RSA)', async () => {
    const jwk = {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      alg: 'RS256',
      kid: '2011-04-29',
    };
    expect(thumbprintInput(jwk)).toBe(`{"e":"AQAB","kty":"RSA","n":"${jwk.n}"}`);
    expect(await jwkThumbprint(jwk)).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  test('RFC 9449 §4.2/§6.1 example (P-256): jkt of the example proof key', async () => {
    const jwk = {
      kty: 'EC',
      x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
      y: '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA',
      crv: 'P-256',
    };
    expect(await jwkThumbprint(jwk)).toBe('0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I');
  });

  test('RFC 8037 Appendix A.3 example (OKP / Ed25519)', async () => {
    const jwk = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
    expect(await jwkThumbprint(jwk)).toBe('kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
  });

  test('ignores optional members and member order (P-256)', async () => {
    const a = {
      kty: 'EC',
      crv: 'P-256',
      x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
      y: '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA',
    };
    const b = { y: a.y, use: 'sig', x: a.x, alg: 'ES256', crv: 'P-256', kid: 'k', kty: 'EC' };
    expect(await jwkThumbprint(b)).toBe(await jwkThumbprint(a));
  });

  test('matches an independent computation for freshly generated P-256 keys', async () => {
    for (let i = 0; i < 10; i++) {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
        'sign',
        'verify',
      ]);
      const jwk = await exportEcPublicJwk(pair.publicKey);
      // Independent: build the canonical string by hand and hash with node:crypto.
      const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
      const expected = createHash('sha256').update(canonical).digest('base64url');
      expect(await jwkThumbprint(jwk)).toBe(expected);
      expect(jwk).toEqual({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y });
    }
  });

  test('rejects JWKs without required members or with unknown kty', () => {
    expect(() => thumbprintInput({ kty: 'EC', crv: 'P-256', x: 'AA' })).toThrow(TypeError);
    expect(() => thumbprintInput({ kty: 'XYZ' })).toThrow(TypeError);
    expect(() => thumbprintInput({})).toThrow(TypeError);
  });
});
