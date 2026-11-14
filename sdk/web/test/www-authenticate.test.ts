import { describe, expect, test } from 'vitest';
import { dpopChallenge, parseWwwAuthenticate } from '../src/www-authenticate.js';

const params = (header: string) =>
  parseWwwAuthenticate(header).map((c) => ({
    scheme: c.scheme,
    params: Object.fromEntries(c.params),
    ...(c.token68 === undefined ? {} : { token68: c.token68 }),
  }));

describe('WWW-Authenticate parser', () => {
  test('protocol §10.7 step-up challenge', () => {
    expect(
      params(
        'DPoP error="insufficient_user_authentication", error_description="A recent sign-in is required", max_age=300, algs="ES256"',
      ),
    ).toEqual([
      {
        scheme: 'dpop',
        params: {
          error: 'insufficient_user_authentication',
          error_description: 'A recent sign-in is required',
          max_age: '300',
          algs: 'ES256',
        },
      },
    ]);
  });

  test('several challenges, mixed token/quoted values, case-insensitive names', () => {
    expect(
      params(
        'Bearer realm="api", error=invalid_token, DPoP ERROR="use_dpop_nonce" , Algs="ES256 PS256"',
      ),
    ).toEqual([
      { scheme: 'bearer', params: { realm: 'api', error: 'invalid_token' } },
      { scheme: 'dpop', params: { error: 'use_dpop_nonce', algs: 'ES256 PS256' } },
    ]);
  });

  test('token68 and parameterless challenges', () => {
    expect(params('Basic YWxhZGRpbjpvcGVuc2VzYW1l, Negotiate, Newauth abc==, DPoP')).toEqual([
      { scheme: 'basic', params: {}, token68: 'YWxhZGRpbjpvcGVuc2VzYW1l' },
      { scheme: 'negotiate', params: {} },
      { scheme: 'newauth', params: {}, token68: 'abc==' },
      { scheme: 'dpop', params: {} },
    ]);
  });

  test('quoted-string escapes and commas inside quotes', () => {
    expect(params('DPoP error_description="a \\"quoted\\", with comma", error="x"')).toEqual([
      { scheme: 'dpop', params: { error_description: 'a "quoted", with comma', error: 'x' } },
    ]);
  });

  test('BWS around "=" and empty list elements', () => {
    expect(params(' , DPoP error = "use_dpop_nonce" ,, algs="ES256"')).toEqual([
      { scheme: 'dpop', params: { error: 'use_dpop_nonce', algs: 'ES256' } },
    ]);
  });

  test('first occurrence of a duplicate parameter wins', () => {
    expect(params('DPoP error="a", error="b"')[0]?.params).toEqual({ error: 'a' });
  });

  test('malformed input yields what was parsed so far, never throws', () => {
    expect(params('DPoP error="unterminated')).toEqual([]);
    expect(params('DPoP error="ok", @@@')).toEqual([{ scheme: 'dpop', params: { error: 'ok' } }]);
    expect(parseWwwAuthenticate('')).toEqual([]);
    expect(parseWwwAuthenticate(null)).toEqual([]);
  });

  test('dpopChallenge extracts error, description and max_age', () => {
    const headers = new Headers({
      'WWW-Authenticate':
        'Bearer realm="x", DPoP error="insufficient_user_authentication", max_age=300',
    });
    expect(dpopChallenge(headers)).toEqual({
      error: 'insufficient_user_authentication',
      errorDescription: undefined,
      maxAge: 300,
    });
    expect(
      dpopChallenge(new Headers({ 'WWW-Authenticate': 'DPoP max_age=-1' }))?.maxAge,
    ).toBeUndefined();
    expect(
      dpopChallenge(new Headers({ 'WWW-Authenticate': 'Bearer error="invalid_token"' })),
    ).toBeUndefined();
    expect(dpopChallenge(new Headers())).toBeUndefined();
  });
});
