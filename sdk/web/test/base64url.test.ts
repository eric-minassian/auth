import { describe, expect, test } from 'vitest';
import { Base64urlError, decode, encode, encodeText, isBase64url } from '../src/base64url.js';

const bytes = (...b: number[]) => new Uint8Array(b);

describe('base64url', () => {
  test.each([
    [bytes(), ''],
    [bytes(0), 'AA'],
    [bytes(0xff), '_w'],
    [bytes(0xfb, 0xff), '-_8'],
    [bytes(0, 0, 0), 'AAAA'],
    [bytes(0xfa, 0xfb, 0xfc, 0xfd), '-vv8_Q'],
    [new TextEncoder().encode('foobar'), 'Zm9vYmFy'],
    [new TextEncoder().encode('fooba'), 'Zm9vYmE'],
    [new TextEncoder().encode('foob'), 'Zm9vYg'],
  ])('encodes %j as %s (RFC 4648 §10 vectors, URL alphabet)', (input, expected) => {
    expect(encode(input)).toBe(expected);
    expect(decode(expected)).toEqual(input);
  });

  test('accepts an ArrayBuffer', () => {
    expect(encode(bytes(1, 2, 3).buffer)).toBe('AQID');
  });

  test('round-trips every length up to 300 bytes against Node', () => {
    for (let n = 0; n <= 300; n++) {
      const data = crypto.getRandomValues(new Uint8Array(n));
      const text = encode(data);
      expect(text).toBe(Buffer.from(data).toString('base64url'));
      expect(decode(text)).toEqual(data);
    }
  });

  test.each([
    ['AA==', 'padding'],
    ['AA=', 'padding'],
    ['AQID=', 'padding'],
    ['A+8', 'standard alphabet +'],
    ['A/8', 'standard alphabet /'],
    ['AA AA', 'whitespace'],
    ['AA\n', 'newline'],
    ['AAAAA', 'impossible length (4n+1)'],
    ['A', 'impossible length'],
    ['AB', 'non-zero trailing bits (2 chars)'],
    ['AAB', 'non-zero trailing bits (3 chars)'],
    ['_x', 'non-zero trailing bits'],
    ['Zm9vYmF', 'non-zero trailing bits'],
    ['é', 'non-ASCII'],
    ['ＡＡ', 'full-width letters'],
    ['AA\u0000', 'NUL'],
  ])('rejects %j (%s)', (input) => {
    expect(() => decode(input)).toThrow(Base64urlError);
    expect(isBase64url(input)).toBe(false);
  });

  test('accepts canonical trailing characters', () => {
    expect(decode('AAE')).toEqual(bytes(0, 1));
    expect(decode('AQ')).toEqual(bytes(1));
  });

  test('rejects non-strings', () => {
    expect(() => decode(42 as unknown as string)).toThrow(Base64urlError);
    expect(isBase64url(null)).toBe(false);
  });

  test('isBase64url enforces decoded length bounds', () => {
    const sixteen = encode(new Uint8Array(16));
    expect(isBase64url(sixteen, 16, 16)).toBe(true);
    expect(isBase64url(sixteen, 17)).toBe(false);
    expect(isBase64url(sixteen, 0, 15)).toBe(false);
  });

  test('encodeText is UTF-8', () => {
    expect(encodeText('{"a":"é"}')).toBe(Buffer.from('{"a":"é"}', 'utf8').toString('base64url'));
  });
});
