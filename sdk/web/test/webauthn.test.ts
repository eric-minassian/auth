import { describe, expect, test } from 'vitest';
import { decode, encode } from '../src/base64url.js';
import { AuthError } from '../src/errors.js';
import {
  authenticationResponseToJSON,
  extensionOutputsToJSON,
  parseCreationOptionsJSON,
  parseRequestOptionsJSON,
  registrationResponseToJSON,
  toCreationOptions,
  toRequestOptions,
} from '../src/webauthn.js';
import { SoftwareAuthenticator } from './support/index.js';

const b64 = (n: number, fill = 7) => encode(new Uint8Array(n).fill(fill));

/** Protocol §8.1 creation options. */
function creationOptions(overrides: Record<string, unknown> = {}) {
  return {
    rp: { id: 'example.com', name: 'Example' },
    user: { id: b64(16, 1), name: 'Example · ABCD', displayName: 'Example · ABCD' },
    challenge: b64(32, 2),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -8 },
      { type: 'public-key', alg: -257 },
    ],
    timeout: 300000,
    excludeCredentials: [{ type: 'public-key', id: b64(20, 3), transports: ['internal'] }],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'none',
    extensions: { credProps: true },
    ...overrides,
  };
}

/** Protocol §8.2 request options. */
function requestOptions(overrides: Record<string, unknown> = {}) {
  return {
    challenge: b64(32, 4),
    rpId: 'example.com',
    timeout: 300000,
    allowCredentials: [],
    userVerification: 'required',
    ...overrides,
  };
}

const asBytes = (source: BufferSource | undefined) =>
  source instanceof ArrayBuffer
    ? new Uint8Array(source)
    : new Uint8Array((source as ArrayBufferView).buffer);

describe('options JSON -> binary', () => {
  test('creation options convert every binary member and keep the rest', () => {
    const options = toCreationOptions(parseCreationOptionsJSON(creationOptions()));
    expect(asBytes(options.challenge)).toEqual(new Uint8Array(32).fill(2));
    expect(asBytes(options.user.id)).toEqual(new Uint8Array(16).fill(1));
    expect(options.user.name).toBe('Example · ABCD');
    expect(options.rp).toEqual({ id: 'example.com', name: 'Example' });
    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -8, -257]);
    expect(options.excludeCredentials?.[0]?.transports).toEqual(['internal']);
    expect(asBytes(options.excludeCredentials?.[0]?.id)).toEqual(new Uint8Array(20).fill(3));
    expect(options.authenticatorSelection).toEqual({
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    });
    expect(options.attestation).toBe('none');
    expect(options.extensions).toEqual({ credProps: true });
    expect(options.timeout).toBe(300000);
  });

  test('request options convert challenge and allowCredentials', () => {
    const options = toRequestOptions(
      parseRequestOptionsJSON(
        requestOptions({ allowCredentials: [{ type: 'public-key', id: b64(8) }] }),
      ),
    );
    expect(asBytes(options.challenge)).toEqual(new Uint8Array(32).fill(4));
    expect(options.rpId).toBe('example.com');
    expect(options.userVerification).toBe('required');
    expect(asBytes(options.allowCredentials?.[0]?.id)).toEqual(new Uint8Array(8).fill(7));
  });

  test('PRF and largeBlob extension inputs are decoded', () => {
    const options = toRequestOptions(
      parseRequestOptionsJSON(
        requestOptions({
          extensions: {
            prf: {
              eval: { first: b64(32, 9) },
              evalByCredential: { [b64(8)]: { first: b64(4), second: b64(5) } },
            },
            largeBlob: { write: b64(3) },
            appid: 'https://example.com',
          },
        }),
      ),
    );
    const ext = options.extensions as unknown as {
      prf: {
        eval: { first: Uint8Array };
        evalByCredential: Record<string, { second: Uint8Array }>;
      };
      largeBlob: { write: Uint8Array };
      appid: string;
    };
    expect(ext.prf.eval.first).toEqual(new Uint8Array(32).fill(9));
    expect(ext.prf.evalByCredential[b64(8)]?.second).toEqual(new Uint8Array(5).fill(7));
    expect(ext.largeBlob.write).toEqual(new Uint8Array(3).fill(7));
    expect(ext.appid).toBe('https://example.com');
  });

  test.each([
    ['padded challenge', { challenge: `${b64(32)}=` }],
    ['short challenge', { challenge: b64(8) }],
    ['missing rp.name', { rp: { id: 'example.com' } }],
    ['user id of wrong length', { user: { id: b64(32), name: 'n', displayName: 'n' } }],
    [
      'user id not canonical',
      { user: { id: `${b64(16).slice(0, -1)}B`, name: 'n', displayName: 'n' } },
    ],
    ['empty pubKeyCredParams', { pubKeyCredParams: [] }],
    ['non-integer alg', { pubKeyCredParams: [{ type: 'public-key', alg: '-7' }] }],
    ['bad excludeCredentials id', { excludeCredentials: [{ type: 'public-key', id: '+++' }] }],
    ['timeout as string', { timeout: '300' }],
    ['extensions not an object', { extensions: [] }],
  ])('rejects creation options with %s', (_name, overrides) => {
    expect(() => parseCreationOptionsJSON(creationOptions(overrides))).toThrow(
      expect.objectContaining({ code: 'invalid_response' }),
    );
  });

  test('rejects request options that are not objects', () => {
    expect(() => parseRequestOptionsJSON(null)).toThrow(AuthError);
    expect(() => parseRequestOptionsJSON([])).toThrow(AuthError);
    expect(() => parseRequestOptionsJSON(requestOptions({ rpId: 5 }))).toThrow(AuthError);
  });
});

describe('credential -> JSON', () => {
  test('registration response from the software authenticator', async () => {
    const authenticator = new SoftwareAuthenticator({ origin: 'https://app.example.com' });
    const credential = await authenticator.create({
      publicKey: toCreationOptions(
        parseCreationOptionsJSON(creationOptions({ excludeCredentials: [] })),
      ),
    });
    const json = registrationResponseToJSON(credential);
    expect(json.type).toBe('public-key');
    expect(json.id).toBe(json.rawId);
    expect(decode(json.rawId)).toEqual(authenticator.credentials[0]?.id);
    expect(json.authenticatorAttachment).toBe('platform');
    expect(json.clientExtensionResults).toEqual({ credProps: { rk: true } });
    expect(json.response.transports).toEqual(['hybrid', 'internal']);
    expect(json.response.publicKeyAlgorithm).toBe(-7);
    expect(json.response.publicKey).toBeTypeOf('string');
    expect(json.response.authenticatorData).toBeTypeOf('string');
    const clientData: unknown = JSON.parse(
      new TextDecoder().decode(decode(json.response.clientDataJSON)),
    );
    expect(clientData).toEqual({
      type: 'webauthn.create',
      challenge: b64(32, 2),
      origin: 'https://app.example.com',
      crossOrigin: false,
    });
    // JSON-serializable: no binary left.
    expect(JSON.parse(JSON.stringify(json))).toEqual(json);
  });

  test('authentication response from the software authenticator', async () => {
    const authenticator = new SoftwareAuthenticator({ origin: 'https://app.example.com' });
    await authenticator.create({
      publicKey: toCreationOptions(
        parseCreationOptionsJSON(creationOptions({ excludeCredentials: [] })),
      ),
    });
    const credential = await authenticator.get({
      publicKey: toRequestOptions(parseRequestOptionsJSON(requestOptions())),
    });
    const json = authenticationResponseToJSON(credential);
    expect(json.response.userHandle).toBe(b64(16, 1));
    expect(Object.keys(json.response).sort()).toEqual([
      'authenticatorData',
      'clientDataJSON',
      'signature',
      'userHandle',
    ]);
    expect(json.clientExtensionResults).toEqual({});
  });

  test('works without the optional getters (extension-provided credentials)', () => {
    const rawId = new Uint8Array([1, 2, 3]);
    const json = registrationResponseToJSON({
      id: encode(rawId),
      rawId: rawId.buffer,
      type: 'public-key',
      authenticatorAttachment: null,
      response: {
        clientDataJSON: new Uint8Array([4]),
        attestationObject: new Uint8Array([5]).buffer,
      },
    });
    expect(json).toEqual({
      id: 'AQID',
      rawId: 'AQID',
      type: 'public-key',
      response: { clientDataJSON: 'BA', attestationObject: 'BQ' },
      clientExtensionResults: {},
    });
  });

  test('getters that throw are ignored', () => {
    const rawId = new Uint8Array([1]);
    const json = registrationResponseToJSON({
      id: encode(rawId),
      rawId: rawId.buffer,
      type: 'public-key',
      response: {
        clientDataJSON: new Uint8Array([4]).buffer,
        attestationObject: new Uint8Array([5]).buffer,
        getPublicKey: () => {
          throw new Error('nope');
        },
      },
      getClientExtensionResults: () => {
        throw new Error('nope');
      },
    });
    expect(json.response.publicKey).toBeUndefined();
  });

  test('a null userHandle is omitted', () => {
    const rawId = new Uint8Array([9]);
    const json = authenticationResponseToJSON({
      id: encode(rawId),
      rawId: rawId.buffer,
      type: 'public-key',
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        authenticatorData: new Uint8Array([2]).buffer,
        signature: new Uint8Array([3]).buffer,
        userHandle: null,
      },
    });
    expect(json.response.userHandle).toBeUndefined();
  });

  test.each([
    ['null', null],
    ['wrong type', { type: 'password', id: 'AQ', rawId: new Uint8Array([1]).buffer, response: {} }],
    [
      'id != base64url(rawId)',
      { type: 'public-key', id: 'AQI', rawId: new Uint8Array([1]).buffer, response: {} },
    ],
    ['empty rawId', { type: 'public-key', id: '', rawId: new ArrayBuffer(0), response: {} }],
    ['missing response', { type: 'public-key', id: 'AQ', rawId: new Uint8Array([1]).buffer }],
    [
      'non-binary clientDataJSON',
      {
        type: 'public-key',
        id: 'AQ',
        rawId: new Uint8Array([1]).buffer,
        response: { clientDataJSON: 'x' },
      },
    ],
  ])('rejects a credential with %s', (_name, credential) => {
    expect(() => registrationResponseToJSON(credential)).toThrow(
      expect.objectContaining({ code: 'credential_invalid' }),
    );
  });

  test('extension outputs: binary values become base64url', () => {
    expect(
      extensionOutputsToJSON({
        prf: { enabled: true, results: { first: new Uint8Array([1, 2]).buffer } },
        largeBlob: { blob: new Uint8Array([3]) },
        fn: () => 1,
      }),
    ).toEqual({ prf: { enabled: true, results: { first: 'AQI' } }, largeBlob: { blob: 'Aw' } });
  });
});
