/**
 * Tests of the reusable test support itself: if the software authenticator or
 * the fake server were wrong, every client test would be meaningless.
 */
import { describe, expect, test } from 'vitest';
import { decode, encode } from '../src/base64url.js';
import {
  FLAG_AT,
  FLAG_UP,
  FLAG_UV,
  SoftwareAuthenticator,
  concatBytes,
  decodeCbor,
  derToP1363,
  encodeCbor,
  p1363ToDer,
  parseAttestationObject,
  parseAuthenticatorData,
  sha256,
} from './support/index.js';

const challenge = new Uint8Array(32).fill(5);
const userId = new Uint8Array(16).fill(6);

function createOptions(
  extra: Partial<PublicKeyCredentialCreationOptions> = {},
): CredentialCreationOptions {
  return {
    publicKey: {
      rp: { id: 'example.com', name: 'Example' },
      user: { id: userId, name: 'u', displayName: 'u' },
      challenge,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      ...extra,
    },
  };
}

describe('CBOR', () => {
  test('encodes canonically (CTAP2 key order) and round-trips', () => {
    const map = new Map<number | string, unknown>([
      [-3, new Uint8Array([3])],
      ['fmt', 'none'],
      [1, 2],
      [-1, 1],
      [3, -7],
    ]);
    const bytes = encodeCbor(map as never);
    // Keys sorted by encoded bytes: 1 (0x01), 3 (0x03), -1 (0x20), -3 (0x22), "fmt".
    expect([...(decodeCbor(bytes) as Map<unknown, unknown>).keys()]).toEqual([1, 3, -1, -3, 'fmt']);
    expect(encodeCbor(1000000)).toEqual(new Uint8Array([0x1a, 0x00, 0x0f, 0x42, 0x40]));
    expect(encodeCbor(-500)).toEqual(new Uint8Array([0x39, 0x01, 0xf3]));
  });

  test('decoder is strict', () => {
    expect(() => decodeCbor(new Uint8Array([0x18, 0x05]))).toThrow(/non-shortest/);
    expect(() => decodeCbor(new Uint8Array([0x5f]))).toThrow(/indefinite/);
    expect(() => decodeCbor(new Uint8Array([0x01, 0x02]))).toThrow(/trailing/);
    expect(() => decodeCbor(new Uint8Array([0xa2, 0x01, 0x01, 0x01, 0x02]))).toThrow(/duplicate/);
    expect(() => decodeCbor(new Uint8Array([0xc0, 0x00]))).toThrow(/tags/);
  });
});

describe('ECDSA signature encodings', () => {
  test('P1363 <-> DER round trip, including high-bit and leading-zero integers', () => {
    const cases = [
      concatBytes(new Uint8Array(32).fill(0xff), new Uint8Array(32).fill(0x01)),
      concatBytes(new Uint8Array([0, 0, 1, ...new Uint8Array(29)]), new Uint8Array(32).fill(0x7f)),
    ];
    for (const sig of cases) {
      const der = p1363ToDer(sig);
      expect(der[0]).toBe(0x30);
      expect(derToP1363(der)).toEqual(sig);
    }
    // Non-minimal DER is rejected.
    expect(() =>
      derToP1363(new Uint8Array([0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01])),
    ).toThrow();
  });
});

describe('SoftwareAuthenticator', () => {
  test('registration produces fmt "none" with correct authenticator data', async () => {
    const authenticator = new SoftwareAuthenticator({ origin: 'https://app.example.com' });
    const credential = (await authenticator.create(createOptions())) as unknown as {
      rawId: ArrayBuffer;
      response: { attestationObject: ArrayBuffer; clientDataJSON: ArrayBuffer };
    };
    const attestation = parseAttestationObject(
      new Uint8Array(credential.response.attestationObject),
    );
    expect(attestation.fmt).toBe('none');
    expect(attestation.attStmt.size).toBe(0);
    const authData = parseAuthenticatorData(attestation.authData);
    expect(authData.rpIdHash).toEqual(await sha256('example.com'));
    expect(authData.flags).toBe(FLAG_UP | FLAG_UV | FLAG_AT);
    expect(authData.signCount).toBe(0);
    expect(authData.attestedCredentialData?.credentialId).toEqual(new Uint8Array(credential.rawId));
    expect(authData.attestedCredentialData?.publicKey).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON))).toEqual({
      type: 'webauthn.create',
      challenge: encode(challenge),
      origin: 'https://app.example.com',
      crossOrigin: false,
    });
  });

  test('assertions are DER-signed over authData || SHA-256(clientDataJSON) and count up', async () => {
    const authenticator = new SoftwareAuthenticator({ origin: 'https://app.example.com' });
    const created = (await authenticator.create(createOptions())) as unknown as {
      response: { attestationObject: ArrayBuffer };
    };
    const jwk = parseAuthenticatorData(
      parseAttestationObject(new Uint8Array(created.response.attestationObject)).authData,
    ).attestedCredentialData?.publicKey;
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk ?? {},
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    for (const expectedCount of [1, 2]) {
      const assertion = (await authenticator.get({
        publicKey: { challenge, rpId: 'example.com' },
      })) as unknown as {
        response: {
          authenticatorData: ArrayBuffer;
          clientDataJSON: ArrayBuffer;
          signature: ArrayBuffer;
          userHandle: ArrayBuffer;
        };
      };
      const authData = new Uint8Array(assertion.response.authenticatorData);
      const parsed = parseAuthenticatorData(authData);
      expect(parsed.flags).toBe(FLAG_UP | FLAG_UV);
      expect(parsed.signCount).toBe(expectedCount);
      expect(new Uint8Array(assertion.response.userHandle)).toEqual(userId);
      const signed = concatBytes(
        authData,
        await sha256(new Uint8Array(assertion.response.clientDataJSON)),
      );
      const sig = derToP1363(new Uint8Array(assertion.response.signature));
      expect(
        await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sig, signed),
      ).toBe(true);
    }
  });

  test('enforces RP ID scoping, excludeCredentials and consent', async () => {
    const authenticator = new SoftwareAuthenticator({ origin: 'https://app.example.com' });
    await expect(
      authenticator.create(createOptions({ rp: { id: 'evil.com', name: 'x' } })),
    ).rejects.toMatchObject({ name: 'SecurityError' });
    const created = (await authenticator.create(createOptions())) as unknown as {
      rawId: ArrayBuffer;
    };
    await expect(
      authenticator.create(
        createOptions({ excludeCredentials: [{ type: 'public-key', id: created.rawId }] }),
      ),
    ).rejects.toMatchObject({ name: 'InvalidStateError' });
    authenticator.onPrompt = () => false;
    await expect(
      authenticator.get({ publicKey: { challenge, rpId: 'example.com' } }),
    ).rejects.toMatchObject({
      name: 'NotAllowedError',
    });
  });

  test('install() provides navigator.credentials and PublicKeyCredential, uninstall restores', async () => {
    const authenticator = new SoftwareAuthenticator({
      origin: 'https://app.example.com',
      immediateGet: true,
    });
    const uninstall = authenticator.install();
    try {
      expect(typeof navigator.credentials.create).toBe('function');
      const caps = await (
        globalThis as unknown as {
          PublicKeyCredential: { getClientCapabilities(): Promise<Record<string, boolean>> };
        }
      ).PublicKeyCredential.getClientCapabilities();
      expect(caps['immediateGet']).toBe(true);
    } finally {
      uninstall();
    }
    expect('PublicKeyCredential' in globalThis).toBe(false);
    expect((navigator as { credentials?: unknown }).credentials).toBeUndefined();
  });

  test('an old-style mediation: "immediate" is a TypeError, like WebIDL enum conversion', async () => {
    const authenticator = new SoftwareAuthenticator({ origin: 'https://app.example.com' });
    await expect(
      authenticator.get({
        publicKey: { challenge },
        mediation: 'immediate' as CredentialMediationRequirement,
      }),
    ).rejects.toBeInstanceOf(TypeError);
  });

  test('base64url user handle survives', () => {
    expect(decode(encode(userId))).toEqual(userId);
  });
});
