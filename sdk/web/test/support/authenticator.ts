/**
 * A software passkey authenticator plus the browser glue around it
 * (`navigator.credentials.create/get`, `PublicKeyCredential` statics).
 *
 * It produces the real binary formats a browser hands to JavaScript:
 * - `attestationObject`: CTAP2-canonical CBOR, fmt "none", empty attStmt;
 * - authenticator data with rpIdHash = SHA-256(rpId), flags UP|UV|AT on create
 *   and UP|UV on get (plus BE/BS if configured), big-endian signCount and a
 *   COSE EC2 ES256 credential public key;
 * - `clientDataJSON` = {"type","challenge","origin","crossOrigin":false};
 * - DER ECDSA assertion signatures over authData || SHA-256(clientDataJSON);
 * - `userHandle` = the `user.id` given at registration.
 *
 * It is deliberately independent of the SDK and of the fake server so it can
 * drive end-to-end tests against the real service.
 */
import { encode as b64encode } from '../../src/base64url.js';
import {
  FLAG_AT,
  FLAG_BE,
  FLAG_BS,
  FLAG_UP,
  FLAG_UV,
  buildAuthenticatorData,
  buildNoneAttestationObject,
  concatBytes,
  coseKeyFromJwk,
  p1363ToDer,
  sha256,
  toArrayBuffer,
} from './webauthn-format.js';

export interface SoftwareAuthenticatorOptions {
  /** The web origin the "browser" runs on, e.g. `https://app.example.com`. */
  readonly origin: string;
  /** AAGUID reported at registration (16 bytes). Defaults to all zeros. */
  readonly aaguid?: Uint8Array;
  /** `increment` (default): counter goes up per assertion. `zero`: always 0 (synced passkeys). */
  readonly signCount?: 'increment' | 'zero';
  /** Backup eligibility / state flags (BE/BS). Default false. */
  readonly backupEligible?: boolean;
  readonly backupState?: boolean;
  /** Length of generated credential IDs in bytes. Default 16. */
  readonly credentialIdLength?: number;
  readonly attachment?: 'platform' | 'cross-platform';
  /** Whether the simulated browser supports Immediate UI mode (`immediateGet`). Default false. */
  readonly immediateGet?: boolean;
  /** Whether `PublicKeyCredential.getClientCapabilities` exists. Default true. */
  readonly clientCapabilities?: boolean;
  /** Whether the Signal API statics exist. Default true. */
  readonly signalApi?: boolean;
}

export interface StoredCredential {
  readonly id: Uint8Array;
  readonly rpId: string;
  readonly userHandle: Uint8Array;
  readonly userName: string;
  readonly privateKey: CryptoKey;
  readonly publicKeyJwk: JsonWebKey;
  signCount: number;
  readonly createdAt: number;
}

export type SignalCall =
  | { readonly kind: 'unknown'; readonly rpId: string; readonly credentialId: string }
  | {
      readonly kind: 'allAccepted';
      readonly rpId: string;
      readonly userId: string;
      readonly allAcceptedCredentialIds: readonly string[];
    };

export interface CeremonyCall {
  readonly kind: 'create' | 'get';
  readonly options: CredentialCreationOptions | CredentialRequestOptions;
}

export type PromptHandler = (context: {
  kind: 'create' | 'get';
  rpId: string;
  immediate: boolean;
}) => boolean | Promise<boolean>;

const MEDIATION_VALUES = new Set(['silent', 'optional', 'conditional', 'required']);
let creationCounter = 0;

function domException(name: string, message: string): DOMException {
  return new DOMException(message, name);
}

function bufferSourceBytes(source: BufferSource | undefined, what: string): Uint8Array {
  if (source instanceof ArrayBuffer) return new Uint8Array(source.slice(0));
  if (source !== undefined && ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength).slice();
  }
  throw new TypeError(`${what} must be a BufferSource`);
}

function isRegistrableSuffix(rpId: string, host: string): boolean {
  return host === rpId || host.endsWith(`.${rpId}`);
}

export class SoftwareAuthenticator {
  readonly origin: string;
  readonly credentials: StoredCredential[] = [];
  readonly calls: CeremonyCall[] = [];
  readonly signals: SignalCall[] = [];
  /** User consent simulation; return `false` to cancel the prompt. Defaults to consenting. */
  onPrompt: PromptHandler | undefined;
  /** Picks among discoverable credentials. Defaults to the most recently created. */
  selectCredential:
    ((candidates: readonly StoredCredential[]) => StoredCredential | undefined) | undefined;
  readonly #options: SoftwareAuthenticatorOptions;

  constructor(options: SoftwareAuthenticatorOptions) {
    this.#options = options;
    this.origin = new URL(options.origin).origin;
  }

  get supportsImmediateGet(): boolean {
    return this.#options.immediateGet === true && this.#options.clientCapabilities !== false;
  }

  #flagsBase(): number {
    let flags = FLAG_UP | FLAG_UV;
    if (this.#options.backupEligible === true) flags |= FLAG_BE;
    if (this.#options.backupState === true) flags |= FLAG_BS;
    return flags;
  }

  #clientData(
    type: 'webauthn.create' | 'webauthn.get',
    challenge: Uint8Array,
  ): Uint8Array<ArrayBuffer> {
    // Same member order as browsers (WebAuthn §5.8.1.1 limited verification).
    return new TextEncoder().encode(
      JSON.stringify({
        type,
        challenge: b64encode(challenge),
        origin: this.origin,
        crossOrigin: false,
      }),
    );
  }

  async #consent(kind: 'create' | 'get', rpId: string, immediate: boolean): Promise<void> {
    const ok = this.onPrompt === undefined ? true : await this.onPrompt({ kind, rpId, immediate });
    if (!ok)
      throw domException('NotAllowedError', 'The operation either timed out or was not allowed.');
  }

  /** `navigator.credentials.create({ publicKey })`. */
  async create(options?: CredentialCreationOptions): Promise<Credential | null> {
    if (options !== undefined) this.calls.push({ kind: 'create', options });
    const pk = options?.publicKey;
    if (pk === undefined) throw new TypeError('only publicKey credentials are supported');
    if (options?.signal?.aborted === true) throw domException('AbortError', 'aborted');
    const host = new URL(this.origin).hostname;
    const rpId = pk.rp.id ?? host;
    if (!isRegistrableSuffix(rpId, host)) {
      throw domException(
        'SecurityError',
        'The relying party ID is not a registrable domain suffix of the origin.',
      );
    }
    const challenge = bufferSourceBytes(pk.challenge, 'challenge');
    const userHandle = bufferSourceBytes(pk.user.id, 'user.id');
    if (userHandle.length < 1 || userHandle.length > 64)
      throw new TypeError('user.id must be 1..64 bytes');
    if (!pk.pubKeyCredParams.some((p) => (p.type as string) === 'public-key' && p.alg === -7)) {
      throw domException(
        'NotSupportedError',
        'No supported algorithm (this authenticator only does ES256).',
      );
    }
    for (const excluded of pk.excludeCredentials ?? []) {
      const id = bufferSourceBytes(excluded.id, 'excludeCredentials[].id');
      if (this.credentials.some((c) => c.rpId === rpId && b64encode(c.id) === b64encode(id))) {
        await this.#consent('create', rpId, false);
        throw domException(
          'InvalidStateError',
          'The authenticator already contains one of the credentials.',
        );
      }
    }
    await this.#consent('create', rpId, false);

    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]);
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
    const id = crypto.getRandomValues(new Uint8Array(this.#options.credentialIdLength ?? 16));
    const authData = buildAuthenticatorData({
      rpIdHash: await sha256(rpId),
      flags: this.#flagsBase() | FLAG_AT,
      signCount: 0,
      attested: {
        aaguid: this.#options.aaguid ?? new Uint8Array(16),
        credentialId: id,
        cosePublicKey: coseKeyFromJwk(publicKeyJwk),
      },
    });
    // A discoverable credential replaces any other for the same RP and user (CTAP 2.1 §6.1.2).
    const existing = this.credentials.findIndex(
      (c) => c.rpId === rpId && b64encode(c.userHandle) === b64encode(userHandle),
    );
    if (existing >= 0) this.credentials.splice(existing, 1);
    this.credentials.push({
      id,
      rpId,
      userHandle,
      userName: pk.user.name,
      privateKey: pair.privateKey,
      publicKeyJwk,
      signCount: 0,
      createdAt: ++creationCounter,
    });

    const clientDataJSON = this.#clientData('webauthn.create', challenge);
    const attestationObject = buildNoneAttestationObject(authData);
    const extensionResults: Record<string, unknown> = {};
    if (pk.extensions?.credProps === true) extensionResults['credProps'] = { rk: true };
    const response = {
      clientDataJSON: toArrayBuffer(clientDataJSON),
      attestationObject: toArrayBuffer(attestationObject),
      getTransports: () => ['hybrid', 'internal'],
      getAuthenticatorData: () => toArrayBuffer(authData),
      getPublicKey: () => spki,
      getPublicKeyAlgorithm: () => -7,
    };
    return {
      id: b64encode(id),
      rawId: toArrayBuffer(id),
      type: 'public-key',
      authenticatorAttachment: this.#options.attachment ?? 'platform',
      response,
      getClientExtensionResults: () => extensionResults,
    } as unknown as Credential;
  }

  /** `navigator.credentials.get({ publicKey, uiMode? })`. */
  async get(options?: CredentialRequestOptions & { uiMode?: string }): Promise<Credential | null> {
    if (options !== undefined) this.calls.push({ kind: 'get', options });
    if (options?.mediation !== undefined && !MEDIATION_VALUES.has(options.mediation)) {
      // WebIDL enum conversion fails for unknown values (e.g. the old `mediation: 'immediate'` origin trial).
      throw new TypeError(`The provided value '${options.mediation}' is not a valid enum value.`);
    }
    const pk = options?.publicKey;
    if (pk === undefined) throw new TypeError('only publicKey credentials are supported');
    // A browser without Immediate UI ignores the unknown `uiMode` member.
    const immediate = options?.uiMode === 'immediate' && this.supportsImmediateGet;
    if (immediate && options.signal !== undefined) {
      throw new TypeError('signal is not allowed with immediate UI mode');
    }
    if (options?.signal?.aborted === true) throw domException('AbortError', 'aborted');
    const host = new URL(this.origin).hostname;
    const rpId = pk.rpId ?? host;
    if (!isRegistrableSuffix(rpId, host)) {
      throw domException(
        'SecurityError',
        'The relying party ID is not a registrable domain suffix of the origin.',
      );
    }
    const challenge = bufferSourceBytes(pk.challenge, 'challenge');
    const allow = (pk.allowCredentials ?? []).map((d) =>
      b64encode(bufferSourceBytes(d.id, 'allowCredentials[].id')),
    );
    if (immediate && allow.length > 0) {
      throw domException('NotAllowedError', 'allowCredentials must be empty in immediate mode.');
    }
    const candidates = this.credentials.filter(
      (c) => c.rpId === rpId && (allow.length === 0 || allow.includes(b64encode(c.id))),
    );
    if (candidates.length === 0) {
      // Immediate mode: rejects right away, without UI. Modal: the user sees
      // "no passkeys" and dismisses the sheet.
      if (!immediate) await this.#consent('get', rpId, false);
      throw domException('NotAllowedError', 'The operation either timed out or was not allowed.');
    }
    await this.#consent('get', rpId, immediate);
    const sorted = [...candidates].sort((a, b) => b.createdAt - a.createdAt);
    const credential =
      this.selectCredential === undefined ? sorted[0] : this.selectCredential(sorted);
    if (credential === undefined) {
      throw domException('NotAllowedError', 'The operation either timed out or was not allowed.');
    }
    if (this.#options.signCount !== 'zero') credential.signCount += 1;

    const authData = buildAuthenticatorData({
      rpIdHash: await sha256(rpId),
      flags: this.#flagsBase(),
      signCount: credential.signCount,
    });
    const clientDataJSON = this.#clientData('webauthn.get', challenge);
    const signed = concatBytes(authData, await sha256(clientDataJSON));
    const p1363 = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, credential.privateKey, signed),
    );
    const response = {
      clientDataJSON: toArrayBuffer(clientDataJSON),
      authenticatorData: toArrayBuffer(authData),
      signature: toArrayBuffer(p1363ToDer(p1363)),
      userHandle: toArrayBuffer(credential.userHandle),
    };
    return {
      id: b64encode(credential.id),
      rawId: toArrayBuffer(credential.id),
      type: 'public-key',
      authenticatorAttachment: this.#options.attachment ?? 'platform',
      response,
      getClientExtensionResults: () => ({}),
    } as unknown as Credential;
  }

  /** Removes credentials the RP reported as unknown (what credential managers do). */
  #applySignal(signal: SignalCall): void {
    this.signals.push(signal);
    for (let i = this.credentials.length - 1; i >= 0; i--) {
      const c = this.credentials[i];
      if (c?.rpId !== signal.rpId) continue;
      const id = b64encode(c.id);
      const remove =
        signal.kind === 'unknown'
          ? id === signal.credentialId
          : b64encode(c.userHandle) === signal.userId &&
            !signal.allAcceptedCredentialIds.includes(id);
      if (remove) this.credentials.splice(i, 1);
    }
  }

  /**
   * Installs this authenticator as `navigator.credentials` and a matching
   * `PublicKeyCredential` global. Returns a function that restores the previous globals.
   */
  install(target: typeof globalThis = globalThis): () => void {
    const g = target as unknown as Record<string, unknown>;
    const nav = g['navigator'] ?? {};
    const hadNavigator = 'navigator' in g;
    if (!hadNavigator) {
      Object.defineProperty(g, 'navigator', { value: nav, configurable: true, writable: true });
    }
    const previousCredentials = Object.getOwnPropertyDescriptor(nav, 'credentials');
    const previousPkc = Object.getOwnPropertyDescriptor(g, 'PublicKeyCredential');

    const container = {
      create: (options?: CredentialCreationOptions) => this.create(options),
      get: (options?: CredentialRequestOptions) => this.get(options),
      store: () => Promise.reject(domException('NotSupportedError', 'not supported')),
      preventSilentAccess: () => Promise.resolve(),
    };
    Object.defineProperty(nav, 'credentials', { value: container, configurable: true });

    const statics: Record<string, unknown> = {
      isUserVerifyingPlatformAuthenticatorAvailable: () => Promise.resolve(true),
      isConditionalMediationAvailable: () => Promise.resolve(true),
    };
    if (this.#options.clientCapabilities !== false) {
      statics['getClientCapabilities'] = () =>
        Promise.resolve({
          conditionalGet: true,
          passkeyPlatformAuthenticator: true,
          userVerifyingPlatformAuthenticator: true,
          signalUnknownCredential: this.#options.signalApi !== false,
          signalAllAcceptedCredentials: this.#options.signalApi !== false,
          immediateGet: this.#options.immediateGet === true,
        });
    }
    if (this.#options.signalApi !== false) {
      statics['signalUnknownCredential'] = (o: { rpId: string; credentialId: string }) => {
        this.#applySignal({ kind: 'unknown', rpId: o.rpId, credentialId: o.credentialId });
        return Promise.resolve();
      };
      statics['signalAllAcceptedCredentials'] = (o: {
        rpId: string;
        userId: string;
        allAcceptedCredentialIds: string[];
      }) => {
        this.#applySignal({
          kind: 'allAccepted',
          rpId: o.rpId,
          userId: o.userId,
          allAcceptedCredentialIds: [...o.allAcceptedCredentialIds],
        });
        return Promise.resolve();
      };
    }
    // Like the real interface, it cannot be constructed from script.
    const PublicKeyCredentialStub = function PublicKeyCredential(): never {
      throw new TypeError('Illegal constructor');
    };
    Object.assign(PublicKeyCredentialStub, statics);
    Object.defineProperty(g, 'PublicKeyCredential', {
      value: PublicKeyCredentialStub,
      configurable: true,
      writable: true,
    });

    return () => {
      if (previousCredentials === undefined) {
        Reflect.deleteProperty(nav, 'credentials');
      } else {
        Object.defineProperty(nav, 'credentials', previousCredentials);
      }
      if (previousPkc === undefined) {
        Reflect.deleteProperty(g, 'PublicKeyCredential');
      } else {
        Object.defineProperty(g, 'PublicKeyCredential', previousPkc);
      }
      if (!hadNavigator) {
        Reflect.deleteProperty(g, 'navigator');
      }
    };
  }
}
