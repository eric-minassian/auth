/**
 * Browser platform integration: access to `navigator.credentials`, Immediate
 * UI mode detection and the WebAuthn Signal API. Everything is feature
 * detected; nothing here throws for a missing optional capability.
 */
import { AuthError } from './errors.js';

/** The static members of `PublicKeyCredential` used by the SDK, all optional. */
interface PublicKeyCredentialStatics {
  getClientCapabilities?: () => Promise<unknown>;
  signalUnknownCredential?: (options: { rpId: string; credentialId: string }) => Promise<void>;
  signalAllAcceptedCredentials?: (options: {
    rpId: string;
    userId: string;
    allAcceptedCredentialIds: string[];
  }) => Promise<void>;
}

/**
 * `CredentialRequestOptions` with Immediate UI mode (Chrome 149+): a top-level
 * `uiMode: 'immediate'` member next to `publicKey`.
 */
export interface ImmediateCredentialRequestOptions extends CredentialRequestOptions {
  uiMode?: 'immediate';
}

function publicKeyCredential(): (PublicKeyCredentialStatics & object) | undefined {
  const pkc = (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential;
  return typeof pkc === 'function' ? pkc : undefined;
}

/** `navigator.credentials` if WebAuthn is available, else throws `webauthn_unsupported`. */
export function credentialsContainer(): CredentialsContainer {
  const nav = (globalThis as { navigator?: { credentials?: Partial<CredentialsContainer> } })
    .navigator;
  const container = nav?.credentials;
  if (
    publicKeyCredential() === undefined ||
    container === undefined ||
    typeof container.create !== 'function' ||
    typeof container.get !== 'function'
  ) {
    throw new AuthError('webauthn_unsupported', 'this browser does not support passkeys');
  }
  return container as CredentialsContainer;
}

/**
 * Whether the browser supports Immediate UI mode for `navigator.credentials.get`.
 *
 * Detection follows Chrome's guidance: `PublicKeyCredential.getClientCapabilities()`
 * must report `immediateGet === true`. Browsers silently ignore unknown
 * dictionary members, so passing `uiMode` without this check would show the
 * regular modal passkey sheet instead.
 */
export async function isImmediateGetAvailable(): Promise<boolean> {
  const pkc = publicKeyCredential();
  if (pkc === undefined || typeof pkc.getClientCapabilities !== 'function') {
    return false;
  }
  try {
    const capabilities = await pkc.getClientCapabilities();
    return (
      typeof capabilities === 'object' &&
      capabilities !== null &&
      (capabilities as Record<string, unknown>)['immediateGet'] === true
    );
  } catch {
    return false;
  }
}

/**
 * Tells the credential manager that a credential ID is unknown to the RP so it
 * can hide or delete the passkey (WebAuthn L3 §5.1.10). Best effort.
 */
export async function signalUnknownCredential(rpId: string, credentialId: string): Promise<void> {
  const pkc = publicKeyCredential();
  if (pkc === undefined || typeof pkc.signalUnknownCredential !== 'function') {
    return;
  }
  try {
    await pkc.signalUnknownCredential({ rpId, credentialId });
  } catch {
    // Signals are advisory; a failure must not affect the caller.
  }
}

/**
 * Tells the credential manager the complete list of credential IDs the RP still
 * accepts for a user, so stale passkeys disappear (WebAuthn L3 §5.1.11). Best effort.
 */
export async function signalAllAcceptedCredentials(
  rpId: string,
  userId: string,
  allAcceptedCredentialIds: string[],
): Promise<void> {
  const pkc = publicKeyCredential();
  if (pkc === undefined || typeof pkc.signalAllAcceptedCredentials !== 'function') {
    return;
  }
  try {
    await pkc.signalAllAcceptedCredentials({ rpId, userId, allAcceptedCredentialIds });
  } catch {
    // Advisory only.
  }
}

function errorName(error: unknown): string {
  if (typeof error === 'object' && error !== null) {
    const name = (error as { name?: unknown }).name;
    if (typeof name === 'string') {
      return name;
    }
  }
  return '';
}

/** True for the `NotAllowedError` a WebAuthn call rejects with when nothing (or no one) consented. */
export function isNotAllowed(error: unknown): boolean {
  return errorName(error) === 'NotAllowedError';
}

/** Maps a rejection of `navigator.credentials.create/get` to an `AuthError`. */
export function ceremonyError(error: unknown): AuthError {
  if (error instanceof AuthError) {
    return error;
  }
  const name = errorName(error);
  if (name === 'NotAllowedError' || name === 'AbortError') {
    return new AuthError('ceremony_cancelled', 'the passkey prompt was dismissed or timed out', {
      cause: error,
    });
  }
  return new AuthError(
    'ceremony_failed',
    `the passkey ceremony failed (${name || 'unknown error'})`,
    {
      cause: error,
    },
  );
}
