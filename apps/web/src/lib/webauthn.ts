/**
 * Bridges the server's webauthn-rs ceremony options to the browser WebAuthn API
 * and drives the email-free flows: passkey signup (gated by a client-side
 * proof-of-work), usernameless discoverable login, step-up re-authentication,
 * and recovery codes. The server serializes options in the standard WebAuthn
 * JSON form (`{ publicKey: … }`), so the native `parse*OptionsFromJSON` / `toJSON`
 * helpers handle conversion with no extra dependency.
 */
import aaguidNames from "./aaguid.json";
import { ApiError, api, type RecoveryReadiness } from "./api.js";

interface CeremonyEnvelope {
  ceremony_id: string;
  options: { publicKey: unknown };
}

export interface RegistrationResult {
  /**
   * credProps.rk — `false` means the authenticator did NOT store a
   * discoverable (resident) credential, so it can't be used for this
   * provider's usernameless login (a permanent-lockout footgun for a hardware
   * key with exhausted resident-key slots). `undefined` when the browser
   * omits the extension; platform authenticators report `true`.
   */
  discoverable: boolean | undefined;
}

export function isWebauthnSupported(): boolean {
  return typeof PublicKeyCredential !== "undefined";
}

export async function supportsConditionalUi(): Promise<boolean> {
  return (
    isWebauthnSupported() &&
    typeof PublicKeyCredential.isConditionalMediationAvailable === "function" &&
    (await PublicKeyCredential.isConditionalMediationAvailable())
  );
}

// ---- Error taxonomy --------------------------------------------------------

export type WebAuthnErrorCode =
  | "cancelled"
  | "unsupported"
  | "already_registered"
  | "not_discoverable"
  | "security"
  | "stale_credential"
  | "unknown";

/**
 * A passkey-ceremony failure with a stable, anti-enumeration-safe `code`. These
 * errors are device-local (cancel, no-credential, capability) and carry no
 * account-existence signal, so their messages are safe to show verbatim.
 */
export class WebAuthnError extends Error {
  readonly code: WebAuthnErrorCode;
  constructor(code: WebAuthnErrorCode, message?: string) {
    super(message ?? webAuthnErrorMessage(code));
    this.name = "WebAuthnError";
    this.code = code;
  }
}

/** Map a raw WebAuthn `DOMException` to a typed {@link WebAuthnError}. */
function classifyWebauthnError(error: unknown): WebAuthnError {
  if (error instanceof WebAuthnError) return error;
  const name = error instanceof DOMException ? error.name : "";
  switch (name) {
    // The platform deliberately conflates user-cancel, timeout, and
    // no-matching-credential into NotAllowedError — we cannot, and (for
    // anti-enumeration) must not, distinguish them.
    case "NotAllowedError":
    case "AbortError":
      return new WebAuthnError("cancelled");
    case "InvalidStateError":
      return new WebAuthnError("already_registered");
    case "NotSupportedError":
    case "ConstraintError":
      return new WebAuthnError("unsupported");
    case "SecurityError":
      return new WebAuthnError("security");
    default:
      return new WebAuthnError("unknown");
  }
}

/** User-facing copy for a {@link WebAuthnErrorCode}. */
export function webAuthnErrorMessage(code: WebAuthnErrorCode): string {
  switch (code) {
    case "cancelled":
      return "The passkey prompt was dismissed or timed out. Please try again.";
    case "unsupported":
      return "This device or browser can't use passkeys here. Try Touch ID, Windows Hello, or a passkey manager.";
    case "already_registered":
      return "There's already a passkey for this account on this device.";
    case "not_discoverable":
      return "This device couldn't store a sign-in-ready passkey. Try a platform authenticator (Touch ID, Windows Hello, or a passkey manager).";
    case "security":
      return "Couldn't verify this site for passkeys. Make sure you're on the official site, then try again.";
    case "stale_credential":
      return "That passkey no longer exists for this account, so it's been removed from this device's list. Use another passkey or a recovery code.";
    case "unknown":
      return "Something went wrong with your passkey. Please try again.";
  }
}

/** Whether the error is the user dismissing/timing out the prompt (not a real failure). */
export function isUserCancellation(error: unknown): boolean {
  return error instanceof WebAuthnError && error.code === "cancelled";
}

/**
 * Best user-facing message for any error thrown by a passkey flow: typed
 * WebAuthn errors and server `ApiError`s carry their own copy; everything else
 * falls back to a caller-supplied default.
 */
export function describePasskeyError(error: unknown, fallback: string): string {
  if (error instanceof WebAuthnError || error instanceof ApiError) return error.message;
  return fallback;
}

/** Run `navigator.credentials.create`, normalizing failures to {@link WebAuthnError}. */
async function createPasskey(
  options: PublicKeyCredentialCreationOptions,
): Promise<PublicKeyCredential> {
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.create({ publicKey: options });
  } catch (error) {
    throw classifyWebauthnError(error);
  }
  if (!credential) throw new WebAuthnError("cancelled");
  return credential as PublicKeyCredential;
}

/** Run `navigator.credentials.get`, normalizing failures to {@link WebAuthnError}. */
async function getPasskey(request: CredentialRequestOptions): Promise<PublicKeyCredential> {
  let credential: Credential | null;
  try {
    credential = await navigator.credentials.get(request);
  } catch (error) {
    throw classifyWebauthnError(error);
  }
  if (!credential) throw new WebAuthnError("cancelled");
  return credential as PublicKeyCredential;
}

// ---- Proof of work ---------------------------------------------------------

interface PowChallenge {
  challenge: string;
  difficulty: number;
}

function leadingZeroBits(bytes: Uint8Array): number {
  let count = 0;
  for (const b of bytes) {
    if (b === 0) {
      count += 8;
      continue;
    }
    // `b` is in 1..=255, so clz32 over-counts by 24 bits.
    return count + Math.clz32(b) - 24;
  }
  return count;
}

/** Find a nonce whose `SHA-256("{challenge}:{nonce}")` meets the difficulty. */
async function solvePow({ challenge, difficulty }: PowChallenge): Promise<string> {
  const encoder = new TextEncoder();
  for (let nonce = 0; ; nonce++) {
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(`${challenge}:${nonce}`)),
    );
    if (leadingZeroBits(digest) >= difficulty) return String(nonce);
  }
}

// ---- Signup ----------------------------------------------------------------

interface SignupStart {
  ceremony_id: string;
  user_id: string;
  options: { publicKey: unknown };
}

/**
 * Create an account: solve the proof-of-work, register the first passkey, and
 * activate it. This leaves an *enroll* session — call {@link loginWithPasskey}
 * afterwards to obtain a full session.
 */
export async function signUp(nickname: string, passkeyName?: string): Promise<RegistrationResult> {
  const pow = await api.get<PowChallenge>("/api/signup/pow");
  const powNonce = await solvePow(pow);
  const start = await api.post<SignupStart>("/api/signup/start", {
    nickname,
    pow_challenge: pow.challenge,
    pow_nonce: powNonce,
  });
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(
    start.options.publicKey as PublicKeyCredentialCreationOptionsJSON,
  );
  const credential = await createPasskey(options);
  await api.post("/api/signup/finish", {
    ceremony_id: start.ceremony_id,
    credential: credential.toJSON(),
    name: passkeyName ?? defaultPasskeyName(credential),
  });
  return { discoverable: credentialDiscoverable(credential) };
}

// ---- Passkey registration (add a passkey / re-onboard after recovery) ------

/** Register a passkey for the current (enroll or full) session. */
export async function registerPasskey(name?: string): Promise<RegistrationResult> {
  const start = await api.post<CeremonyEnvelope>("/api/webauthn/register/start");
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(
    start.options.publicKey as PublicKeyCredentialCreationOptionsJSON,
  );
  const credential = await createPasskey(options);
  await api.post("/api/webauthn/register/finish", {
    ceremony_id: start.ceremony_id,
    credential: credential.toJSON(),
    name: name ?? defaultPasskeyName(credential),
  });
  return { discoverable: credentialDiscoverable(credential) };
}

// ---- Login (usernameless, discoverable) ------------------------------------

/**
 * Authenticate with a discoverable passkey. `conditional` uses the browser's
 * autofill UI; `signal` lets the caller abort a pending conditional request.
 * Takes no identifier — the authenticator reveals which account.
 */
export async function loginWithPasskey(opts?: {
  conditional?: boolean;
  signal?: AbortSignal;
}): Promise<void> {
  const start = await api.post<CeremonyEnvelope>("/api/webauthn/login/start");
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(
    start.options.publicKey as PublicKeyCredentialRequestOptionsJSON,
  );
  const credential = await getPasskey({
    publicKey: options,
    ...(opts?.conditional ? { mediation: "conditional" as const } : {}),
    ...(opts?.signal ? { signal: opts.signal } : {}),
  });
  try {
    await api.post("/api/webauthn/login/finish", {
      ceremony_id: start.ceremony_id,
      credential: credential.toJSON(),
    });
  } catch (e) {
    // The server has no record of this credential (deleted on another
    // device): tell the platform manager to prune the ghost entry, then
    // surface actionable copy instead of a generic failure.
    if (e instanceof ApiError && e.code === "unknown_credential") {
      await signalUnknownCredential(credential.id);
      throw new WebAuthnError("stale_credential");
    }
    throw e;
  }
}

// ---- Step-up re-authentication ---------------------------------------------

/** Perform a fresh WebAuthn assertion to satisfy a step-up requirement. */
export async function reauth(): Promise<void> {
  const start = await api.post<CeremonyEnvelope>("/api/webauthn/reauth/start");
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(
    start.options.publicKey as PublicKeyCredentialRequestOptionsJSON,
  );
  const credential = await getPasskey({ publicKey: options });
  await api.post("/api/webauthn/reauth/finish", {
    ceremony_id: start.ceremony_id,
    credential: credential.toJSON(),
  });
}

/** Run `fn`; if the server demands a step-up (`reauth_required`), do one and retry once. */
export async function withStepUp<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof ApiError && e.code === "reauth_required") {
      await reauth();
      return await fn();
    }
    throw e;
  }
}

// ---- Recovery --------------------------------------------------------------

/** Redeem a one-time recovery code. Leaves an enroll session (register a passkey next). */
export async function redeemRecoveryCode(code: string): Promise<void> {
  await api.post("/api/recovery/redeem", { code });
}

/** (Re)generate recovery codes (step-up gated). Returns the plaintext codes to show once. */
export async function generateRecoveryCodes(): Promise<string[]> {
  const { codes } = await withStepUp(() =>
    api.post<{ codes: string[] }>("/api/account/recovery-codes"),
  );
  return codes;
}

export function getRecoveryReadiness(): Promise<RecoveryReadiness> {
  return api.get<RecoveryReadiness>("/api/account/recovery-readiness");
}

// ---- Authenticator metadata & client-manager sync --------------------------

const AAGUID_NAMES = aaguidNames as Record<string, string>;

/** credProps.rk: did the authenticator store a discoverable credential? */
function credentialDiscoverable(credential: PublicKeyCredential): boolean | undefined {
  return credential.getClientExtensionResults().credProps?.rk;
}

/** A default passkey label from the authenticator's AAGUID, when recognizable. */
function defaultPasskeyName(credential: PublicKeyCredential): string | undefined {
  const aaguid = parseAaguid(credential);
  return aaguid ? AAGUID_NAMES[aaguid] : undefined;
}

/** Extract the AAGUID (bytes 37–53 of authData) from a registration response. */
function parseAaguid(credential: PublicKeyCredential): string | undefined {
  const response = credential.response;
  if (
    !(response instanceof AuthenticatorAttestationResponse) ||
    typeof response.getAuthenticatorData !== "function"
  ) {
    return undefined;
  }
  const authData = new Uint8Array(response.getAuthenticatorData());
  if (authData.length < 53) return undefined;
  const bytes = authData.slice(37, 53);
  // All-zero AAGUID (attestation=none privacy default) carries no provider info.
  if (bytes.every((b) => b === 0)) return undefined;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface SignalCapableStatic {
  signalAllAcceptedCredentials?: (options: {
    rpId: string;
    userId: string;
    allAcceptedCredentialIds: string[];
  }) => Promise<void>;
  signalUnknownCredential?: (options: { rpId: string; credentialId: string }) => Promise<void>;
  signalCurrentUserDetails?: (options: {
    rpId: string;
    userId: string;
    name: string;
    displayName: string;
  }) => Promise<void>;
}

function signalCapable(): (typeof PublicKeyCredential & SignalCapableStatic) | undefined {
  return (typeof PublicKeyCredential !== "undefined" ? PublicKeyCredential : undefined) as
    | (typeof PublicKeyCredential & SignalCapableStatic)
    | undefined;
}

/**
 * Best-effort WebAuthn Signal API (WebAuthn L3): tell the platform passkey
 * manager the COMPLETE set of credential ids this account still accepts, so it
 * can prune ghost entries for passkeys deleted server-side. Must always be the
 * full valid list — a partial list can make the manager drop live passkeys —
 * and only mutates the calling device. Silently no-ops where unsupported.
 */
export async function signalAcceptedCredentials(
  userIdUuid: string,
  credentialIds: string[],
): Promise<void> {
  const pk = signalCapable();
  if (!pk || typeof pk.signalAllAcceptedCredentials !== "function") return;
  try {
    await pk.signalAllAcceptedCredentials({
      rpId: window.location.hostname,
      // The user handle is the raw 16-byte UUID, base64url-encoded.
      userId: uuidToBase64url(userIdUuid),
      allAcceptedCredentialIds: credentialIds,
    });
  } catch {
    // Purely advisory; never block the UI on a sync hint.
  }
}

/**
 * Best-effort WebAuthn Signal API: the asserted credential is unknown to the
 * server (deleted elsewhere) — let the platform manager prune the ghost entry
 * on this device. Silently no-ops where unsupported.
 */
export async function signalUnknownCredential(credentialId: string): Promise<void> {
  const pk = signalCapable();
  if (!pk || typeof pk.signalUnknownCredential !== "function") return;
  try {
    await pk.signalUnknownCredential({
      rpId: window.location.hostname,
      credentialId,
    });
  } catch {
    // Purely advisory; never block the UI on a sync hint.
  }
}

/**
 * Best-effort WebAuthn Signal API: the account's display name changed — keep
 * the passkey entries in the platform manager labeled correctly.
 */
export async function signalCurrentUserDetails(
  userIdUuid: string,
  nickname: string,
): Promise<void> {
  const pk = signalCapable();
  if (!pk || typeof pk.signalCurrentUserDetails !== "function") return;
  try {
    await pk.signalCurrentUserDetails({
      rpId: window.location.hostname,
      userId: uuidToBase64url(userIdUuid),
      name: nickname,
      displayName: nickname,
    });
  } catch {
    // Purely advisory; never block the UI on a sync hint.
  }
}

function uuidToBase64url(uuid: string): string {
  const hex = uuid.replace(/-/g, "");
  if (hex.length !== 32) return "";
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
