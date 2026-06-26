/**
 * Bridges the server's webauthn-rs ceremony options to the browser WebAuthn API
 * and drives the email-free flows: passkey signup (gated by a client-side
 * proof-of-work), usernameless discoverable login, step-up re-authentication,
 * and recovery codes. The server serializes options in the standard WebAuthn
 * JSON form (`{ publicKey: … }`), so the native `parse*OptionsFromJSON` / `toJSON`
 * helpers handle conversion with no extra dependency.
 */
import { ApiError, api, type RecoveryReadiness } from "./api.js";

interface CeremonyEnvelope {
  ceremony_id: string;
  options: { publicKey: unknown };
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
export async function signUp(nickname: string, passkeyName?: string): Promise<void> {
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
  const credential = (await navigator.credentials.create({
    publicKey: options,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("passkey creation was cancelled");
  await api.post("/api/signup/finish", {
    ceremony_id: start.ceremony_id,
    credential: credential.toJSON(),
    name: passkeyName,
  });
}

// ---- Passkey registration (add a passkey / re-onboard after recovery) ------

/** Register a passkey for the current (enroll or full) session. */
export async function registerPasskey(name?: string): Promise<void> {
  const start = await api.post<CeremonyEnvelope>("/api/webauthn/register/start");
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(
    start.options.publicKey as PublicKeyCredentialCreationOptionsJSON,
  );
  const credential = (await navigator.credentials.create({
    publicKey: options,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("passkey creation was cancelled");
  await api.post("/api/webauthn/register/finish", {
    ceremony_id: start.ceremony_id,
    credential: credential.toJSON(),
    name,
  });
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
  const credential = (await navigator.credentials.get({
    publicKey: options,
    ...(opts?.conditional ? { mediation: "conditional" as const } : {}),
    ...(opts?.signal ? { signal: opts.signal } : {}),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("passkey authentication was cancelled");
  await api.post("/api/webauthn/login/finish", {
    ceremony_id: start.ceremony_id,
    credential: credential.toJSON(),
  });
}

// ---- Step-up re-authentication ---------------------------------------------

/** Perform a fresh WebAuthn assertion to satisfy a step-up requirement. */
export async function reauth(): Promise<void> {
  const start = await api.post<CeremonyEnvelope>("/api/webauthn/reauth/start");
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(
    start.options.publicKey as PublicKeyCredentialRequestOptionsJSON,
  );
  const credential = (await navigator.credentials.get({
    publicKey: options,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("re-authentication was cancelled");
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
