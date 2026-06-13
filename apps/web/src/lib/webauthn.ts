/**
 * Bridges the server's webauthn-rs ceremony options to the browser WebAuthn
 * API. The server serializes options in the standard WebAuthn JSON form (a
 * `{ publicKey: … }` envelope with base64url buffers), so the native
 * `parse*OptionsFromJSON` / `toJSON` helpers handle the conversion with no
 * extra dependency.
 */
import { api } from "./api.js";

interface CeremonyEnvelope {
  ceremony_id: string;
  // The webauthn-rs CreationChallengeResponse / RequestChallengeResponse,
  // both shaped as `{ publicKey: … }`.
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

/** Register a new passkey for the current (enroll or full) session. */
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

/**
 * Authenticate with a passkey. `conditional` uses the browser's autofill UI;
 * `signal` lets the caller abort a pending conditional request.
 */
export async function loginWithPasskey(opts?: {
  email?: string;
  conditional?: boolean;
  signal?: AbortSignal;
}): Promise<void> {
  const start = await api.post<CeremonyEnvelope>("/api/webauthn/login/start", {
    email: opts?.email,
  });
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
