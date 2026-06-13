/** PKCE (RFC 7636) S256 helpers, built on the Web Crypto API. */

const VERIFIER_BYTES = 32;

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomBase64url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

export function createState(): string {
  return randomBase64url(16);
}

export interface PkcePair {
  verifier: string;
  challenge: string;
}

export async function createPkcePair(): Promise<PkcePair> {
  const verifier = randomBase64url(VERIFIER_BYTES);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}
