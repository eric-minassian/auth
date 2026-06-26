/**
 * DPoP (RFC 9449) proof-of-possession for the browser client.
 *
 * A non-extractable P-256 key is generated once and kept in IndexedDB; the
 * private key never leaves WebCrypto, so even an XSS that exfiltrates the
 * refresh token from `sessionStorage` cannot redeem it — rotation requires a
 * fresh proof signed by this key. (DPoP is a large but not total mitigation: an
 * in-page payload can still use the key as a signing oracle while it runs.)
 */

const DB_NAME = "ema_auth";
const STORE = "keys";
const KEY_ID = "dpop_p256";

export interface DpopProofOptions {
  /** Server-issued DPoP-Nonce to echo, if challenged. */
  nonce?: string;
  /** Access token to bind via the `ath` claim (resource-server proofs). */
  accessToken?: string;
}

export interface DpopSigner {
  /** Build a DPoP proof JWT for `htm` (method) + `htu` (URL). */
  proof(htm: string, htu: string, options?: DpopProofOptions): Promise<string>;
}

/**
 * Create a DPoP signer, or `undefined` when WebCrypto/IndexedDB are unavailable
 * (non-browser, or a hardened environment) — the client then falls back to
 * plain bearer tokens, which the server still accepts.
 */
export function createDpopSigner(): DpopSigner | undefined {
  if (
    typeof indexedDB === "undefined" ||
    typeof crypto === "undefined" ||
    !crypto.subtle
  ) {
    return undefined;
  }

  let keyPromise: Promise<CryptoKeyPair> | undefined;
  const getKey = (): Promise<CryptoKeyPair> => (keyPromise ??= loadOrCreateKey());

  return {
    async proof(htm, htu, options): Promise<string> {
      const { privateKey, publicKey } = await getKey();
      const jwk = (await crypto.subtle.exportKey("jwk", publicKey)) as JsonWebKey;
      const header = {
        typ: "dpop+jwt",
        alg: "ES256",
        // Only the public coordinates — never the private `d`.
        jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      };
      const payload: Record<string, unknown> = {
        jti: randomJti(),
        htm,
        // Bind to the URL without query/fragment (RFC 9449 §4.3).
        htu: htu.split(/[?#]/)[0],
        iat: Math.floor(Date.now() / 1000),
      };
      if (options?.nonce) payload.nonce = options.nonce;
      if (options?.accessToken) payload.ath = await sha256b64u(options.accessToken);

      const signingInput = `${b64uJson(header)}.${b64uJson(payload)}`;
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        new TextEncoder().encode(signingInput),
      );
      // WebCrypto ECDSA emits the raw r||s form JWS ES256 expects.
      return `${signingInput}.${b64u(new Uint8Array(signature))}`;
    },
  };
}

async function loadOrCreateKey(): Promise<CryptoKeyPair> {
  const existing = await idbGet(KEY_ID);
  if (isKeyPair(existing)) return existing;
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    // Non-extractable: the private key can never be serialized out of WebCrypto.
    // (The public key stays exportable regardless, per the WebCrypto spec.)
    false,
    ["sign", "verify"],
  );
  await idbPut(KEY_ID, pair);
  return pair;
}

function isKeyPair(value: unknown): value is CryptoKeyPair {
  return (
    typeof value === "object" &&
    value !== null &&
    "privateKey" in value &&
    "publicKey" in value
  );
}

// --- IndexedDB (CryptoKey is structured-cloneable, even when non-extractable) ---

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbGet(key: string): Promise<unknown> {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

async function idbPut(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

// --- encoding helpers ---

function randomJti(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return b64u(bytes);
}

async function sha256b64u(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return b64u(new Uint8Array(digest));
}

function b64uJson(value: unknown): string {
  return b64u(new TextEncoder().encode(JSON.stringify(value)));
}

function b64u(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
