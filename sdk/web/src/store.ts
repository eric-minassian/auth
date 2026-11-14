/**
 * Persistent session storage in IndexedDB.
 *
 * The record holds the device key pair as structured-cloned `CryptoKey`
 * objects (the private key is non-extractable, so its bytes are never
 * reachable from JavaScript) next to the DPoP-bound refresh token, which is
 * useless without that key. Access tokens are never persisted.
 */
import { AuthError } from './errors.js';
import { isBase64url } from './base64url.js';
import { isToken68 } from './validate.js';

export interface StoredSession {
  readonly v: 1;
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly refreshToken: string;
  /** Local epoch ms after which the refresh token is certainly expired (advisory). */
  readonly refreshExpiresAt: number | null;
  /** base64url account ID (the token `sub`). */
  readonly accountId: string;
  /** RP ID of the ceremony that started the session (for the Signal API). */
  readonly rpId: string | null;
}

export interface SessionStore {
  load(): Promise<StoredSession | undefined>;
  save(session: StoredSession): Promise<void>;
  clear(): Promise<void>;
}

const STORE = 'sessions';
const DB_VERSION = 1;

function storageError(cause: unknown): AuthError {
  return new AuthError('storage_unavailable', 'IndexedDB is unavailable or failed', { cause });
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return typeof CryptoKey !== 'undefined' && value instanceof CryptoKey;
}

/** Shape check of a record read back from storage. */
export function isStoredSession(value: unknown): value is StoredSession {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const r = value as Record<string, unknown>;
  return (
    r['v'] === 1 &&
    isCryptoKey(r['privateKey']) &&
    isCryptoKey(r['publicKey']) &&
    isToken68(r['refreshToken']) &&
    (r['refreshExpiresAt'] === null ||
      (typeof r['refreshExpiresAt'] === 'number' && Number.isFinite(r['refreshExpiresAt']))) &&
    isBase64url(r['accountId'], 16, 16) &&
    (r['rpId'] === null || (typeof r['rpId'] === 'string' && r['rpId'].length > 0))
  );
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => {
      resolve(req.result);
    };
    req.onerror = () => {
      reject(storageError(req.error));
    };
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => {
      resolve();
    };
    tx.onerror = () => {
      reject(storageError(tx.error));
    };
    tx.onabort = () => {
      reject(storageError(tx.error ?? new Error('transaction aborted')));
    };
  });
}

export class IndexedDbSessionStore implements SessionStore {
  readonly #dbName: string;
  readonly #key: string;
  #db: Promise<IDBDatabase> | undefined;

  constructor(dbName: string, key: string) {
    this.#dbName = dbName;
    this.#key = key;
  }

  #open(): Promise<IDBDatabase> {
    if (this.#db !== undefined) {
      return this.#db;
    }
    const factory = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    if (factory === undefined) {
      return Promise.reject(storageError(new Error('indexedDB is not defined')));
    }
    const opening = new Promise<IDBDatabase>((resolve, reject) => {
      let req: IDBOpenDBRequest;
      try {
        req = factory.open(this.#dbName, DB_VERSION);
      } catch (error) {
        reject(storageError(error));
        return;
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);
        }
      };
      req.onsuccess = () => {
        const db = req.result;
        // Let other tabs upgrade the schema; reopen lazily afterwards.
        db.onversionchange = () => {
          db.close();
          this.#db = undefined;
        };
        db.onclose = () => {
          this.#db = undefined;
        };
        resolve(db);
      };
      req.onerror = () => {
        reject(storageError(req.error));
      };
    });
    this.#db = opening;
    opening.catch(() => {
      this.#db = undefined;
    });
    return opening;
  }

  async load(): Promise<StoredSession | undefined> {
    const db = await this.#open();
    let value: unknown;
    try {
      const tx = db.transaction(STORE, 'readonly');
      value = await request(tx.objectStore(STORE).get(this.#key));
    } catch (error) {
      throw error instanceof AuthError ? error : storageError(error);
    }
    if (value === undefined) {
      return undefined;
    }
    if (!isStoredSession(value)) {
      // Corrupt or from an incompatible version: it cannot be used safely.
      await this.clear();
      return undefined;
    }
    return value;
  }

  async save(session: StoredSession): Promise<void> {
    const db = await this.#open();
    try {
      const tx = db.transaction(STORE, 'readwrite', { durability: 'strict' });
      const done = transactionDone(tx);
      tx.objectStore(STORE).put(session, this.#key);
      await done;
    } catch (error) {
      throw error instanceof AuthError ? error : storageError(error);
    }
  }

  async clear(): Promise<void> {
    const db = await this.#open();
    try {
      const tx = db.transaction(STORE, 'readwrite', { durability: 'strict' });
      const done = transactionDone(tx);
      tx.objectStore(STORE).delete(this.#key);
      await done;
    } catch (error) {
      throw error instanceof AuthError ? error : storageError(error);
    }
  }

  /** Closes the connection (it is reopened on demand). */
  close(): void {
    const db = this.#db;
    this.#db = undefined;
    void db
      ?.then((d) => {
        d.close();
      })
      .catch(() => undefined);
  }
}
