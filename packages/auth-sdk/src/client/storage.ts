/**
 * Pluggable persistence for the refresh token and the in-flight authorization
 * transaction (PKCE verifier + state). Access tokens are never persisted —
 * they live in memory only.
 */
export interface TokenStorage {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

/** Default storage: `sessionStorage` when available, else an in-memory map. */
export function defaultStorage(): TokenStorage {
  if (typeof sessionStorage !== "undefined") {
    return {
      get: (key) => sessionStorage.getItem(key),
      set: (key, value) => sessionStorage.setItem(key, value),
      remove: (key) => sessionStorage.removeItem(key),
    };
  }
  const map = new Map<string, string>();
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => {
      map.set(key, value);
    },
    remove: (key) => {
      map.delete(key);
    },
  };
}
