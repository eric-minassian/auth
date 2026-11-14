/**
 * Concurrency helpers: cross-tab mutual exclusion (Web Locks API, with an
 * in-tab fallback) and in-tab single-flight.
 */

const localQueues = new Map<string, Promise<unknown>>();

/** In-tab mutex used when the Web Locks API is not available. */
function withLocalLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const previous = localQueues.get(name) ?? Promise.resolve();
  const run = previous.then(fn, fn);
  const tail = run.catch(() => undefined);
  localQueues.set(name, tail);
  void tail.then(() => {
    if (localQueues.get(name) === tail) {
      localQueues.delete(name);
    }
  });
  return run;
}

function webLocks(): LockManager | undefined {
  const nav = (globalThis as { navigator?: Partial<Navigator> }).navigator;
  const locks = nav?.locks;
  return locks !== undefined && typeof locks.request === 'function' ? locks : undefined;
}

/**
 * Runs `fn` while holding the exclusive lock `name`. With the Web Locks API the
 * lock is shared by every tab and worker of the origin; otherwise it only
 * serializes callers within this realm.
 */
export function withExclusiveLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const locks = webLocks();
  if (locks === undefined) {
    return withLocalLock(name, fn);
  }
  return locks.request(name, { mode: 'exclusive' }, fn);
}

/** Deduplicates concurrent calls with the same key into one in-flight promise. */
export class SingleFlight<K> {
  readonly #inflight = new Map<K, Promise<unknown>>();

  run<T>(key: K, fn: () => Promise<T>): Promise<T> {
    const existing = this.#inflight.get(key) as Promise<T> | undefined;
    if (existing !== undefined) {
      return existing;
    }
    const promise = fn().finally(() => {
      if (this.#inflight.get(key) === promise) {
        this.#inflight.delete(key);
      }
    });
    this.#inflight.set(key, promise);
    return promise;
  }

  clear(): void {
    this.#inflight.clear();
  }
}
