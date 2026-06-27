import { useRouter } from "@tanstack/react-router";
import { useCallback, useState } from "react";
import { toast } from "sonner";

import { ApiError } from "../lib/api.js";

interface RunOptions {
  /** Toast shown on success. Omit to stay silent (e.g. recovery codes). */
  success?: string;
  /** Fallback toast when the error isn't an ApiError with a message. */
  error?: string;
  /** Skip re-running route loaders after success (default: refresh). */
  skipInvalidate?: boolean;
}

/**
 * Uniform wrapper for account mutations: tracks a per-action pending key, shows
 * an error toast (preferring the server's ApiError message), an optional success
 * toast, and re-runs the route loaders via `router.invalidate()` so the UI
 * reflects the new state. Failed mutations never invalidate (no stale flash).
 */
export function useAccountMutation() {
  const router = useRouter();
  const [pendingKey, setPendingKey] = useState<string | null>(null);

  const run = useCallback(
    async <T>(key: string, fn: () => Promise<T>, opts: RunOptions = {}): Promise<T | undefined> => {
      setPendingKey(key);
      try {
        const result = await fn();
        if (opts.success) toast.success(opts.success);
        if (!opts.skipInvalidate) await router.invalidate();
        return result;
      } catch (e) {
        toast.error(e instanceof ApiError ? e.message : (opts.error ?? "Something went wrong"));
        return undefined;
      } finally {
        setPendingKey(null);
      }
    },
    [router],
  );

  return {
    run,
    /** Key of the action currently in flight, or null. */
    pendingKey,
    /** Whether any action is in flight. */
    busy: pendingKey !== null,
    /** True when the given action key is the one in flight. */
    isPending: (key: string) => pendingKey === key,
  };
}
