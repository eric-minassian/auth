import { AuthError } from "../index.js";
import type { AuthVerifier } from "./verify.js";

/**
 * Back-channel logout receiver (OIDC Back-Channel Logout 1.0).
 *
 * The IdP POSTs `logout_token=<JWS>` (form-encoded) to the RP's registered
 * `backchannel_logout_uri` whenever a session it issued ends. The receiver
 * verifies the token via the verifier's JWKS (signature, iss/aud/exp,
 * `typ: logout+jwt`, the `events` claim, no `nonce`) and hands `{ sub, sid }`
 * to the RP's callback so it can end its own session(s).
 */
export interface LogoutReceiverOptions {
  /**
   * End the RP-side session(s). `sid` is the IdP session id (matches the `sid`
   * claim in the id_token the RP received at login); `sub` identifies the user
   * when the token is session-less. At least one is always present.
   */
  onLogout: (event: { sub?: string; sid?: string }) => void | Promise<void>;
  /**
   * Single-use guard for the token `jti`. Return `true` (or a promise of it)
   * when this `jti` has already been seen — the request is then rejected as a
   * replay. Use {@link inMemoryReplayCache} for single-process servers; back it
   * with shared storage when running multiple instances.
   */
  isReplay?: (jti: string) => boolean | Promise<boolean>;
}

/**
 * Build a framework-agnostic receiver: a `(Request) => Response` handler for
 * the RP's `backchannel_logout_uri` route. Responds per spec: `200` once the
 * logout has been processed, `400` with an OAuth-style error body otherwise —
 * both with `Cache-Control: no-store`. Prefer the express/hono adapters
 * (`logoutReceiver` in their modules) where applicable.
 */
export function createLogoutReceiver(
  verifier: AuthVerifier,
  options: LogoutReceiverOptions,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    if (request.method.toUpperCase() !== "POST") {
      return errorResponse(405, "invalid_request", "logout notifications are POSTed");
    }
    let token: string | null;
    try {
      const form = new URLSearchParams(await request.text());
      token = form.get("logout_token");
    } catch {
      token = null;
    }
    if (!token) {
      return errorResponse(400, "invalid_request", "missing logout_token");
    }

    let event: { sub?: string; sid?: string; jti?: string };
    try {
      event = await verifier.verifyLogoutToken(token);
    } catch (error) {
      return errorResponse(
        400,
        "invalid_request",
        error instanceof AuthError ? error.message : "invalid logout token",
      );
    }
    if (options.isReplay && event.jti && (await options.isReplay(event.jti))) {
      return errorResponse(400, "invalid_request", "logout token replay");
    }

    const payload: { sub?: string; sid?: string } = {};
    if (event.sub !== undefined) payload.sub = event.sub;
    if (event.sid !== undefined) payload.sid = event.sid;
    try {
      await options.onLogout(payload);
    } catch {
      // The RP's cleanup failed; per spec the OP treats non-200 as undelivered
      // and may retry, which is exactly what we want here.
      return errorResponse(400, "server_error", "logout handling failed");
    }
    return new Response(null, {
      status: 200,
      headers: { "cache-control": "no-store" },
    });
  };
}

/**
 * A process-local `jti` replay cache for {@link LogoutReceiverOptions.isReplay}.
 * Remembers each `jti` for `ttlSeconds` (default 600 — comfortably past the
 * logout token's own lifetime, after which `exp` rejects it anyway).
 */
export function inMemoryReplayCache(ttlSeconds = 600): (jti: string) => boolean {
  const seen = new Map<string, number>();
  return (jti: string): boolean => {
    const now = Date.now();
    for (const [key, expires] of seen) {
      if (expires <= now) seen.delete(key);
    }
    if (seen.has(jti)) return true;
    seen.set(jti, now + ttlSeconds * 1000);
    return false;
  };
}

function errorResponse(status: number, error: string, description: string): Response {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
