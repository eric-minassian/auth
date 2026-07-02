import type { Context, Handler, MiddlewareHandler } from "hono";

import { createLogoutReceiver, type LogoutReceiverOptions } from "./backchannel.js";
import type { AccessTokenClaims, AuthVerifier } from "./verify.js";

declare module "hono" {
  interface ContextVariableMap {
    auth: AccessTokenClaims;
  }
}

/**
 * Hono middleware that verifies the access token (and a DPoP proof, per the
 * verifier's DPoP mode) and stores the claims at `c.var.auth`. Responds 401 with
 * a `WWW-Authenticate` challenge when the token is missing or invalid.
 *
 * `c.req.raw` is a real `Request` carrying the method, absolute URL, and `DPoP`
 * header, so DPoP `htm`/`htu` binding works out of the box.
 */
export function authMiddleware(verifier: AuthVerifier): MiddlewareHandler {
  return async (c: Context, next) => {
    const result = await verifier.authenticateRequest(c.req.raw);
    if (!result.authenticated) {
      c.header("WWW-Authenticate", result.wwwAuthenticate);
      return c.json({ error: "unauthorized" }, 401);
    }
    c.set("auth", result.claims);
    await next();
  };
}

/**
 * Hono handler for the RP's registered `backchannel_logout_uri`. `c.req.raw`
 * is a real `Request`, so the receiver consumes it directly.
 *
 * ```ts
 * app.post("/auth/backchannel-logout", logoutReceiver(verifier, {
 *   onLogout: ({ sid }) => sessions.deleteByIdpSid(sid),
 *   isReplay: inMemoryReplayCache(),
 * }));
 * ```
 */
export function logoutReceiver(
  verifier: AuthVerifier,
  options: LogoutReceiverOptions,
): Handler {
  const receive = createLogoutReceiver(verifier, options);
  return (c: Context) => receive(c.req.raw);
}
