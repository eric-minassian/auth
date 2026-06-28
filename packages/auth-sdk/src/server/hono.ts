import type { Context, MiddlewareHandler } from "hono";

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
