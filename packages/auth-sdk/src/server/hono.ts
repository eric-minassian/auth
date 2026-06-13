import type { Context, MiddlewareHandler } from "hono";

import type { AccessTokenClaims, AuthVerifier } from "./verify.js";

declare module "hono" {
  interface ContextVariableMap {
    auth: AccessTokenClaims;
  }
}

/**
 * Hono middleware that verifies the Bearer access token and stores the claims
 * at `c.var.auth`. Responds 401 when the token is missing or invalid.
 */
export function authMiddleware(verifier: AuthVerifier): MiddlewareHandler {
  return async (c: Context, next) => {
    const result = await verifier.authenticateRequest(c.req.raw);
    if (!result.authenticated) {
      return c.json({ error: "unauthorized" }, 401);
    }
    c.set("auth", result.claims);
    await next();
  };
}
