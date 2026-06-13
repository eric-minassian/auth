import type { NextFunction, Request, RequestHandler, Response } from "express";

import type { AccessTokenClaims, AuthVerifier } from "./verify.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AccessTokenClaims;
    }
  }
}

/**
 * Express middleware that verifies the Bearer access token and attaches the
 * claims to `req.auth`. Responds 401 when the token is missing or invalid.
 */
export function requireAuth(verifier: AuthVerifier): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.header("authorization");
    const request = new Request("http://local/", {
      headers: header ? { authorization: header } : {},
    });
    verifier
      .authenticateRequest(request)
      .then((result) => {
        if (!result.authenticated) {
          res.status(401).json({ error: "unauthorized" });
          return;
        }
        req.auth = result.claims;
        next();
      })
      .catch(next);
  };
}
