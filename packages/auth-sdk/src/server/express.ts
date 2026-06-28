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
 * Express middleware that verifies the access token (and a DPoP proof, per the
 * verifier's DPoP mode) and attaches the claims to `req.auth`. Responds 401 with
 * a `WWW-Authenticate` challenge when the token is missing or invalid.
 *
 * Reconstructs the externally-visible method + absolute URL so DPoP `htm`/`htu`
 * binding works. Behind a proxy, ensure `app.set("trust proxy", …)` so
 * `req.protocol`/`req.host` reflect the public origin (or DPoP `htu` will not
 * match what the client signed).
 */
export function requireAuth(verifier: AuthVerifier): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    const headers = new Headers();
    const authorization = req.header("authorization");
    if (authorization) headers.set("authorization", authorization);
    const dpop = req.header("dpop");
    if (dpop) headers.set("dpop", dpop);

    const url = `${req.protocol}://${req.get("host") ?? "localhost"}${req.originalUrl}`;
    const request = new Request(url, { method: req.method, headers });

    verifier
      .authenticateRequest(request)
      .then((result) => {
        if (!result.authenticated) {
          res.setHeader("WWW-Authenticate", result.wwwAuthenticate);
          res.status(401).json({ error: "unauthorized" });
          return;
        }
        req.auth = result.claims;
        next();
      })
      .catch(next);
  };
}
