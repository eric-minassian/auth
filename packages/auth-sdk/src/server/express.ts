import type { NextFunction, Request, RequestHandler, Response } from "express";

import { createLogoutReceiver, type LogoutReceiverOptions } from "./backchannel.js";
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

/**
 * Express handler for the RP's registered `backchannel_logout_uri`. Mount it
 * directly — it reads the raw form body itself, so no body parser is needed
 * (and an urlencoded parser upstream is fine too: the parsed body is used when
 * present).
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
): RequestHandler {
  const receive = createLogoutReceiver(verifier, options);
  return (req: Request, res: Response, next: NextFunction): void => {
    readBody(req)
      .then((body) => {
        const request = new Request("http://receiver.local/backchannel-logout", {
          method: req.method,
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body,
        });
        return receive(request);
      })
      .then(async (response) => {
        response.headers.forEach((value, key) => res.setHeader(key, value));
        res.status(response.status).send(await response.text());
      })
      .catch(next);
  };
}

/** The raw request body — from an upstream body parser when present, else the stream. */
function readBody(req: Request): Promise<string> {
  const parsed = (req as { body?: unknown }).body;
  if (typeof parsed === "string") return Promise.resolve(parsed);
  if (parsed && typeof parsed === "object") {
    return Promise.resolve(new URLSearchParams(parsed as Record<string, string>).toString());
  }
  return new Promise((resolve, reject) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}
