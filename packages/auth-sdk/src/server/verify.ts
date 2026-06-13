import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";

import { AuthError, DEFAULT_ISSUER } from "../index.js";

export interface VerifierOptions {
  /** Your registered `client_id` — checked against the token `aud`. */
  audience: string;
  /** Defaults to `https://auth.ericminassian.com`. */
  issuer?: string;
  /** Clock skew tolerance, e.g. `"30s"`. Defaults to `"30s"`. */
  clockTolerance?: string;
}

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  scope: string;
  client_id: string;
  iat: number;
  exp: number;
  jti: string;
  email?: string;
}

export type AuthResult =
  | { authenticated: true; claims: AccessTokenClaims }
  | { authenticated: false; reason: "missing" | "invalid" | "expired" };

export interface AuthVerifier {
  /** Verify a Bearer access token; throws `AuthError` on failure. */
  verifyAccessToken(token: string): Promise<AccessTokenClaims>;
  /** Inspect an HTTP `Request`'s `Authorization: Bearer` header. Never throws. */
  authenticateRequest(request: Request): Promise<AuthResult>;
  /** Verify a back-channel logout token (for an RP's logout receiver). */
  verifyLogoutToken(token: string): Promise<{ sub?: string; sid?: string }>;
}

export function createAuthVerifier(options: VerifierOptions): AuthVerifier {
  const issuer = (options.issuer ?? DEFAULT_ISSUER).replace(/\/$/, "");
  const clockTolerance = options.clockTolerance ?? "30s";
  // Module-singleton-equivalent: one JWKS set per verifier, so the 10-minute
  // cache and unknown-kid refetch behavior are shared across requests.
  const jwks: JWTVerifyGetKey = createRemoteJWKSet(
    new URL(`${issuer}/.well-known/jwks.json`),
  );

  async function verifyAccessToken(token: string): Promise<AccessTokenClaims> {
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer,
        audience: options.audience,
        clockTolerance,
        typ: "at+jwt",
      });
      return payload as unknown as AccessTokenClaims;
    } catch (error) {
      throw new AuthError("invalid_token", describe(error));
    }
  }

  return {
    verifyAccessToken,

    async authenticateRequest(request): Promise<AuthResult> {
      const header = request.headers.get("authorization");
      const token = header?.startsWith("Bearer ") ? header.slice(7) : undefined;
      if (!token) return { authenticated: false, reason: "missing" };
      try {
        const claims = await verifyAccessToken(token);
        return { authenticated: true, claims };
      } catch {
        return { authenticated: false, reason: "invalid" };
      }
    },

    async verifyLogoutToken(token): Promise<{ sub?: string; sid?: string }> {
      try {
        const { payload } = await jwtVerify(token, jwks, {
          issuer,
          audience: options.audience,
          clockTolerance,
        });
        const events = payload["events"] as Record<string, unknown> | undefined;
        if (!events?.["http://schemas.openid.net/event/backchannel-logout"]) {
          throw new AuthError("invalid_token", "not a back-channel logout token");
        }
        if ("nonce" in payload) {
          throw new AuthError("invalid_token", "logout token must not contain a nonce");
        }
        const result: { sub?: string; sid?: string } = {};
        if (typeof payload.sub === "string") result.sub = payload.sub;
        if (typeof payload["sid"] === "string") result.sid = payload["sid"] as string;
        return result;
      } catch (error) {
        if (error instanceof AuthError) throw error;
        throw new AuthError("invalid_token", describe(error));
      }
    },
  };
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : "token verification failed";
}
