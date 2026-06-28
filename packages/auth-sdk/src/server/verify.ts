import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  EmbeddedJWK,
  jwtVerify,
  type JWK,
  type JWTVerifyGetKey,
} from "jose";

import { AuthError, DEFAULT_ISSUER } from "../index.js";

/**
 * Resource-server DPoP (RFC 9449) enforcement mode:
 * - `"auto"` (default): verify a DPoP proof whenever the access token is
 *   sender-constrained (`cnf.jkt` present); plain bearer tokens still pass.
 *   This closes the downgrade gap — a bound token can no longer be replayed as
 *   a plain bearer at the RP's own API.
 * - `"required"`: every request MUST carry a sender-constrained token *and* a
 *   valid proof (a plain bearer is rejected).
 * - `"disabled"`: never verify proofs (legacy bearer-only behavior).
 */
export type DpopMode = "auto" | "required" | "disabled";

export interface DpopOptions {
  /** Defaults to `"auto"`. */
  mode?: DpopMode;
  /** Maximum proof age in seconds (defaults to 300, matching the IdP). */
  maxAgeSeconds?: number;
  /**
   * Single-use guard for proof `jti`s. Return `true` (or a promise of it) when
   * this `jti` has already been seen for this key inside the freshness window —
   * the request is then rejected as a replay. Without one, proofs are verified
   * but not replay-protected *at the resource server* (the IdP still rejects
   * replays at its own endpoints). A tiny TTL map keyed by `jti` is enough.
   */
  isReplay?: (input: { jti: string; jkt: string; iat: number }) => boolean | Promise<boolean>;
}

export interface VerifierOptions {
  /** Your registered `client_id` — checked against the token `aud`. */
  audience: string;
  /** Defaults to `https://auth.ericminassian.com`. */
  issuer?: string;
  /** Clock skew tolerance, e.g. `"30s"`. Defaults to `"30s"`. */
  clockTolerance?: string;
  /** Resource-server DPoP enforcement. Defaults to `{ mode: "auto" }`. */
  dpop?: DpopOptions;
}

export interface AccessTokenClaims {
  sub: string;
  sid: string;
  scope: string;
  client_id: string;
  iat: number;
  exp: number;
  jti: string;
  /** Authentication Context Class Reference, e.g. `"phr"` for a phishing-resistant passkey login. */
  acr?: string;
  /** Authentication methods, e.g. `["webauthn"]`. */
  amr?: string[];
  /**
   * DPoP confirmation (RFC 9449). Present when the token is sender-constrained:
   * `cnf.jkt` is the JWK thumbprint of the key it is bound to. `authenticateRequest`
   * verifies a matching proof for it unless DPoP is `"disabled"`.
   */
  cnf?: { jkt: string };
}

export type AuthResult =
  | { authenticated: true; claims: AccessTokenClaims }
  | {
      authenticated: false;
      reason: "missing" | "invalid" | "expired";
      /** Ready-to-send `WWW-Authenticate` header value (RFC 6750 / RFC 9449). */
      wwwAuthenticate: string;
    };

export interface AuthVerifier {
  /** Verify a Bearer access token's JWS; throws `AuthError` on failure. Does NOT check DPoP. */
  verifyAccessToken(token: string): Promise<AccessTokenClaims>;
  /**
   * Authenticate an HTTP `Request`: verify the access token AND, per the DPoP
   * mode, a sender-constraint proof bound to this method/URL/token. Never throws;
   * a failure carries a `WWW-Authenticate` challenge to return verbatim.
   *
   * The `Request` must reflect the real method and absolute URL the client
   * called — the SDK's express/hono adapters build it correctly; a hand-rolled
   * `Request("http://local/")` will fail DPoP `htu` binding.
   */
  authenticateRequest(request: Request): Promise<AuthResult>;
  /** Verify a back-channel logout token (for an RP's logout receiver). */
  verifyLogoutToken(token: string): Promise<{ sub?: string; sid?: string }>;
}

const DEFAULT_PROOF_MAX_AGE = 300;

export function createAuthVerifier(options: VerifierOptions): AuthVerifier {
  const issuer = (options.issuer ?? DEFAULT_ISSUER).replace(/\/$/, "");
  const clockTolerance = options.clockTolerance ?? "30s";
  const dpopMode: DpopMode = options.dpop?.mode ?? "auto";
  const proofMaxAge = options.dpop?.maxAgeSeconds ?? DEFAULT_PROOF_MAX_AGE;
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
        // Pin the algorithm — never let the JWS header pick it (alg confusion).
        algorithms: ["ES256"],
      });
      return payload as unknown as AccessTokenClaims;
    } catch (error) {
      throw new AuthError("invalid_token", describe(error));
    }
  }

  // Which auth schemes this verifier advertises in a WWW-Authenticate challenge.
  function challenge(error?: string, description?: string): string {
    const params: string[] = [];
    if (error) params.push(`error="${error}"`);
    if (description) params.push(`error_description="${description}"`);
    const join = (extra: string[] = []) => [...params, ...extra].join(", ");
    const bearer = `Bearer${params.length ? ` ${join()}` : ""}`;
    const dpop = `DPoP ${join([`algs="ES256"`])}`;
    if (dpopMode === "disabled") return bearer;
    if (dpopMode === "required") return dpop;
    return `${bearer}, ${dpop}`;
  }

  const fail = (
    reason: "missing" | "invalid" | "expired",
    error?: string,
    description?: string,
  ): AuthResult => ({
    authenticated: false,
    reason,
    wwwAuthenticate: challenge(error, description),
  });

  async function authenticateRequest(request: Request): Promise<AuthResult> {
    const header = request.headers.get("authorization") ?? "";
    const space = header.indexOf(" ");
    const scheme = (space === -1 ? header : header.slice(0, space)).toLowerCase();
    const token =
      space !== -1 && (scheme === "bearer" || scheme === "dpop")
        ? header.slice(space + 1).trim()
        : undefined;
    if (!token) return fail("missing");

    let claims: AccessTokenClaims;
    try {
      claims = await verifyAccessToken(token);
    } catch {
      return fail("invalid", "invalid_token");
    }

    if (dpopMode !== "disabled") {
      const boundThumbprint = claims.cnf?.jkt;
      if (dpopMode === "required" && !boundThumbprint) {
        return fail("invalid", "invalid_token", "a sender-constrained (DPoP) token is required");
      }
      if (boundThumbprint) {
        const proof = request.headers.get("dpop");
        if (!proof) {
          return fail("invalid", "invalid_token", "DPoP proof required for a sender-constrained token");
        }
        try {
          const verified = await verifyDpopProof({
            proof,
            method: request.method,
            url: request.url,
            accessToken: token,
            expectedThumbprint: boundThumbprint,
            maxAgeSeconds: proofMaxAge,
            clockTolerance,
          });
          if (options.dpop?.isReplay && (await options.dpop.isReplay(verified))) {
            return fail("invalid", "invalid_token", "DPoP proof replay");
          }
        } catch (error) {
          return fail("invalid", "invalid_token", error instanceof AuthError ? error.message : "invalid DPoP proof");
        }
      }
    }

    return { authenticated: true, claims };
  }

  return {
    verifyAccessToken,
    authenticateRequest,

    async verifyLogoutToken(token): Promise<{ sub?: string; sid?: string }> {
      try {
        const { payload } = await jwtVerify(token, jwks, {
          issuer,
          audience: options.audience,
          clockTolerance,
          // Per OIDC Back-Channel Logout 1.0: typ MUST be logout+jwt, so an
          // access/ID token can never be replayed through this path.
          typ: "logout+jwt",
          algorithms: ["ES256"],
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
        // Spec MUST: a logout token identifies a subject, a session, or both.
        if (result.sub === undefined && result.sid === undefined) {
          throw new AuthError("invalid_token", "logout token has neither sub nor sid");
        }
        return result;
      } catch (error) {
        if (error instanceof AuthError) throw error;
        throw new AuthError("invalid_token", describe(error));
      }
    },
  };
}

export interface DpopProofInput {
  /** The `DPoP` header value (a `dpop+jwt` JWS). */
  proof: string;
  /** The request's HTTP method (`htm`). */
  method: string;
  /** The request's absolute URL (`htu`; query/fragment ignored). */
  url: string;
  /** The access token presented alongside, bound via the proof's `ath`. */
  accessToken: string;
  /** The token's `cnf.jkt` the proof key must match. */
  expectedThumbprint: string;
  /** Max proof age in seconds (default 300). */
  maxAgeSeconds?: number;
  /** Clock skew, e.g. `"30s"` (default `"30s"`). */
  clockTolerance?: string;
}

/**
 * Verify a standalone DPoP proof against a request. Returns the key thumbprint
 * (`jkt`), proof id (`jti`), and `iat` on success — a caller can use the `jti`
 * to enforce single-use. Throws `AuthError` on any mismatch. Exposed for RPs
 * that authenticate outside the express/hono adapters.
 */
export async function verifyDpopProof(
  input: DpopProofInput,
): Promise<{ jkt: string; jti: string; iat: number }> {
  const maxTokenAge = input.maxAgeSeconds ?? DEFAULT_PROOF_MAX_AGE;
  let payload: Record<string, unknown>;
  let jwk: JWK | undefined;
  try {
    const result = await jwtVerify(input.proof, EmbeddedJWK, {
      algorithms: ["ES256"],
      typ: "dpop+jwt",
      maxTokenAge,
      clockTolerance: input.clockTolerance ?? "30s",
    });
    payload = result.payload as Record<string, unknown>;
    jwk = result.protectedHeader.jwk;
  } catch (error) {
    throw new AuthError("invalid_token", `invalid DPoP proof: ${describe(error)}`);
  }

  // The embedded JWK must be a public key, and its thumbprint must be the one
  // the access token committed to (cnf.jkt).
  if (!jwk || (jwk as Record<string, unknown>)["d"] !== undefined) {
    throw new AuthError("invalid_token", "DPoP proof must embed a public JWK");
  }
  const jkt = await calculateJwkThumbprint(jwk, "sha256");
  if (jkt !== input.expectedThumbprint) {
    throw new AuthError("invalid_token", "DPoP key does not match the token");
  }

  // Bind to this exact request.
  if (payload["htm"] !== input.method.toUpperCase()) {
    throw new AuthError("invalid_token", "DPoP htm mismatch");
  }
  if (normalizeHtu(String(payload["htu"] ?? "")) !== normalizeHtu(input.url)) {
    throw new AuthError("invalid_token", "DPoP htu mismatch");
  }
  // Bind to this access token.
  const ath = await sha256b64u(input.accessToken);
  if (payload["ath"] !== ath) {
    throw new AuthError("invalid_token", "DPoP ath mismatch");
  }

  const iat = typeof payload["iat"] === "number" ? payload["iat"] : 0;
  const jti = typeof payload["jti"] === "string" ? payload["jti"] : "";
  if (!jti) throw new AuthError("invalid_token", "DPoP proof missing jti");
  return { jkt, jti, iat };
}

export interface StepUpChallengeOptions {
  /** `acr_values` the RP requires, e.g. `"phr-stepup"`. */
  acrValues?: string;
  /** `max_age` (seconds) the backing authentication must be within. */
  maxAge?: number;
  /** Human-readable hint. */
  description?: string;
  /** Auth scheme to name in the challenge. Defaults to `"DPoP"`. */
  scheme?: "Bearer" | "DPoP";
}

/**
 * Build an RFC 9470 step-up challenge for a resource server: a `401`
 * `WWW-Authenticate` with `error="insufficient_user_authentication"` plus the
 * `acr_values`/`max_age` the client must satisfy. The client re-authenticates
 * (`signInWithRedirect({ acrValues, maxAge })`) and the IdP performs the
 * step-up, returning a token whose `acr` clears the bar.
 */
export function stepUpChallenge(options: StepUpChallengeOptions = {}): string {
  const scheme = options.scheme ?? "DPoP";
  const params = [`error="insufficient_user_authentication"`];
  if (options.description) params.push(`error_description="${options.description}"`);
  if (options.acrValues) params.push(`acr_values="${options.acrValues}"`);
  if (options.maxAge !== undefined) params.push(`max_age="${options.maxAge}"`);
  if (scheme === "DPoP") params.push(`algs="ES256"`);
  return `${scheme} ${params.join(", ")}`;
}

function normalizeHtu(htu: string): string {
  const cut = htu.search(/[?#]/);
  return cut === -1 ? htu : htu.slice(0, cut);
}

async function sha256b64u(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : "token verification failed";
}
