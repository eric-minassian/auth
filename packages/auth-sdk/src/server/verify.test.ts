import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthError } from "../index.js";
import { createAuthVerifier } from "./verify.js";

const ISSUER = "https://auth.test";
const AUDIENCE = "rp";

// A self-contained issuer: an ES256 keypair whose public JWK is served from a
// stubbed fetch, exactly as the Rust service publishes it.
async function setupIssuer() {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "test-kid";
  jwk.alg = "ES256";
  jwk.use = "sig";

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL) => {
      if (String(url).endsWith("/.well-known/jwks.json")) {
        return new Response(JSON.stringify({ keys: [jwk] }), {
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    }),
  );

  const sign = (claims: Record<string, unknown>, typ = "at+jwt") =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: "test-kid", typ })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setExpirationTime("10m")
      .sign(privateKey);

  return { sign };
}

describe("createAuthVerifier", () => {
  let sign: Awaited<ReturnType<typeof setupIssuer>>["sign"];

  beforeEach(async () => {
    ({ sign } = await setupIssuer());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies a well-formed access token", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const token = await sign({
      sub: "user-1",
      sid: "sid-1",
      scope: "openid email",
      client_id: AUDIENCE,
      jti: "jti-1",
      email: "a@test.dev",
    });
    const claims = await verifier.verifyAccessToken(token);
    expect(claims.sub).toBe("user-1");
    expect(claims.scope).toBe("openid email");
    expect(claims.email).toBe("a@test.dev");
  });

  it("rejects a token with the wrong audience", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: "someone-else" });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "j" });
    await expect(verifier.verifyAccessToken(token)).rejects.toBeInstanceOf(AuthError);
  });

  it("authenticateRequest reports missing vs invalid without throwing", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });

    const noHeader = await verifier.authenticateRequest(new Request("http://x/"));
    expect(noHeader).toEqual({ authenticated: false, reason: "missing" });

    const bad = await verifier.authenticateRequest(
      new Request("http://x/", { headers: { authorization: "Bearer not.a.jwt" } }),
    );
    expect(bad).toEqual({ authenticated: false, reason: "invalid" });

    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "j" });
    const ok = await verifier.authenticateRequest(
      new Request("http://x/", { headers: { authorization: `Bearer ${token}` } }),
    );
    expect(ok.authenticated).toBe(true);
  });

  it("verifies a back-channel logout token and rejects one with a nonce", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const logoutToken = await sign(
      {
        sub: "user-1",
        sid: "sid-1",
        jti: "j",
        events: { "http://schemas.openid.net/event/backchannel-logout": {} },
      },
      "logout+jwt",
    );
    const result = await verifier.verifyLogoutToken(logoutToken);
    expect(result).toEqual({ sub: "user-1", sid: "sid-1" });

    const withNonce = await sign({
      sub: "user-1",
      sid: "sid-1",
      jti: "j",
      nonce: "no",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    await expect(verifier.verifyLogoutToken(withNonce)).rejects.toBeInstanceOf(AuthError);
  });
});
