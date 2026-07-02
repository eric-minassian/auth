import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type JWK,
  SignJWT,
} from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthError } from "../index.js";
import { createAuthVerifier, stepUpChallenge } from "./verify.js";

async function sha256b64u(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

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
      scope: "openid profile",
      client_id: AUDIENCE,
      jti: "jti-1",
    });
    const claims = await verifier.verifyAccessToken(token);
    expect(claims.sub).toBe("user-1");
    expect(claims.scope).toBe("openid profile");
  });

  it("rejects a token with the wrong audience", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: "someone-else" });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "j" });
    await expect(verifier.verifyAccessToken(token)).rejects.toBeInstanceOf(AuthError);
  });

  it("authenticateRequest reports missing vs invalid without throwing", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });

    const noHeader = await verifier.authenticateRequest(new Request("http://x/"));
    expect(noHeader.authenticated).toBe(false);
    if (!noHeader.authenticated) {
      expect(noHeader.reason).toBe("missing");
      expect(noHeader.wwwAuthenticate).toContain("Bearer");
    }

    const bad = await verifier.authenticateRequest(
      new Request("http://x/", { headers: { authorization: "Bearer not.a.jwt" } }),
    );
    expect(bad.authenticated).toBe(false);
    if (!bad.authenticated) {
      expect(bad.reason).toBe("invalid");
      expect(bad.wwwAuthenticate).toContain('error="invalid_token"');
    }

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
    expect(result).toEqual({ sub: "user-1", sid: "sid-1", jti: "j" });

    const withNonce = await sign(
      {
        sub: "user-1",
        sid: "sid-1",
        jti: "j",
        nonce: "no",
        events: { "http://schemas.openid.net/event/backchannel-logout": {} },
      },
      "logout+jwt",
    );
    await expect(verifier.verifyLogoutToken(withNonce)).rejects.toBeInstanceOf(AuthError);
  });

  it("rejects an access token replayed as a logout token (typ pinned)", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    // typ defaults to at+jwt; even with a logout events claim it must not pass.
    const accessShaped = await sign({
      sub: "user-1",
      sid: "sid-1",
      jti: "j",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    await expect(verifier.verifyLogoutToken(accessShaped)).rejects.toBeInstanceOf(AuthError);
  });

  it("rejects a logout token that identifies neither sub nor sid", async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const noSubject = await sign(
      { jti: "j", events: { "http://schemas.openid.net/event/backchannel-logout": {} } },
      "logout+jwt",
    );
    await expect(verifier.verifyLogoutToken(noSubject)).rejects.toBeInstanceOf(AuthError);
  });
});

describe("DPoP-bound access tokens (RFC 9449)", () => {
  const RS_URL = "https://api.rp.test/data";
  let sign: Awaited<ReturnType<typeof setupIssuer>>["sign"];

  beforeEach(async () => {
    ({ sign } = await setupIssuer());
  });
  afterEach(() => vi.unstubAllGlobals());

  // A DPoP keypair, its public JWK, and the matching cnf.jkt thumbprint.
  async function dpopKey() {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const jwk = (await exportJWK(publicKey)) as JWK;
    const jkt = await calculateJwkThumbprint(jwk, "sha256");
    return { privateKey, jwk, jkt };
  }

  function proof(
    key: Awaited<ReturnType<typeof dpopKey>>,
    claims: { htm: string; htu: string; ath: string; jti?: string },
  ): Promise<string> {
    return new SignJWT({ htm: claims.htm, htu: claims.htu, ath: claims.ath, jti: claims.jti ?? "j1" })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: key.jwk })
      .setIssuedAt()
      .sign(key.privateKey);
  }

  function request(token: string, dpopProof?: string): Request {
    const headers: Record<string, string> = { authorization: `DPoP ${token}` };
    if (dpopProof) headers["dpop"] = dpopProof;
    return new Request(RS_URL, { method: "GET", headers });
  }

  it("accepts a bound token with a matching proof", async () => {
    const key = await dpopKey();
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "t", cnf: { jkt: key.jkt } });
    const p = await proof(key, { htm: "GET", htu: RS_URL, ath: await sha256b64u(token) });
    const result = await verifier.authenticateRequest(request(token, p));
    expect(result.authenticated).toBe(true);
  });

  it("rejects a bound token presented as a plain bearer (no proof) — the downgrade gap", async () => {
    const key = await dpopKey();
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "t", cnf: { jkt: key.jkt } });
    const result = await verifier.authenticateRequest(
      new Request(RS_URL, { headers: { authorization: `Bearer ${token}` } }),
    );
    expect(result.authenticated).toBe(false);
    if (!result.authenticated) {
      expect(result.wwwAuthenticate).toContain("DPoP");
    }
  });

  it("rejects a proof bound to a different URL (htu)", async () => {
    const key = await dpopKey();
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "t", cnf: { jkt: key.jkt } });
    const p = await proof(key, { htm: "GET", htu: "https://api.rp.test/other", ath: await sha256b64u(token) });
    const result = await verifier.authenticateRequest(request(token, p));
    expect(result.authenticated).toBe(false);
  });

  it("rejects a proof signed by a different key than cnf.jkt", async () => {
    const key = await dpopKey();
    const attacker = await dpopKey();
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "t", cnf: { jkt: key.jkt } });
    // Proof carries the attacker's key (so its thumbprint != cnf.jkt).
    const p = await proof(attacker, { htm: "GET", htu: RS_URL, ath: await sha256b64u(token) });
    const result = await verifier.authenticateRequest(request(token, p));
    expect(result.authenticated).toBe(false);
  });

  it("enforces single-use via the replay guard", async () => {
    const key = await dpopKey();
    const seen = new Set<string>();
    const verifier = createAuthVerifier({
      issuer: ISSUER,
      audience: AUDIENCE,
      dpop: { isReplay: ({ jti }) => (seen.has(jti) ? true : (seen.add(jti), false)) },
    });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "t", cnf: { jkt: key.jkt } });
    const make = async () => proof(key, { htm: "GET", htu: RS_URL, ath: await sha256b64u(token), jti: "reused" });

    const first = await verifier.authenticateRequest(request(token, await make()));
    expect(first.authenticated).toBe(true);
    const replay = await verifier.authenticateRequest(request(token, await make()));
    expect(replay.authenticated).toBe(false);
  });

  it('mode "required" rejects a plain bearer token with no cnf', async () => {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE, dpop: { mode: "required" } });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "t" });
    const result = await verifier.authenticateRequest(
      new Request(RS_URL, { headers: { authorization: `Bearer ${token}` } }),
    );
    expect(result.authenticated).toBe(false);
  });

  it('mode "disabled" accepts a bound token as a plain bearer (legacy)', async () => {
    const key = await dpopKey();
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE, dpop: { mode: "disabled" } });
    const token = await sign({ sub: "u", sid: "s", scope: "openid", client_id: AUDIENCE, jti: "t", cnf: { jkt: key.jkt } });
    const result = await verifier.authenticateRequest(
      new Request(RS_URL, { headers: { authorization: `Bearer ${token}` } }),
    );
    expect(result.authenticated).toBe(true);
  });
});

describe("stepUpChallenge (RFC 9470)", () => {
  it("builds an insufficient_user_authentication challenge with acr_values", () => {
    const header = stepUpChallenge({ acrValues: "phr-stepup" });
    expect(header).toContain('error="insufficient_user_authentication"');
    expect(header).toContain('acr_values="phr-stepup"');
    expect(header.startsWith("DPoP ")).toBe(true);
  });

  it("supports a Bearer scheme and max_age", () => {
    const header = stepUpChallenge({ scheme: "Bearer", maxAge: 300 });
    expect(header.startsWith("Bearer ")).toBe(true);
    expect(header).toContain('max_age="300"');
  });
});
