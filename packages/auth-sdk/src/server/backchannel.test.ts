import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createLogoutReceiver, inMemoryReplayCache } from "./backchannel.js";
import { createAuthVerifier } from "./verify.js";

const ISSUER = "https://auth.test";
const AUDIENCE = "rp";

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

  const logoutToken = (claims: Record<string, unknown> = {}, typ = "logout+jwt") =>
    new SignJWT({
      sub: "user-1",
      sid: "sid-1",
      jti: "jti-1",
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
      ...claims,
    })
      .setProtectedHeader({ alg: "ES256", kid: "test-kid", typ })
      .setIssuedAt()
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setExpirationTime("2m")
      .sign(privateKey);

  return { logoutToken };
}

function post(token?: string): Request {
  return new Request("https://rp.test/auth/backchannel-logout", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(token !== undefined ? { logout_token: token } : {}),
  });
}

describe("createLogoutReceiver", () => {
  let logoutToken: Awaited<ReturnType<typeof setupIssuer>>["logoutToken"];

  beforeEach(async () => {
    ({ logoutToken } = await setupIssuer());
  });
  afterEach(() => vi.unstubAllGlobals());

  function receiver(overrides?: Partial<Parameters<typeof createLogoutReceiver>[1]>) {
    const verifier = createAuthVerifier({ issuer: ISSUER, audience: AUDIENCE });
    const onLogout = vi.fn();
    const receive = createLogoutReceiver(verifier, { onLogout, ...overrides });
    return { receive, onLogout };
  }

  it("accepts a valid logout token and invokes onLogout with sub+sid", async () => {
    const { receive, onLogout } = receiver();
    const response = await receive(post(await logoutToken()));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(onLogout).toHaveBeenCalledWith({ sub: "user-1", sid: "sid-1" });
  });

  it("rejects a missing logout_token with 400", async () => {
    const { receive, onLogout } = receiver();
    const response = await receive(post());
    expect(response.status).toBe(400);
    expect(onLogout).not.toHaveBeenCalled();
  });

  it("rejects an invalid token (wrong typ) with 400", async () => {
    const { receive, onLogout } = receiver();
    const response = await receive(post(await logoutToken({}, "at+jwt")));
    expect(response.status).toBe(400);
    expect(onLogout).not.toHaveBeenCalled();
  });

  it("rejects a replayed jti when a replay cache is wired", async () => {
    const { receive, onLogout } = receiver({ isReplay: inMemoryReplayCache() });
    const token = await logoutToken();
    expect((await receive(post(token))).status).toBe(200);
    expect((await receive(post(token))).status).toBe(400);
    expect(onLogout).toHaveBeenCalledTimes(1);
  });

  it("returns 400 when the RP's onLogout callback throws (OP may retry)", async () => {
    const { receive } = receiver({
      onLogout: () => {
        throw new Error("session store down");
      },
    });
    const response = await receive(post(await logoutToken()));
    expect(response.status).toBe(400);
  });

  it("rejects non-POST requests", async () => {
    const { receive } = receiver();
    const response = await receive(
      new Request("https://rp.test/auth/backchannel-logout", { method: "GET" }),
    );
    expect(response.status).toBe(405);
  });
});
