import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthError } from "../index.js";
import type { TokenStorage } from "./storage.js";
import { createAuthClient } from "./auth-client.js";

const ISSUER = "https://auth.test";

function memoryStorage(seed: Record<string, string> = {}): TokenStorage {
  const map = new Map<string, string>(Object.entries(seed));
  return {
    get: (key) => map.get(key) ?? null,
    set: (key, value) => void map.set(key, value),
    remove: (key) => void map.delete(key),
  };
}

/**
 * Stub the discovery document and a rotating token endpoint. Each token request
 * mints a fresh access + refresh token and bumps a counter so a test can assert
 * how many rotations actually happened. `failTokenWith` makes the next token
 * requests fail a chosen way (a canned Response, or a network rejection).
 */
function stubIssuer() {
  let tokenPosts = 0;
  let generation = 0;
  let tokenFailure: Response | "network" | undefined;
  let discoveryDown = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
        if (discoveryDown) throw new TypeError("fetch failed");
        return new Response(
          JSON.stringify({
            authorization_endpoint: `${ISSUER}/oauth/authorize`,
            token_endpoint: `${ISSUER}/oauth/token`,
            end_session_endpoint: `${ISSUER}/oauth/logout`,
            revocation_endpoint: `${ISSUER}/oauth/revoke`,
          }),
          { headers: { "content-type": "application/json" } },
        );
      }
      if (url.endsWith("/oauth/token")) {
        tokenPosts += 1;
        if (tokenFailure === "network") throw new TypeError("fetch failed");
        if (tokenFailure) return tokenFailure.clone();
        generation += 1;
        // A refresh-token grant consumes the presented token; a real server
        // would reject a second concurrent use of the same one.
        void init;
        return new Response(
          JSON.stringify({
            access_token: `access-${generation}`,
            token_type: "Bearer",
            expires_in: 600,
            refresh_token: `refresh-${generation}`,
          }),
          { headers: { "content-type": "application/json" } },
        );
      }
      return new Response("not found", { status: 404 });
    }),
  );
  return {
    get tokenPosts() {
      return tokenPosts;
    },
    failTokenWith(failure: Response | "network" | undefined) {
      tokenFailure = failure;
    },
    setDiscoveryDown(down: boolean) {
      discoveryDown = down;
    },
  };
}

describe("getAccessToken single-flight refresh", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("coalesces concurrent refreshes into one token request", async () => {
    const issuer = stubIssuer();
    const client = createAuthClient({
      clientId: "rp",
      redirectUri: "https://rp.test/cb",
      issuer: ISSUER,
      storage: memoryStorage({ ema_auth_rt: "refresh-0" }),
    });

    const tokens = await Promise.all(
      Array.from({ length: 5 }, () => client.getAccessToken()),
    );

    // Exactly one rotation, despite five concurrent callers, and they all see
    // the same freshly-minted token.
    expect(issuer.tokenPosts).toBe(1);
    expect(new Set(tokens).size).toBe(1);
    expect(tokens[0]).toBe("access-1");
  });

  it("serves the cached token without a second rotation, and forceRefresh rotates once", async () => {
    const issuer = stubIssuer();
    const client = createAuthClient({
      clientId: "rp",
      redirectUri: "https://rp.test/cb",
      issuer: ISSUER,
      storage: memoryStorage({ ema_auth_rt: "refresh-0" }),
    });

    await client.getAccessToken();
    expect(issuer.tokenPosts).toBe(1);

    // Cached: no new rotation.
    await client.getAccessToken();
    expect(issuer.tokenPosts).toBe(1);

    // forceRefresh: one more rotation, and concurrent forced calls still share it.
    const forced = await Promise.all([
      client.getAccessToken({ forceRefresh: true }),
      client.getAccessToken({ forceRefresh: true }),
    ]);
    expect(issuer.tokenPosts).toBe(2);
    expect(new Set(forced).size).toBe(1);
  });
});

describe("refresh failure handling", () => {
  afterEach(() => vi.unstubAllGlobals());

  function makeClient(storage: TokenStorage) {
    return createAuthClient({
      clientId: "rp",
      redirectUri: "https://rp.test/cb",
      issuer: ISSUER,
      storage,
    });
  }

  it("preserves the refresh token across a 5xx and recovers on the next attempt", async () => {
    const issuer = stubIssuer();
    const storage = memoryStorage({ ema_auth_rt: "refresh-0" });
    const client = makeClient(storage);

    issuer.failTokenWith(
      new Response(JSON.stringify({ error: "server_error" }), { status: 500 }),
    );
    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: "token_refresh_failed",
    });
    // The still-valid refresh token survives the outage…
    expect(storage.get("ema_auth_rt")).toBe("refresh-0");

    // …and the next call succeeds without interactive re-login.
    issuer.failTokenWith(undefined);
    await expect(client.getAccessToken()).resolves.toBe("access-1");
  });

  it("preserves state across a network failure", async () => {
    const issuer = stubIssuer();
    const storage = memoryStorage({ ema_auth_rt: "refresh-0" });
    const client = makeClient(storage);

    issuer.failTokenWith("network");
    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: "network_error",
    });
    expect(storage.get("ema_auth_rt")).toBe("refresh-0");
  });

  it("clears state and demands re-login only on a definitive invalid_grant", async () => {
    const issuer = stubIssuer();
    const storage = memoryStorage({ ema_auth_rt: "refresh-stolen" });
    const client = makeClient(storage);

    issuer.failTokenWith(
      new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 }),
    );
    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: "login_required",
    });
    expect(storage.get("ema_auth_rt")).toBeNull();
    expect(client.getState().status).toBe("unauthenticated");
  });

  it("rate limiting (400 slow_down) does not destroy the session", async () => {
    const issuer = stubIssuer();
    const storage = memoryStorage({ ema_auth_rt: "refresh-0" });
    const client = makeClient(storage);

    issuer.failTokenWith(
      new Response(JSON.stringify({ error: "slow_down" }), { status: 400 }),
    );
    await expect(client.getAccessToken()).rejects.toBeInstanceOf(AuthError);
    expect(storage.get("ema_auth_rt")).toBe("refresh-0");
  });
});

describe("signOut", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("clears local state even when discovery is unreachable", async () => {
    const issuer = stubIssuer();
    issuer.setDiscoveryDown(true);
    const storage = memoryStorage({ ema_auth_rt: "refresh-0", ema_auth_id: "not-a-jwt" });
    const client = createAuthClient({
      clientId: "rp",
      redirectUri: "https://rp.test/cb",
      issuer: ISSUER,
      storage,
    });

    await expect(client.signOut()).resolves.toBeUndefined();
    expect(storage.get("ema_auth_rt")).toBeNull();
    expect(storage.get("ema_auth_id")).toBeNull();
    expect(client.getState().status).toBe("unauthenticated");
  });

  it("still revokes the refresh token when online", async () => {
    stubIssuer();
    const storage = memoryStorage({ ema_auth_rt: "refresh-0" });
    const client = createAuthClient({
      clientId: "rp",
      redirectUri: "https://rp.test/cb",
      issuer: ISSUER,
      storage,
    });

    await client.signOut();
    expect(storage.get("ema_auth_rt")).toBeNull();
    const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls.map((c) => String(c[0]));
    expect(calls.some((u) => u.endsWith("/oauth/revoke"))).toBe(true);
  });
});
