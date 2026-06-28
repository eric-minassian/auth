import { afterEach, describe, expect, it, vi } from "vitest";

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
 * how many rotations actually happened.
 */
function stubIssuer() {
  let tokenPosts = 0;
  let generation = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/.well-known/openid-configuration")) {
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
