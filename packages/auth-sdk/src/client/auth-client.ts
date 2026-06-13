import { AuthError, DEFAULT_ISSUER, type User } from "../index.js";
import { createPkcePair, createState } from "./pkce.js";
import { defaultStorage, type TokenStorage } from "./storage.js";

export interface AuthClientOptions {
  clientId: string;
  redirectUri: string;
  /** Defaults to `https://auth.ericminassian.com`. */
  issuer?: string;
  /** Defaults to `openid email offline_access`. */
  scope?: string;
  storage?: TokenStorage;
}

export type AuthState =
  | { status: "loading" }
  | { status: "authenticated"; user: User }
  | { status: "unauthenticated" };

export interface SignInOptions {
  /** Where to return after the callback completes. Defaults to the current URL. */
  returnTo?: string;
}

export interface AuthClient {
  /** Build a PKCE+state transaction and navigate to the authorize endpoint. */
  signInWithRedirect(options?: SignInOptions): Promise<void>;
  /** Complete the redirect: exchange the code for tokens. Returns the saved returnTo. */
  handleRedirectCallback(url?: string): Promise<{ returnTo: string | undefined }>;
  /** A valid access token, refreshing if necessary. Throws `login_required` if not signed in. */
  getAccessToken(options?: { forceRefresh?: boolean }): Promise<string>;
  getUser(): User | undefined;
  getState(): AuthState;
  onStateChange(listener: (state: AuthState) => void): () => void;
  /** Revoke the refresh token, clear local state, and navigate to end_session. */
  signOut(options?: { postLogoutRedirectUri?: string }): Promise<void>;
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint: string;
  revocation_endpoint: string;
}

interface Transaction {
  verifier: string;
  state: string;
  returnTo?: string;
}

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

const TX_KEY = "ema_auth_tx";
const RT_KEY = "ema_auth_rt";
const ID_KEY = "ema_auth_id";
// Refresh this many seconds before the access token actually expires.
const EXPIRY_SKEW_SECONDS = 30;

export function createAuthClient(options: AuthClientOptions): AuthClient {
  const issuer = (options.issuer ?? DEFAULT_ISSUER).replace(/\/$/, "");
  const scope = options.scope ?? "openid email offline_access";
  const storage = options.storage ?? defaultStorage();

  let discovery: Promise<Discovery> | undefined;
  let cachedToken: CachedToken | undefined;
  let user: User | undefined = decodeStoredUser(storage);
  let state: AuthState = user
    ? { status: "authenticated", user }
    : { status: "unauthenticated" };
  const listeners = new Set<(state: AuthState) => void>();

  function setState(next: AuthState): void {
    state = next;
    user = next.status === "authenticated" ? next.user : undefined;
    for (const listener of listeners) listener(state);
  }

  function getDiscovery(): Promise<Discovery> {
    discovery ??= fetchJson<Discovery>(
      `${issuer}/.well-known/openid-configuration`,
    ).catch(() => {
      discovery = undefined;
      throw new AuthError("network_error", "failed to load OIDC discovery document");
    });
    return discovery;
  }

  async function exchange(body: Record<string, string>): Promise<void> {
    const { token_endpoint } = await getDiscovery();
    const response = await fetch(token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body),
    });
    if (!response.ok) {
      throw new AuthError(
        body.grant_type === "refresh_token" ? "token_refresh_failed" : "invalid_grant",
        "token endpoint rejected the request",
      );
    }
    const tokens = (await response.json()) as {
      access_token: string;
      expires_in: number;
      id_token?: string;
      refresh_token?: string;
    };
    cachedToken = {
      accessToken: tokens.access_token,
      expiresAt: Date.now() + (tokens.expires_in - EXPIRY_SKEW_SECONDS) * 1000,
    };
    if (tokens.refresh_token) storage.set(RT_KEY, tokens.refresh_token);
    if (tokens.id_token) {
      storage.set(ID_KEY, tokens.id_token);
      const next = userFromIdToken(tokens.id_token);
      if (next) setState({ status: "authenticated", user: next });
    }
  }

  return {
    async signInWithRedirect(signInOptions): Promise<void> {
      const { authorization_endpoint } = await getDiscovery();
      const pkce = await createPkcePair();
      const tx: Transaction = {
        verifier: pkce.verifier,
        state: createState(),
        returnTo: signInOptions?.returnTo ?? currentUrl(),
      };
      storage.set(TX_KEY, JSON.stringify(tx));
      const url = new URL(authorization_endpoint);
      url.search = new URLSearchParams({
        response_type: "code",
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        scope,
        state: tx.state,
        code_challenge: pkce.challenge,
        code_challenge_method: "S256",
      }).toString();
      redirect(url.toString());
    },

    async handleRedirectCallback(url): Promise<{ returnTo: string | undefined }> {
      const params = new URL(url ?? currentUrl()).searchParams;
      const raw = storage.get(TX_KEY);
      storage.remove(TX_KEY);
      if (!raw) throw new AuthError("state_mismatch", "no authorization transaction in progress");
      const tx = JSON.parse(raw) as Transaction;
      if (params.get("error")) {
        throw new AuthError("invalid_grant", params.get("error_description") ?? params.get("error") ?? "authorization failed");
      }
      if (params.get("state") !== tx.state) {
        throw new AuthError("state_mismatch", "state parameter mismatch");
      }
      const code = params.get("code");
      if (!code) throw new AuthError("invalid_grant", "missing authorization code");
      await exchange({
        grant_type: "authorization_code",
        code,
        redirect_uri: options.redirectUri,
        client_id: options.clientId,
        code_verifier: tx.verifier,
      });
      return { returnTo: tx.returnTo };
    },

    async getAccessToken(getOptions): Promise<string> {
      if (!getOptions?.forceRefresh && cachedToken && cachedToken.expiresAt > Date.now()) {
        return cachedToken.accessToken;
      }
      const refreshToken = storage.get(RT_KEY);
      if (!refreshToken) throw new AuthError("login_required", "no refresh token available");
      try {
        await exchange({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: options.clientId,
        });
      } catch (error) {
        // Refresh failed (rotated away, revoked, session ended): force re-login.
        storage.remove(RT_KEY);
        storage.remove(ID_KEY);
        setState({ status: "unauthenticated" });
        if (error instanceof AuthError) throw new AuthError("login_required", error.message);
        throw new AuthError("login_required");
      }
      if (!cachedToken) throw new AuthError("login_required");
      return cachedToken.accessToken;
    },

    getUser: () => user,
    getState: () => state,

    onStateChange(listener): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    async signOut(signOutOptions): Promise<void> {
      const idToken = storage.get(ID_KEY);
      const refreshToken = storage.get(RT_KEY);
      const { end_session_endpoint, revocation_endpoint } = await getDiscovery();
      if (refreshToken) {
        await fetch(revocation_endpoint, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: refreshToken }),
        }).catch(() => undefined);
      }
      storage.remove(RT_KEY);
      storage.remove(ID_KEY);
      cachedToken = undefined;
      setState({ status: "unauthenticated" });

      const url = new URL(end_session_endpoint);
      const search = new URLSearchParams();
      if (idToken) search.set("id_token_hint", idToken);
      search.set("client_id", options.clientId);
      const postLogout = signOutOptions?.postLogoutRedirectUri;
      if (postLogout) search.set("post_logout_redirect_uri", postLogout);
      url.search = search.toString();
      redirect(url.toString());
    },
  };
}

function decodeStoredUser(storage: TokenStorage): User | undefined {
  const idToken = storage.get(ID_KEY);
  return idToken ? userFromIdToken(idToken) : undefined;
}

/**
 * Decode (not verify) the ID token to surface profile info in the UI. The
 * token arrives directly from the token endpoint over TLS; RP *backends* must
 * still verify via the server entry point's JWKS check.
 */
function userFromIdToken(idToken: string): User | undefined {
  const parts = idToken.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const payload = JSON.parse(base64urlDecode(parts[1] ?? "")) as {
      sub?: string;
      email?: string;
      email_verified?: boolean;
      exp?: number;
    };
    if (!payload.sub) return undefined;
    const user: User = { sub: payload.sub };
    if (payload.email !== undefined) user.email = payload.email;
    if (payload.email_verified !== undefined) user.emailVerified = payload.email_verified;
    return user;
  } catch {
    return undefined;
  }
}

function base64urlDecode(input: string): string {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  return atob(padded);
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`fetch ${url} failed: ${response.status}`);
  return (await response.json()) as T;
}

function currentUrl(): string {
  return typeof location !== "undefined" ? location.href : "";
}

function redirect(url: string): void {
  if (typeof location !== "undefined") location.assign(url);
}
