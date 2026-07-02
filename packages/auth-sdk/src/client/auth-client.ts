import { AuthError, DEFAULT_ISSUER, type User } from "../index.js";
import { createDpopSigner } from "./dpop.js";
import { createPkcePair, createState } from "./pkce.js";
import { defaultStorage, type TokenStorage } from "./storage.js";

export interface AuthClientOptions {
  clientId: string;
  redirectUri: string;
  /** Defaults to `https://auth.ericminassian.com`. */
  issuer?: string;
  /** Defaults to `openid profile offline_access`. */
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
  /**
   * OIDC `acr_values` to request — e.g. `"phr-stepup"` to satisfy an RFC 9470
   * step-up challenge from a resource server. The IdP forces a fresh assertion
   * when the current session can't meet it.
   */
  acrValues?: string;
  /** OIDC `max_age` (seconds): require the backing authentication to be this recent. */
  maxAge?: number;
}

export interface AuthClient {
  /** Build a PKCE+state transaction and navigate to the authorize endpoint. */
  signInWithRedirect(options?: SignInOptions): Promise<void>;
  /**
   * Attempt silent SSO via a hidden iframe (`prompt=none`). Resolves to the
   * resulting state — authenticated if an IdP session already existed,
   * otherwise unchanged. Never rejects on `login_required`.
   *
   * Same-site only: the IdP session cookie is not sent to a cross-site iframe,
   * so this is a no-op when the app and issuer aren't on the same site (e.g.
   * `localhost` against a hosted issuer).
   */
  signInSilently(): Promise<AuthState>;
  /** Complete the redirect: exchange the code for tokens. Returns the saved returnTo. */
  handleRedirectCallback(url?: string): Promise<{ returnTo: string | undefined }>;
  /**
   * Call from the redirect callback page. Inside a silent-auth iframe it relays
   * the result to the opener and resolves `null` (the page should do nothing
   * else). At top level it completes the code exchange and returns `returnTo`.
   */
  handleCallback(): Promise<{ returnTo: string | undefined } | null>;
  /** A valid access token, refreshing if necessary. Throws `login_required` if not signed in. */
  getAccessToken(options?: { forceRefresh?: boolean }): Promise<string>;
  /**
   * A DPoP proof (RFC 9449) for an RP-API call, bound to `method`/`url`/`accessToken`
   * (`htm`/`htu`/`ath`). Resolves `undefined` where DPoP is unavailable — the caller
   * then sends a plain bearer token. Usually you want {@link fetchWithAuth} instead.
   */
  getDpopProof(method: string, url: string, accessToken: string): Promise<string | undefined>;
  /**
   * `fetch` with the access token attached: `Authorization: DPoP <token>` plus a
   * fresh proof when DPoP is available, otherwise `Authorization: Bearer <token>`.
   * Refreshes the token as needed and transparently retries once on a
   * resource-server DPoP-Nonce challenge (RFC 9449 §9).
   */
  fetchWithAuth(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
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

/**
 * A non-2xx token-endpoint response, carrying the parsed OAuth error body so
 * callers can tell a definitive grant rejection (`invalid_grant`) from a
 * transient failure (5xx, rate limit) that must not destroy local state.
 */
class TokenEndpointError extends AuthError {
  readonly status: number;
  readonly oauthError: string | undefined;

  constructor(
    code: ConstructorParameters<typeof AuthError>[0],
    status: number,
    oauthError: string | undefined,
    message: string,
  ) {
    super(code, message);
    this.status = status;
    this.oauthError = oauthError;
  }
}
// Refresh this many seconds before the access token actually expires.
const EXPIRY_SKEW_SECONDS = 30;
// postMessage discriminator + budget for the hidden silent-auth iframe.
const SILENT_MESSAGE_SOURCE = "ema_auth_silent";
const SILENT_TIMEOUT_MS = 8000;

export function createAuthClient(options: AuthClientOptions): AuthClient {
  const issuer = (options.issuer ?? DEFAULT_ISSUER).replace(/\/$/, "");
  const scope = options.scope ?? "openid profile offline_access";
  const storage = options.storage ?? defaultStorage();
  // Sender-constrain tokens with DPoP when the browser supports it; falls back
  // to bearer tokens otherwise (the server accepts both).
  const dpop = createDpopSigner();

  let discovery: Promise<Discovery> | undefined;
  let cachedToken: CachedToken | undefined;
  // One shared refresh at a time. Refresh tokens are rotating and (under DPoP)
  // sender-constrained, so two concurrent `getAccessToken()` calls that each
  // POST the same refresh token look like token theft to the server, which
  // revokes the whole family and logs the user out. Coalescing every caller
  // onto a single in-flight rotation makes the common multi-component SPA case
  // safe. See the single-flight test.
  let refreshInFlight: Promise<void> | undefined;
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

  // POST to the token endpoint with a DPoP proof when available, transparently
  // retrying once if the server challenges for a nonce (RFC 9449 §8).
  async function tokenRequest(
    endpoint: string,
    body: Record<string, string>,
    nonce?: string,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
    };
    if (dpop) {
      headers["dpop"] = await dpop.proof(
        "POST",
        endpoint,
        nonce !== undefined ? { nonce } : undefined,
      );
    }
    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: new URLSearchParams(body),
    });
    if (response.status === 400 && dpop && !nonce) {
      const challenge = response.headers.get("dpop-nonce");
      if (challenge) {
        const error = (await response
          .clone()
          .json()
          .catch(() => undefined)) as { error?: string } | undefined;
        if (error?.error === "use_dpop_nonce") {
          return tokenRequest(endpoint, body, challenge);
        }
      }
    }
    return response;
  }

  async function exchange(body: Record<string, string>): Promise<void> {
    const { token_endpoint } = await getDiscovery();
    let response: Response;
    try {
      response = await tokenRequest(token_endpoint, body);
    } catch {
      // fetch() rejection = network failure, not a server verdict.
      throw new AuthError("network_error", "token endpoint unreachable");
    }
    if (!response.ok) {
      const detail = (await response.json().catch(() => undefined)) as
        | { error?: string; error_description?: string }
        | undefined;
      throw new TokenEndpointError(
        body.grant_type === "refresh_token" ? "token_refresh_failed" : "invalid_grant",
        response.status,
        detail?.error,
        detail?.error_description ?? "token endpoint rejected the request",
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

  // The body of a refresh, run at most once concurrently (guarded by
  // `refreshInFlight`). Reads the refresh token inside the flight so it is
  // consumed exactly once per rotation. Only a *definitive* rejection of the
  // grant itself (400 invalid_grant: rotated away, revoked, session ended)
  // clears local state and forces re-login — a transient failure (offline,
  // discovery down, 5xx, rate limit) leaves the still-valid refresh token in
  // place and surfaces a retriable error instead of silently signing the user
  // out of every RP.
  async function refreshAccessToken(): Promise<void> {
    const refreshToken = storage.get(RT_KEY);
    if (!refreshToken) throw new AuthError("login_required", "no refresh token available");
    try {
      await exchange({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: options.clientId,
      });
    } catch (error) {
      const definitive =
        error instanceof TokenEndpointError &&
        error.status === 400 &&
        error.oauthError === "invalid_grant";
      if (!definitive) {
        // Retriable: preserve state; the next getAccessToken() tries again.
        throw error instanceof AuthError
          ? error
          : new AuthError("token_refresh_failed", "token refresh failed");
      }
      storage.remove(RT_KEY);
      storage.remove(ID_KEY);
      cachedToken = undefined;
      setState({ status: "unauthenticated" });
      throw new AuthError("login_required", error.message);
    }
  }

  async function buildAuthorizeUrl(
    extra: Record<string, string>,
    returnTo?: string,
  ): Promise<string> {
    const { authorization_endpoint } = await getDiscovery();
    const pkce = await createPkcePair();
    const tx: Transaction = { verifier: pkce.verifier, state: createState() };
    if (returnTo !== undefined) tx.returnTo = returnTo;
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
      ...extra,
    }).toString();
    return url.toString();
  }

  async function completeCallback(
    url?: string,
  ): Promise<{ returnTo: string | undefined }> {
    const params = new URL(url ?? currentUrl()).searchParams;
    const raw = storage.get(TX_KEY);
    storage.remove(TX_KEY);
    if (!raw) {
      throw new AuthError("state_mismatch", "no authorization transaction in progress");
    }
    const tx = JSON.parse(raw) as Transaction;
    if (params.get("error")) {
      throw new AuthError(
        "invalid_grant",
        params.get("error_description") ?? params.get("error") ?? "authorization failed",
      );
    }
    if (params.get("state") !== tx.state) {
      throw new AuthError("state_mismatch", "state parameter mismatch");
    }
    // RFC 9207: if the AS stamped an issuer, it must be ours — defends against
    // a mix-up attack that swaps in a response from a different authorization
    // server. (Absent for legacy responses; only enforced when present.)
    const responseIss = params.get("iss");
    if (responseIss !== null && responseIss !== issuer) {
      throw new AuthError("state_mismatch", "issuer mismatch in authorization response");
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
  }

  async function obtainAccessToken(getOptions?: { forceRefresh?: boolean }): Promise<string> {
    if (!getOptions?.forceRefresh && cachedToken && cachedToken.expiresAt > Date.now()) {
      return cachedToken.accessToken;
    }
    // Join an in-flight refresh rather than starting a second one — including
    // for `forceRefresh`, which must ride an existing rotation, never race it.
    refreshInFlight ??= refreshAccessToken().finally(() => {
      refreshInFlight = undefined;
    });
    await refreshInFlight;
    if (!cachedToken) throw new AuthError("login_required");
    return cachedToken.accessToken;
  }

  // `fetch` with a valid access token attached, sender-constrained with DPoP
  // when available. One transparent retry on a resource-server DPoP-Nonce
  // challenge (RFC 9449 §9): the RS replies 401 + `DPoP-Nonce`, we re-sign with
  // it. `htu` is the request URL without query/fragment (the proof helper strips it).
  async function fetchWithAuth(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const isRequest = typeof Request !== "undefined" && input instanceof Request;
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const method = (init?.method ?? (isRequest ? input.method : "GET")).toUpperCase();
    const token = await obtainAccessToken();

    const send = async (nonce?: string): Promise<Response> => {
      const headers = new Headers(init?.headers ?? (isRequest ? input.headers : undefined));
      if (dpop) {
        headers.set("authorization", `DPoP ${token}`);
        headers.set(
          "dpop",
          await dpop.proof(method, url, { accessToken: token, ...(nonce ? { nonce } : {}) }),
        );
      } else {
        headers.set("authorization", `Bearer ${token}`);
      }
      // Don't override a Request's method (a GET Request can't carry an init
      // method/body) — its method already drove `method` above.
      const requestInit: RequestInit = { ...init, headers };
      if (!isRequest) requestInit.method = method;
      return fetch(input, requestInit);
    };

    const response = await send();
    if (dpop && response.status === 401) {
      const nonce = response.headers.get("dpop-nonce");
      const wantsNonce = (response.headers.get("www-authenticate") ?? "").includes(
        "use_dpop_nonce",
      );
      if (nonce && wantsNonce) return send(nonce);
    }
    return response;
  }

  // Drive a hidden iframe through `prompt=none` authorize. The callback page,
  // detecting it's framed, posts its query string back (see `handleCallback`).
  // Resolves the relayed search string, or `undefined` on timeout.
  function runSilentFrame(authorizeUrl: string): Promise<string | undefined> {
    return new Promise((resolve) => {
      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      iframe.setAttribute("aria-hidden", "true");
      let settled = false;
      const finish = (result: string | undefined): void => {
        if (settled) return;
        settled = true;
        window.removeEventListener("message", onMessage);
        clearTimeout(timer);
        iframe.remove();
        resolve(result);
      };
      const onMessage = (event: MessageEvent): void => {
        if (event.origin !== window.location.origin) return;
        const data = event.data as { source?: unknown; search?: unknown } | null;
        if (!data || data.source !== SILENT_MESSAGE_SOURCE) return;
        finish(typeof data.search === "string" ? data.search : "");
      };
      const timer = setTimeout(() => finish(undefined), SILENT_TIMEOUT_MS);
      window.addEventListener("message", onMessage);
      iframe.src = authorizeUrl;
      document.body.appendChild(iframe);
    });
  }

  return {
    async signInWithRedirect(signInOptions): Promise<void> {
      const extra: Record<string, string> = {};
      if (signInOptions?.acrValues) extra.acr_values = signInOptions.acrValues;
      if (signInOptions?.maxAge !== undefined) extra.max_age = String(signInOptions.maxAge);
      const url = await buildAuthorizeUrl(extra, signInOptions?.returnTo ?? currentUrl());
      redirect(url);
    },

    async signInSilently(): Promise<AuthState> {
      if (state.status === "authenticated") return state;
      if (typeof window === "undefined" || typeof document === "undefined") {
        return state;
      }
      let authorizeUrl: string;
      try {
        authorizeUrl = await buildAuthorizeUrl({ prompt: "none" });
      } catch {
        return state; // discovery failed; leave state untouched
      }
      const search = await runSilentFrame(authorizeUrl);
      if (search === undefined) {
        storage.remove(TX_KEY); // timed out; drop the dangling transaction
        return state;
      }
      const callbackUrl = new URL(options.redirectUri);
      callbackUrl.search = search;
      try {
        await completeCallback(callbackUrl.toString());
      } catch {
        // login_required (no IdP session) or any silent failure: stay
        // unauthenticated, no UI disruption.
      }
      return state;
    },

    async handleRedirectCallback(url): Promise<{ returnTo: string | undefined }> {
      return completeCallback(url);
    },

    async handleCallback(): Promise<{ returnTo: string | undefined } | null> {
      if (isFramed()) {
        // Silent-auth iframe: hand the result to the opener and stop. The
        // parent (same origin) owns the transaction and does the exchange.
        window.parent.postMessage(
          { source: SILENT_MESSAGE_SOURCE, search: window.location.search },
          window.location.origin,
        );
        return null;
      }
      return completeCallback();
    },

    getAccessToken: (getOptions) => obtainAccessToken(getOptions),

    async getDpopProof(method, url, accessToken): Promise<string | undefined> {
      return dpop ? dpop.proof(method.toUpperCase(), url, { accessToken }) : undefined;
    },

    fetchWithAuth,

    getUser: () => user,
    getState: () => state,

    onStateChange(listener): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    async signOut(signOutOptions): Promise<void> {
      const idToken = storage.get(ID_KEY);
      const refreshToken = storage.get(RT_KEY);
      // Local state goes first: sign-out must take effect even when the
      // network or discovery is down. Everything after is best-effort.
      storage.remove(RT_KEY);
      storage.remove(ID_KEY);
      cachedToken = undefined;
      setState({ status: "unauthenticated" });

      let endpoints: Discovery;
      try {
        endpoints = await getDiscovery();
      } catch {
        return; // offline: locally signed out; the IdP session is untouched
      }
      if (refreshToken) {
        await fetch(endpoints.revocation_endpoint, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: refreshToken }),
        }).catch(() => undefined);
      }

      const url = new URL(endpoints.end_session_endpoint);
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
      nickname?: string;
      updated_at?: number;
      exp?: number;
    };
    if (!payload.sub) return undefined;
    // Don't surface an expired token as a signed-in user. This is a display
    // decision only — the access token (verified server-side) is the real
    // credential — but a stale id_token shouldn't rehydrate `authenticated`.
    if (typeof payload.exp === "number" && payload.exp * 1000 <= Date.now()) {
      return undefined;
    }
    const user: User = { sub: payload.sub };
    // `nickname`/`updated_at` arrive only under the `profile` scope.
    if (payload.nickname !== undefined) user.nickname = payload.nickname;
    if (payload.updated_at !== undefined) user.updatedAt = payload.updated_at;
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

function isFramed(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.self !== window.top;
  } catch {
    // Cross-origin parent throws on access — which means we are framed.
    return true;
  }
}

function redirect(url: string): void {
  if (typeof location !== "undefined") location.assign(url);
}
