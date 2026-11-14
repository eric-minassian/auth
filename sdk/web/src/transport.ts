/**
 * HTTP transport: attaches DPoP proofs, tracks server nonces per origin,
 * retries once on a nonce challenge and estimates server clock skew.
 */
import type { ServerClock } from './clock.js';
import { createDpopProof, htuFor, type DeviceKey } from './dpop.js';
import {
  AuthError,
  StepUpRequiredError,
  isProtocolErrorCode,
  type AuthErrorCode,
} from './errors.js';
import { isObject } from './validate.js';
import { dpopChallenge } from './www-authenticate.js';

/** RFC 9449 §8.1: `nonce = 1*NQCHAR`, `NQCHAR = %x21 / %x23-5B / %x5D-7E`. */
const NONCE_SYNTAX = /^[\x21\x23-\x5B\x5D-\x7E]{1,1024}$/;

/**
 * If a proof is rejected as invalid and the clock estimate moved by at least
 * this much while handling the response, the rejection was most likely caused
 * by `iat`: retry once with the corrected clock.
 */
export const CLOCK_RETRY_THRESHOLD_MS = 30_000;

export type FetchLike = (input: Request) => Promise<Response>;

export interface SendOptions {
  /** Device key to sign a DPoP proof with. Without it no proof is attached. */
  readonly key?: DeviceKey | undefined;
  /** Access token to present as `Authorization: DPoP …` (adds `ath` to the proof). */
  readonly accessToken?: string | undefined;
}

function isMediaTypeJson(headers: Headers): boolean {
  const type = headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() ?? '';
  return type === 'application/json' || (type.startsWith('application/') && type.endsWith('+json'));
}

/** Reads a JSON body. Returns `undefined` for empty, non-JSON or malformed bodies. */
export async function readJson(response: Response): Promise<unknown> {
  if (response.status === 204 || response.status === 205 || !isMediaTypeJson(response.headers)) {
    await response.body?.cancel().catch(() => undefined);
    return undefined;
  }
  let text: string;
  try {
    text = await response.text();
  } catch (cause) {
    throw new AuthError('network_error', 'failed to read the response body', { cause });
  }
  if (text.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** The DPoP-related error a response carries, if any (both RFC 9449 §7.1 and §5/§8 forms). */
async function dpopErrorOf(response: Response): Promise<string | undefined> {
  if (response.status === 401) {
    return dpopChallenge(response.headers)?.error;
  }
  if (response.status === 400 && isMediaTypeJson(response.headers)) {
    const body = await readJson(response.clone());
    const error = isObject(body) ? body['error'] : undefined;
    return typeof error === 'string' ? error : undefined;
  }
  return undefined;
}

function isAbortError(error: unknown): boolean {
  const name =
    typeof error === 'object' && error !== null ? (error as { name?: unknown }).name : '';
  return name === 'AbortError' || name === 'TimeoutError';
}

function defaultCodeForStatus(status: number): AuthErrorCode {
  if (status === 413) return 'payload_too_large';
  if (status === 429) return 'rate_limited';
  if (status >= 500) return 'server_error';
  return 'unexpected_status';
}

/**
 * Builds the `AuthError` for a failed auth-service response. The code comes from
 * the OAuth error object, else from a `WWW-Authenticate: DPoP` challenge, else
 * from the status.
 */
export function errorFromResponse(response: Response, body: unknown): AuthError {
  const challenge = dpopChallenge(response.headers);
  const bodyError = isObject(body) ? body['error'] : undefined;
  const rawDescription = isObject(body) ? body['error_description'] : undefined;
  const description =
    typeof rawDescription === 'string' ? rawDescription : challenge?.errorDescription;
  const code: AuthErrorCode = isProtocolErrorCode(bodyError)
    ? bodyError
    : isProtocolErrorCode(challenge?.error)
      ? challenge.error
      : defaultCodeForStatus(response.status);
  const options =
    description === undefined
      ? { status: response.status }
      : { status: response.status, description };
  if (code === 'insufficient_user_authentication') {
    return new StepUpRequiredError(
      challenge?.maxAge === undefined ? options : { ...options, maxAge: challenge.maxAge },
    );
  }
  return new AuthError(
    code,
    description ?? `request failed with status ${response.status} (${code})`,
    options,
  );
}

export class DpopTransport {
  readonly #fetch: FetchLike;
  readonly #clock: ServerClock;
  readonly #clockOrigin: string;
  readonly #nonces = new Map<string, string>();

  /**
   * @param clockOrigin Only `Date` headers from this origin (the issuer) update
   *   the clock estimate: its responses are `no-store` and it is trusted, while
   *   a resource server's `Date` could come from a cache.
   */
  constructor(fetchImpl: FetchLike, clock: ServerClock, clockOrigin: string) {
    this.#fetch = fetchImpl;
    this.#clock = clock;
    this.#clockOrigin = clockOrigin;
  }

  /** The latest nonce received from `origin`. */
  nonceFor(origin: string): string | undefined {
    return this.#nonces.get(origin);
  }

  #recordNonce(origin: string, headers: Headers): string | undefined {
    const nonce = headers.get('dpop-nonce');
    if (nonce !== null && NONCE_SYNTAX.test(nonce)) {
      this.#nonces.set(origin, nonce);
      return nonce;
    }
    return undefined;
  }

  /**
   * Sends `base` (which is never consumed; each attempt uses a clone). When a
   * key is given, a fresh DPoP proof is attached to every attempt, and the
   * request is retried once if the server demands a (new) nonce, or rejects the
   * proof while the clock estimate shifted significantly.
   */
  async send(base: Request, options: SendOptions = {}): Promise<Response> {
    const url = new URL(base.url);
    const origin = url.origin;
    const htu = htuFor(url);
    for (let attempt = 0; ; attempt++) {
      const headers = new Headers(base.headers);
      let sentNonce: string | undefined;
      if (options.accessToken !== undefined) {
        headers.set('Authorization', `DPoP ${options.accessToken}`);
      }
      if (options.key !== undefined) {
        sentNonce = this.#nonces.get(origin);
        const proof = await createDpopProof(options.key, {
          htm: base.method,
          htu,
          iat: this.#clock.nowSeconds(),
          nonce: sentNonce,
          accessToken: options.accessToken,
        });
        headers.set('DPoP', proof);
      }
      // `new Request(request, init)` with a non-empty init resets the referrer
      // and referrer policy (Fetch §5.4 "Request class" constructor), so carry
      // them over explicitly.
      const request = new Request(base.clone(), {
        headers,
        referrer: base.referrer,
        referrerPolicy: base.referrerPolicy,
      });
      const sentAt = this.#clock.localNow();
      let response: Response;
      try {
        // Invoke unbound: a native `fetch` throws "Illegal invocation" when
        // called with a foreign `this`.
        const fetchImpl = this.#fetch;
        response = await fetchImpl(request);
      } catch (error) {
        if (isAbortError(error)) {
          throw error;
        }
        throw new AuthError('network_error', 'the request could not be completed', {
          cause: error,
        });
      }
      const skewDelta =
        origin === this.#clockOrigin
          ? this.#clock.observe(response.headers.get('date'), sentAt, this.#clock.localNow())
          : 0;
      const receivedNonce = this.#recordNonce(origin, response.headers);

      if (options.key === undefined || attempt > 0) {
        return response;
      }
      const error = await dpopErrorOf(response);
      const retry =
        (error === 'use_dpop_nonce' &&
          receivedNonce !== undefined &&
          receivedNonce !== sentNonce) ||
        (error === 'invalid_dpop_proof' && Math.abs(skewDelta) >= CLOCK_RETRY_THRESHOLD_MS);
      if (!retry) {
        return response;
      }
      await response.body?.cancel().catch(() => undefined);
    }
  }
}
