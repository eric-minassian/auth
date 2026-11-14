/**
 * Server clock estimation (protocol §7.4).
 *
 * DPoP proofs carry `iat`, which servers accept only within a small window of
 * their own clock (120 s at the auth service, 60 s at resource servers). Client
 * clocks are frequently wrong by more than that, so the SDK estimates the
 * offset from the `Date` header of auth-service responses.
 */

// RFC 9110 §5.6.7 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
const IMF_FIXDATE =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/** Parses an IMF-fixdate `Date` header to epoch milliseconds, or `undefined`. */
export function parseHttpDate(value: string | null): number | undefined {
  if (value === null || !IMF_FIXDATE.test(value)) {
    return undefined;
  }
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}

export class ServerClock {
  #offsetMs = 0;
  readonly #localNow: () => number;

  constructor(localNow: () => number = Date.now) {
    this.#localNow = localNow;
  }

  /** Estimated offset (server - local), in milliseconds. */
  get offsetMs(): number {
    return this.#offsetMs;
  }

  /** Estimated server time in epoch milliseconds. */
  nowMs(): number {
    return this.#localNow() + this.#offsetMs;
  }

  /** Estimated server time as a NumericDate. */
  nowSeconds(): number {
    return Math.floor(this.nowMs() / 1000);
  }

  /** Local time in epoch milliseconds (used to time requests). */
  localNow(): number {
    return this.#localNow();
  }

  /**
   * Updates the estimate from a response's `Date` header.
   *
   * `Date` has one-second resolution and is truncated, so the server time when
   * the header was generated is in `[date, date + 1s)`; we take the middle of
   * that second. The local time at that instant is approximated by the middle of
   * the request's round trip. The resulting error is bounded by 0.5 s plus half
   * the round-trip time, far below the servers' accepted skew.
   *
   * Returns the change of the estimate in milliseconds.
   */
  observe(dateHeader: string | null, sentAt: number, receivedAt: number): number {
    const serverMs = parseHttpDate(dateHeader);
    if (serverMs === undefined || receivedAt < sentAt) {
      return 0;
    }
    const next = Math.round(serverMs + 500 - (sentAt + receivedAt) / 2);
    const delta = next - this.#offsetMs;
    this.#offsetMs = next;
    return delta;
  }
}
