/**
 * `WWW-Authenticate` parsing (RFC 9110 §11.6.1).
 *
 *   WWW-Authenticate = #challenge
 *   challenge        = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
 *   auth-param       = token BWS "=" BWS ( token / quoted-string )
 */

export interface Challenge {
  /** Lowercased auth scheme. */
  readonly scheme: string;
  /** Auth parameters with lowercased names. The first occurrence of a name wins. */
  readonly params: ReadonlyMap<string, string>;
  readonly token68?: string;
}

const TCHAR = /[!#$%&'*+\-.^_`|~0-9A-Za-z]/;
const TOKEN68_CHAR = /[A-Za-z0-9\-._~+/]/;

class Cursor {
  pos = 0;
  constructor(readonly input: string) {}

  atEnd(): boolean {
    return this.pos >= this.input.length;
  }

  peek(): string {
    return this.input.charAt(this.pos);
  }

  skipWhitespace(): void {
    while (this.peek() === ' ' || this.peek() === '\t') {
      this.pos++;
    }
  }

  read(charClass: RegExp): string {
    const start = this.pos;
    while (!this.atEnd() && charClass.test(this.peek())) {
      this.pos++;
    }
    return this.input.slice(start, this.pos);
  }

  readQuoted(): string | undefined {
    if (this.peek() !== '"') {
      return undefined;
    }
    let i = this.pos + 1;
    let out = '';
    while (i < this.input.length) {
      const c = this.input.charAt(i++);
      if (c === '"') {
        this.pos = i;
        return out;
      }
      if (c === '\\') {
        if (i >= this.input.length) {
          break;
        }
        out += this.input.charAt(i++);
      } else {
        out += c;
      }
    }
    return undefined; // unterminated
  }
}

/** Parses every challenge in a `WWW-Authenticate` value. Malformed input yields the challenges parsed so far. */
export function parseWwwAuthenticate(header: string | null): Challenge[] {
  if (header === null) {
    return [];
  }
  const cur = new Cursor(header);
  const challenges: Challenge[] = [];

  for (;;) {
    // Skip empty list elements.
    while (cur.peek() === ',' || cur.peek() === ' ' || cur.peek() === '\t') {
      cur.pos++;
    }
    if (cur.atEnd()) {
      return challenges;
    }
    const scheme = cur.read(TCHAR);
    if (scheme.length === 0) {
      return challenges;
    }
    const params = new Map<string, string>();
    let token68: string | undefined;
    cur.skipWhitespace();

    // token68 form: the element after the scheme ends the challenge. An
    // auth-param always has a value after "=", so `name=` followed by the end
    // of the element can only be a token68.
    const afterScheme = cur.pos;
    const body = cur.read(TOKEN68_CHAR);
    const t68 = body.length > 0 ? body + cur.read(/=/) : '';
    cur.skipWhitespace();
    if (t68.length > 0 && (cur.atEnd() || cur.peek() === ',')) {
      token68 = t68;
    } else {
      cur.pos = afterScheme;
      // auth-param list
      for (;;) {
        const save = cur.pos;
        const name = cur.read(TCHAR);
        cur.skipWhitespace();
        if (name.length === 0 || cur.peek() !== '=') {
          // Not a parameter: start of the next challenge (or garbage).
          cur.pos = save;
          break;
        }
        cur.pos++; // '='
        cur.skipWhitespace();
        const value = cur.peek() === '"' ? cur.readQuoted() : cur.read(TCHAR);
        if (value === undefined) {
          return challenges; // unterminated quoted-string: stop parsing
        }
        const key = name.toLowerCase();
        if (!params.has(key)) {
          params.set(key, value);
        }
        cur.skipWhitespace();
        if (cur.peek() !== ',') {
          break;
        }
        // Look ahead: is the next list element another auth-param of this challenge?
        const commaPos = cur.pos;
        while (cur.peek() === ',' || cur.peek() === ' ' || cur.peek() === '\t') {
          cur.pos++;
        }
        const probeStart = cur.pos;
        const probe = cur.read(TCHAR);
        cur.skipWhitespace();
        const isParam = probe.length > 0 && cur.peek() === '=';
        cur.pos = isParam ? probeStart : commaPos;
        if (!isParam) {
          break;
        }
      }
    }
    challenges.push(
      token68 === undefined
        ? { scheme: scheme.toLowerCase(), params }
        : { scheme: scheme.toLowerCase(), params, token68 },
    );
    cur.skipWhitespace();
    if (!cur.atEnd() && cur.peek() !== ',') {
      return challenges; // garbage after a challenge
    }
  }
}

export interface DpopChallenge {
  readonly error: string | undefined;
  readonly errorDescription: string | undefined;
  readonly maxAge: number | undefined;
}

/** The first `DPoP` challenge of a response, if any (RFC 9449 §7.1, RFC 9470 §3). */
export function dpopChallenge(headers: Headers): DpopChallenge | undefined {
  const challenge = parseWwwAuthenticate(headers.get('www-authenticate')).find(
    (c) => c.scheme === 'dpop',
  );
  if (challenge === undefined) {
    return undefined;
  }
  const rawMaxAge = challenge.params.get('max_age');
  const maxAge =
    rawMaxAge !== undefined && /^\d{1,10}$/.test(rawMaxAge) ? Number(rawMaxAge) : undefined;
  return {
    error: challenge.params.get('error'),
    errorDescription: challenge.params.get('error_description'),
    maxAge,
  };
}
