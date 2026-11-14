/**
 * Strict base64url (RFC 4648 §5) without padding, as required by protocol §2.
 *
 * The decoder rejects padding, characters outside the URL-safe alphabet,
 * impossible lengths and non-canonical encodings (non-zero trailing bits), so
 * that every byte string has exactly one accepted textual form.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const DECODE_TABLE: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Thrown when a string is not canonical, unpadded base64url. */
export class Base64urlError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = 'Base64urlError';
  }
}

/** Encodes bytes as base64url without padding. */
export function encode(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out +=
      ALPHABET.charAt((n >>> 18) & 63) +
      ALPHABET.charAt((n >>> 12) & 63) +
      ALPHABET.charAt((n >>> 6) & 63) +
      ALPHABET.charAt(n & 63);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += ALPHABET.charAt((n >>> 18) & 63) + ALPHABET.charAt((n >>> 12) & 63);
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out +=
      ALPHABET.charAt((n >>> 18) & 63) +
      ALPHABET.charAt((n >>> 12) & 63) +
      ALPHABET.charAt((n >>> 6) & 63);
  }
  return out;
}

function sextet(input: string, index: number): number {
  const code = input.charCodeAt(index);
  const value = code < 128 ? (DECODE_TABLE[code] ?? -1) : -1;
  if (value < 0) {
    throw new Base64urlError(`invalid base64url character at offset ${index}`);
  }
  return value;
}

/** Decodes canonical, unpadded base64url. Throws {@link Base64urlError} otherwise. */
export function decode(input: string): Uint8Array<ArrayBuffer> {
  // `typeof` guard because this is reached with untrusted server data.
  if (typeof input !== 'string') {
    throw new Base64urlError('base64url input must be a string');
  }
  const length = input.length;
  const rest = length % 4;
  if (rest === 1) {
    throw new Base64urlError('invalid base64url length');
  }
  const out = new Uint8Array(((length - rest) / 4) * 3 + (rest === 0 ? 0 : rest - 1));
  let o = 0;
  let i = 0;
  for (; i + 3 < length; i += 4) {
    const n =
      (sextet(input, i) << 18) |
      (sextet(input, i + 1) << 12) |
      (sextet(input, i + 2) << 6) |
      sextet(input, i + 3);
    out[o++] = (n >>> 16) & 0xff;
    out[o++] = (n >>> 8) & 0xff;
    out[o++] = n & 0xff;
  }
  if (rest === 2) {
    const a = sextet(input, i);
    const b = sextet(input, i + 1);
    if ((b & 0x0f) !== 0) {
      throw new Base64urlError('non-canonical base64url (non-zero trailing bits)');
    }
    out[o] = ((a << 2) | (b >>> 4)) & 0xff;
  } else if (rest === 3) {
    const a = sextet(input, i);
    const b = sextet(input, i + 1);
    const c = sextet(input, i + 2);
    if ((c & 0x03) !== 0) {
      throw new Base64urlError('non-canonical base64url (non-zero trailing bits)');
    }
    out[o++] = ((a << 2) | (b >>> 4)) & 0xff;
    out[o] = ((b << 4) | (c >>> 2)) & 0xff;
  }
  return out;
}

/** True when `input` is canonical base64url whose decoded length is within bounds. */
export function isBase64url(input: unknown, minBytes = 0, maxBytes = Infinity): input is string {
  if (typeof input !== 'string') {
    return false;
  }
  try {
    const n = decode(input).length;
    return n >= minBytes && n <= maxBytes;
  } catch {
    return false;
  }
}

const textEncoder = new TextEncoder();

/** base64url(UTF-8(text)). */
export function encodeText(text: string): string {
  return encode(textEncoder.encode(text));
}
