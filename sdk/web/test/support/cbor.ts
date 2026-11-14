/**
 * Minimal CBOR (RFC 8949) encoder/decoder for WebAuthn test data.
 *
 * The encoder emits CTAP2 canonical CBOR (definite lengths, shortest integer
 * encodings, map keys sorted by encoded length then bytewise). The decoder is
 * strict: it rejects indefinite lengths, non-shortest integers, tags, floats
 * and trailing bytes.
 */

export type CborValue =
  | number
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>
  | { readonly [key: string]: CborValue };

function head(major: number, value: number): number[] {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError('CBOR argument out of range');
  }
  const m = major << 5;
  if (value < 24) return [m | value];
  if (value < 0x100) return [m | 24, value];
  if (value < 0x10000) return [m | 25, value >> 8, value & 0xff];
  if (value < 0x100000000) {
    return [
      m | 26,
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ];
  }
  const hi = Math.floor(value / 0x100000000);
  const lo = value >>> 0;
  return [
    m | 27,
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff,
  ];
}

function concat(chunks: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export function encodeCbor(value: CborValue): Uint8Array<ArrayBuffer> {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('only integers are supported');
    return new Uint8Array(value >= 0 ? head(0, value) : head(1, -1 - value));
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concat([new Uint8Array(head(3, bytes.length)), bytes]);
  }
  if (value === false) return new Uint8Array([0xf4]);
  if (value === true) return new Uint8Array([0xf5]);
  if (value === null) return new Uint8Array([0xf6]);
  if (value === undefined) return new Uint8Array([0xf7]);
  if (value instanceof Uint8Array) {
    return concat([new Uint8Array(head(2, value.length)), value]);
  }
  if (Array.isArray(value)) {
    return concat([new Uint8Array(head(4, value.length)), ...value.map(encodeCbor)]);
  }
  const entries: [CborValue, CborValue][] =
    value instanceof Map ? [...value.entries()] : Object.entries(value);
  const encoded = entries
    .map(([k, v]) => [encodeCbor(k), encodeCbor(v)] as const)
    .sort((a, b) => compareBytes(a[0], b[0]));
  return concat([new Uint8Array(head(5, encoded.length)), ...encoded.flat()]);
}

export class CborError extends Error {}

class Reader {
  offset: number;
  constructor(
    readonly bytes: Uint8Array,
    offset = 0,
  ) {
    this.offset = offset;
  }

  byte(): number {
    const b = this.bytes[this.offset];
    if (b === undefined) throw new CborError('unexpected end of CBOR data');
    this.offset++;
    return b;
  }

  take(n: number): Uint8Array {
    if (this.offset + n > this.bytes.length) throw new CborError('unexpected end of CBOR data');
    const out = this.bytes.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  argument(info: number): number {
    if (info < 24) return info;
    let n: number;
    let min: number;
    if (info === 24) {
      n = this.byte();
      min = 24;
    } else if (info === 25) {
      n = (this.byte() << 8) | this.byte();
      min = 0x100;
    } else if (info === 26) {
      n = ((this.byte() << 24) >>> 0) + ((this.byte() << 16) | (this.byte() << 8) | this.byte());
      min = 0x10000;
    } else if (info === 27) {
      const hi =
        ((this.byte() << 24) >>> 0) + ((this.byte() << 16) | (this.byte() << 8) | this.byte());
      const lo =
        ((this.byte() << 24) >>> 0) + ((this.byte() << 16) | (this.byte() << 8) | this.byte());
      n = hi * 0x100000000 + lo;
      if (!Number.isSafeInteger(n)) throw new CborError('CBOR integer too large');
      min = 0x100000000;
    } else {
      throw new CborError('indefinite lengths and reserved values are not allowed');
    }
    if (n < min) throw new CborError('non-shortest CBOR integer encoding');
    return n;
  }

  value(depth = 0): CborValue {
    if (depth > 16) throw new CborError('CBOR nesting too deep');
    const initial = this.byte();
    const major = initial >> 5;
    const info = initial & 0x1f;
    switch (major) {
      case 0:
        return this.argument(info);
      case 1:
        return -1 - this.argument(info);
      case 2:
        return this.take(this.argument(info));
      case 3:
        return new TextDecoder('utf-8', { fatal: true }).decode(this.take(this.argument(info)));
      case 4: {
        const n = this.argument(info);
        const out: CborValue[] = [];
        for (let i = 0; i < n; i++) out.push(this.value(depth + 1));
        return out;
      }
      case 5: {
        const n = this.argument(info);
        const out = new Map<CborValue, CborValue>();
        for (let i = 0; i < n; i++) {
          const key = this.value(depth + 1);
          if (typeof key !== 'number' && typeof key !== 'string') {
            throw new CborError('only integer and text map keys are supported');
          }
          if (out.has(key)) throw new CborError('duplicate CBOR map key');
          out.set(key, this.value(depth + 1));
        }
        return out;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 23) return undefined;
        throw new CborError('floats and other simple values are not supported');
      default:
        throw new CborError('CBOR tags are not supported');
    }
  }
}

/** Decodes exactly one CBOR item spanning all of `bytes`. */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.value();
  if (reader.offset !== bytes.length) throw new CborError('trailing bytes after CBOR item');
  return value;
}

/** Decodes one CBOR item starting at `offset`; returns it with the offset just past it. */
export function decodeCborPrefix(
  bytes: Uint8Array,
  offset: number,
): { value: CborValue; end: number } {
  const reader = new Reader(bytes, offset);
  const value = reader.value();
  return { value, end: reader.offset };
}
