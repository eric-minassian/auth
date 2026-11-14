//! Strict base64url without padding (RFC 4648 §5).
//!
//! The decoder rejects padding, characters outside the URL-safe alphabet,
//! impossible lengths and non-canonical encodings (non-zero trailing bits), so
//! every byte string has exactly one accepted encoding.
//!
//! Both directions work group by group (3 bytes ↔ 4 symbols). Kani proves, for
//! every possible group, that the group codecs never panic, that decoding then
//! encoding gives back the same symbols (canonicity) and that encoding then
//! decoding gives back the same bytes; `encode` and `decode` only concatenate
//! groups (see `kani_proofs`).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Length of the unpadded encoding of `n` bytes.
pub const fn encoded_len(n: usize) -> usize {
    let full = (n / 3) * 4;
    match n % 3 {
        1 => full + 2,
        2 => full + 3,
        _ => full,
    }
}

fn sym(index: u32) -> u8 {
    // `index` is always < 64 because it is masked with 0x3f.
    ALPHABET[(index & 0x3f) as usize]
}

/// Encodes one group of 1–3 bytes into 2–4 symbols. Returns the symbols and
/// how many of them are used. The allocation-free core that Kani checks.
pub(crate) fn encode_group(group: &[u8]) -> ([u8; 4], usize) {
    match *group {
        [a, b, c] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
            ([sym(n >> 18), sym(n >> 12), sym(n >> 6), sym(n)], 4)
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            ([sym(n >> 18), sym(n >> 12), sym(n >> 6), 0], 3)
        }
        [a] => {
            let n = u32::from(a) << 16;
            ([sym(n >> 18), sym(n >> 12), 0, 0], 2)
        }
        _ => ([0; 4], 0),
    }
}

/// Encodes bytes as unpadded base64url.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(input.len()));
    for group in input.chunks(3) {
        let (symbols, used) = encode_group(group);
        for s in symbols.iter().take(used) {
            out.push(char::from(*s));
        }
    }
    out
}

fn val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes one group of 2–4 symbols into 1–3 bytes, rejecting invalid symbols
/// and non-zero trailing bits. Returns the bytes and how many are used. The
/// allocation-free core that Kani checks.
#[allow(clippy::many_single_char_names)] // a, b, c, d are the four symbols of a group
pub(crate) fn decode_group(group: &[u8]) -> Option<([u8; 3], usize)> {
    match *group {
        [a, b, c, d] => {
            let n = (val(a)? << 18) | (val(b)? << 12) | (val(c)? << 6) | val(d)?;
            Some((
                [
                    ((n >> 16) & 0xff) as u8,
                    ((n >> 8) & 0xff) as u8,
                    (n & 0xff) as u8,
                ],
                3,
            ))
        }
        [a, b, c] => {
            let c = val(c)?;
            if c & 0b11 != 0 {
                return None;
            }
            let n = (val(a)? << 18) | (val(b)? << 12) | (c << 6);
            Some(([((n >> 16) & 0xff) as u8, ((n >> 8) & 0xff) as u8, 0], 2))
        }
        [a, b] => {
            let b = val(b)?;
            if b & 0b1111 != 0 {
                return None;
            }
            let n = (val(a)? << 18) | (b << 12);
            Some(([((n >> 16) & 0xff) as u8, 0, 0], 1))
        }
        _ => None,
    }
}

/// Decodes strict unpadded base64url. Returns `None` for any input that is not
/// the canonical encoding of some byte string.
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
    for group in input.chunks(4) {
        let (bytes, used) = decode_group(group)?;
        out.extend_from_slice(bytes.get(..used)?);
    }
    Some(out)
}

/// Decodes a base64url string.
pub fn decode_str(input: &str) -> Option<Vec<u8>> {
    decode(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rfc4648_vectors() {
        // RFC 4648 §10 vectors, converted to the URL-safe alphabet without padding.
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xfb, 0xff], "-_8"),
        ];
        for (raw, enc) in cases {
            assert_eq!(encode(raw), *enc);
            assert_eq!(decode_str(enc).as_deref(), Some(*raw));
        }
    }

    #[test]
    fn rejects_non_canonical_and_invalid() {
        for bad in [
            "Zh", "Zm9", "Zg==", "Zg=", "Z", "Zm9vY", "Zm+v", "Zm/v", "Zm9v\n", " Zm9v",
        ] {
            assert_eq!(decode_str(bad), None, "{bad:?} must be rejected");
        }
    }

    proptest! {
        #[test]
        fn roundtrip(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let enc = encode(&bytes);
            prop_assert_eq!(enc.len(), encoded_len(bytes.len()));
            prop_assert_eq!(decode_str(&enc), Some(bytes));
        }

        #[test]
        fn decode_is_injective(s in "[A-Za-z0-9_-]{0,64}") {
            if let Some(bytes) = decode_str(&s) {
                prop_assert_eq!(encode(&bytes), s);
            }
        }
    }
}
