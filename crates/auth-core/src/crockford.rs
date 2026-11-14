//! Recovery-code text encoding: Crockford base32 (protocol §9).
//!
//! A recovery code is 20 bytes (160 bits), which is exactly 32 base32 symbols.
//! It is displayed in eight groups of four separated by `-`.

/// Length of a recovery code in bytes.
pub const RECOVERY_CODE_LEN: usize = 20;
const SYMBOLS: usize = 32;
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The 5-bit value of a typed symbol, after normalization.
pub(crate) fn value(c: u8) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    };
    let mut i = 0u8;
    while (i as usize) < ALPHABET.len() {
        if ALPHABET[i as usize] == c {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 20 bytes → 32 five-bit symbol values. Allocation-free core checked by Kani.
pub(crate) fn to_symbols(bytes: &[u8; RECOVERY_CODE_LEN]) -> [u8; SYMBOLS] {
    let mut out = [0u8; SYMBOLS];
    // 160 bits = 32 × 5 bits: symbol i covers bits 5i..5i+5 (big-endian).
    for (i, o) in out.iter_mut().enumerate() {
        let bit = i * 5;
        let byte = bit / 8;
        let hi = u16::from(bytes[byte]) << 8;
        let lo = bytes.get(byte + 1).map_or(0, |b| u16::from(*b));
        let window = hi | lo;
        let shift = 16 - 5 - (bit % 8);
        *o = ((window >> shift) & 0x1f) as u8;
    }
    out
}

/// 32 five-bit symbol values → 20 bytes. `None` if a value is ≥ 32.
/// Allocation-free core checked by Kani.
pub(crate) fn from_symbols(values: &[u8; SYMBOLS]) -> Option<[u8; RECOVERY_CODE_LEN]> {
    let mut out = [0u8; RECOVERY_CODE_LEN];
    for (i, v) in values.iter().enumerate() {
        if *v >= 32 {
            return None;
        }
        let bit = i * 5;
        let byte = bit / 8;
        let window = u16::from(*v) << (16 - 5 - (bit % 8));
        out[byte] |= (window >> 8) as u8;
        if let Some(next) = out.get_mut(byte + 1) {
            *next |= (window & 0xff) as u8;
        }
    }
    Some(out)
}

/// Encodes a recovery code for display.
pub fn encode_recovery_code(bytes: &[u8; RECOVERY_CODE_LEN]) -> String {
    let mut out = String::with_capacity(SYMBOLS + SYMBOLS / 4 - 1);
    for (i, v) in to_symbols(bytes).iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(char::from(ALPHABET[usize::from(*v)]));
    }
    out
}

/// Parses typed recovery-code bytes (see [`decode_recovery_code`]).
/// Allocation-free core checked by Kani.
pub(crate) fn decode_bytes(text: &[u8]) -> Option<[u8; RECOVERY_CODE_LEN]> {
    let mut values = [0u8; SYMBOLS];
    let mut n = 0usize;
    for c in text {
        if *c == b'-' || *c == b' ' {
            continue;
        }
        *values.get_mut(n)? = value(*c)?;
        n += 1;
    }
    if n != SYMBOLS {
        return None;
    }
    from_symbols(&values)
}

/// Parses a recovery code typed by a user. Hyphens and spaces are ignored,
/// letters are case-insensitive and `I`/`L`/`O` are read as `1`/`1`/`0`.
pub fn decode_recovery_code(text: &str) -> Option<[u8; RECOVERY_CODE_LEN]> {
    decode_bytes(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn format_and_normalization() {
        let code = encode_recovery_code(&[0u8; 20]);
        assert_eq!(code, "0000-0000-0000-0000-0000-0000-0000-0000");
        let code = encode_recovery_code(&[0xff; 20]);
        assert_eq!(code, "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ");
        assert_eq!(
            decode_recovery_code("zzzz zzzz-zzzzzzzz zzzz zzzz zzzz zzzz"),
            Some([0xff; 20])
        );
        assert_eq!(
            decode_recovery_code("oooo-oooo-oooo-oooo-oooo-oooo-oooo-oooo"),
            Some([0; 20])
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode_recovery_code(""), None);
        assert_eq!(
            decode_recovery_code("0000-0000-0000-0000-0000-0000-0000-000"),
            None
        );
        assert_eq!(
            decode_recovery_code("0000-0000-0000-0000-0000-0000-0000-00000"),
            None
        );
        assert_eq!(
            decode_recovery_code("UUUU-0000-0000-0000-0000-0000-0000-0000"),
            None
        );
        assert_eq!(
            decode_recovery_code("0000_0000-0000-0000-0000-0000-0000-0000"),
            None
        );
    }

    proptest! {
        #[test]
        fn roundtrip(bytes in proptest::array::uniform20(any::<u8>())) {
            let text = encode_recovery_code(&bytes);
            prop_assert_eq!(text.len(), 39);
            prop_assert_eq!(decode_recovery_code(&text), Some(bytes));
            prop_assert_eq!(decode_recovery_code(&text.to_lowercase()), Some(bytes));
        }
    }
}
