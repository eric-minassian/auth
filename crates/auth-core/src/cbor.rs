//! A small, strict CBOR (RFC 8949) decoder for the subset WebAuthn uses.
//!
//! Supported: unsigned and negative integers, byte strings, text strings,
//! arrays, maps, `false`, `true` and `null`, all with definite lengths.
//!
//! Rejected: indefinite lengths, tags, floats, `undefined` and other simple
//! values, reserved additional-information values, invalid UTF-8, duplicate map
//! keys, nesting deeper than [`MAX_DEPTH`], containers with more than
//! [`MAX_ITEMS`] entries and truncated input.
//!
//! Kani proves that the item-extent walker behind `decode_prefix` never panics
//! and never reports more bytes than it was given (see `kani_proofs`).
//! Fuzzing covers larger inputs and the value builder.

/// Maximum nesting depth of arrays and maps.
pub const MAX_DEPTH: usize = 8;
/// Maximum number of entries in one array or map.
pub const MAX_ITEMS: u64 = 64;

/// A decoded CBOR data item that borrows from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value is `-1 - n`.
    Nint(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Value<'a>>),
    /// Major type 5, in encoding order.
    Map(Vec<(Value<'a>, Value<'a>)>),
    /// Simple values 20 and 21.
    Bool(bool),
    /// Simple value 22.
    Null,
}

impl<'a> Value<'a> {
    /// Returns the value as a signed integer if it is an integer in `i64` range.
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Uint(n) => i64::try_from(n).ok(),
            Value::Nint(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// Looks up a map entry whose key is the integer `key`.
    pub fn map_get_int(&self, key: i64) -> Option<&Value<'a>> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.as_i64() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// Looks up a map entry whose key is the text string `key`.
    pub fn map_get_text(&self, key: &str) -> Option<&Value<'a>> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if *t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.input.get(self.pos)?;
        self.pos = self.pos.checked_add(1)?;
        Some(b)
    }

    fn take(&mut self, n: u64) -> Option<&'a [u8]> {
        let n = usize::try_from(n).ok()?;
        let end = self.pos.checked_add(n)?;
        let s = self.input.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn be(&mut self, n: u64) -> Option<u64> {
        let bytes = self.take(n)?;
        let mut v: u64 = 0;
        for b in bytes {
            v = (v << 8) | u64::from(*b);
        }
        Some(v)
    }

    fn arg(&mut self, info: u8) -> Option<u64> {
        match info {
            0..=23 => Some(u64::from(info)),
            24 => self.be(1),
            25 => self.be(2),
            26 => self.be(4),
            27 => self.be(8),
            // 28..=30 are reserved; 31 is the indefinite-length marker.
            _ => None,
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value<'a>> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            0 => Some(Value::Uint(self.arg(info)?)),
            1 => Some(Value::Nint(self.arg(info)?)),
            2 => {
                let n = self.arg(info)?;
                Some(Value::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.arg(info)?;
                let s = self.take(n)?;
                Some(Value::Text(core::str::from_utf8(s).ok()?))
            }
            4 => {
                let n = self.arg(info)?;
                if n > MAX_ITEMS || depth >= MAX_DEPTH {
                    return None;
                }
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.value(depth.checked_add(1)?)?);
                }
                Some(Value::Array(items))
            }
            5 => {
                let n = self.arg(info)?;
                if n > MAX_ITEMS || depth >= MAX_DEPTH {
                    return None;
                }
                let mut entries: Vec<(Value<'a>, Value<'a>)> = Vec::new();
                for _ in 0..n {
                    let key = self.value(depth.checked_add(1)?)?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return None;
                    }
                    let val = self.value(depth.checked_add(1)?)?;
                    entries.push((key, val));
                }
                Some(Value::Map(entries))
            }
            7 => match info {
                20 => Some(Value::Bool(false)),
                21 => Some(Value::Bool(true)),
                22 => Some(Value::Null),
                _ => None,
            },
            // Major type 6 (tags) is not used by WebAuthn and is rejected.
            _ => None,
        }
    }
}

/// Reads an initial byte and its argument at `pos`: `(major, info, argument,
/// next position)`.
fn head(input: &[u8], pos: usize) -> Option<(u8, u8, u64, usize)> {
    let initial = *input.get(pos)?;
    let major = initial >> 5;
    let info = initial & 0x1f;
    let mut p = pos.checked_add(1)?;
    let width: usize = match info {
        0..=23 => return Some((major, info, u64::from(info), p)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let mut arg: u64 = 0;
    for _ in 0..width {
        arg = (arg << 8) | u64::from(*input.get(p)?);
        p = p.checked_add(1)?;
    }
    Some((major, info, arg, p))
}

fn walk(input: &[u8], pos: usize, depth: usize) -> Option<usize> {
    let (major, info, arg, mut p) = head(input, pos)?;
    match major {
        0 | 1 => Some(p),
        2 | 3 => {
            let end = p.checked_add(usize::try_from(arg).ok()?)?;
            let s = input.get(p..end)?;
            if major == 3 {
                core::str::from_utf8(s).ok()?;
            }
            Some(end)
        }
        4 | 5 => {
            if arg > MAX_ITEMS || depth >= MAX_DEPTH {
                return None;
            }
            let count = if major == 5 { arg * 2 } else { arg };
            for _ in 0..count {
                p = walk(input, p, depth.checked_add(1)?)?;
            }
            Some(p)
        }
        7 if matches!(info, 20..=22) => Some(p),
        _ => None,
    }
}

/// The length of the data item at the start of `input`, under the decoder's
/// rules except duplicate-key detection (which needs the values). This is the
/// allocation-free core Kani checks: a returned length is always within the
/// input.
pub(crate) fn item_len(input: &[u8]) -> Option<usize> {
    walk(input, 0, 0)
}

/// Decodes one data item from the start of `input` and returns it together
/// with the number of bytes it occupies. Trailing bytes are left unread.
///
/// The extent comes from [`item_len`] and the value is then built from exactly
/// that slice, so the reported length is the one Kani proves bounded. If the
/// two passes ever disagreed, decoding would fail closed.
pub fn decode_prefix(input: &[u8]) -> Option<(Value<'_>, usize)> {
    let used = item_len(input)?;
    let mut d = Decoder {
        input: input.get(..used)?,
        pos: 0,
    };
    let v = d.value(0)?;
    (d.pos == used).then_some((v, used))
}

/// Decodes `input`, which must contain exactly one data item.
pub fn decode_exact(input: &[u8]) -> Option<Value<'_>> {
    let (v, used) = decode_prefix(input)?;
    (used == input.len()).then_some(v)
}

/// Returns true iff `input` is exactly one CBOR map (used for the WebAuthn
/// extensions block, whose contents are otherwise ignored).
pub fn is_single_map(input: &[u8]) -> bool {
    matches!(decode_exact(input), Some(Value::Map(_)))
}

/// A minimal CBOR encoder used to build test vectors and fuzz seeds.
#[cfg(any(test, feature = "test-support"))]
pub mod encode {
    fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        if n < 24 {
            out.push(m | u8::try_from(n).unwrap_or(0));
        } else if let Ok(n) = u8::try_from(n) {
            out.push(m | 0x18);
            out.push(n);
        } else if let Ok(n) = u16::try_from(n) {
            out.push(m | 0x19);
            out.extend_from_slice(&n.to_be_bytes());
        } else if let Ok(n) = u32::try_from(n) {
            out.push(m | 0x1a);
            out.extend_from_slice(&n.to_be_bytes());
        } else {
            out.push(m | 0x1b);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }

    /// An owned CBOR item for encoding.
    #[derive(Debug, Clone)]
    pub enum Item {
        /// Integer (either sign).
        Int(i64),
        /// Byte string.
        Bytes(Vec<u8>),
        /// Text string.
        Text(String),
        /// Array.
        Array(Vec<Item>),
        /// Map in the given order.
        Map(Vec<(Item, Item)>),
        /// Boolean.
        Bool(bool),
    }

    impl Item {
        /// Encodes the item.
        pub fn to_vec(&self) -> Vec<u8> {
            let mut out = Vec::new();
            self.write(&mut out);
            out
        }

        fn write(&self, out: &mut Vec<u8>) {
            match self {
                Item::Int(i) => {
                    if *i >= 0 {
                        head(out, 0, i.unsigned_abs());
                    } else {
                        head(out, 1, i.unsigned_abs() - 1);
                    }
                }
                Item::Bytes(b) => {
                    head(out, 2, b.len() as u64);
                    out.extend_from_slice(b);
                }
                Item::Text(t) => {
                    head(out, 3, t.len() as u64);
                    out.extend_from_slice(t.as_bytes());
                }
                Item::Array(items) => {
                    head(out, 4, items.len() as u64);
                    for i in items {
                        i.write(out);
                    }
                }
                Item::Map(entries) => {
                    head(out, 5, entries.len() as u64);
                    for (k, v) in entries {
                        k.write(out);
                        v.write(out);
                    }
                }
                Item::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::encode::Item;
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rfc8949_appendix_a_vectors() {
        assert_eq!(decode_exact(&[0x00]), Some(Value::Uint(0)));
        assert_eq!(decode_exact(&[0x17]), Some(Value::Uint(23)));
        assert_eq!(decode_exact(&[0x18, 0x18]), Some(Value::Uint(24)));
        assert_eq!(decode_exact(&[0x19, 0x03, 0xe8]), Some(Value::Uint(1000)));
        assert_eq!(
            decode_exact(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Some(Value::Uint(u64::MAX))
        );
        assert_eq!(decode_exact(&[0x20]), Some(Value::Nint(0)));
        assert_eq!(
            decode_exact(&[0x38, 0x63]).and_then(|v| v.as_i64()),
            Some(-100)
        );
        assert_eq!(
            decode_exact(&[0x44, 1, 2, 3, 4]),
            Some(Value::Bytes(&[1, 2, 3, 4]))
        );
        assert_eq!(decode_exact(&[0x62, 0xc3, 0xbc]), Some(Value::Text("ü")));
        assert_eq!(decode_exact(&[0xf4]), Some(Value::Bool(false)));
        assert_eq!(decode_exact(&[0xf6]), Some(Value::Null));
        assert_eq!(
            decode_exact(&[0x82, 0x01, 0x02]),
            Some(Value::Array(vec![Value::Uint(1), Value::Uint(2)]))
        );
    }

    #[test]
    fn rejects_unsupported_and_malformed() {
        let bad: &[&[u8]] = &[
            &[],                             // empty
            &[0x5f, 0x41, 0x00, 0xff],       // indefinite byte string
            &[0x9f, 0xff],                   // indefinite array
            &[0xc1, 0x00],                   // tag
            &[0xf9, 0x3c, 0x00],             // half float
            &[0xf7],                         // undefined
            &[0x1c],                         // reserved additional info
            &[0x42, 0x00],                   // truncated byte string
            &[0x62, 0xff, 0xfe],             // invalid UTF-8
            &[0xa2, 0x01, 0x00, 0x01, 0x00], // duplicate key
            &[0x1b, 0, 0, 0, 0],             // truncated argument
        ];
        for b in bad {
            assert_eq!(decode_exact(b), None, "{b:02x?} must be rejected");
        }
        // Trailing bytes are rejected by decode_exact but reported by decode_prefix.
        assert_eq!(decode_exact(&[0x00, 0x00]), None);
        assert_eq!(decode_prefix(&[0x00, 0x00]), Some((Value::Uint(0), 1)));
    }

    #[test]
    fn depth_limit() {
        let mut nested = Item::Int(0);
        for _ in 0..MAX_DEPTH {
            nested = Item::Array(vec![nested]);
        }
        assert!(decode_exact(&nested.to_vec()).is_some());
        let too_deep = Item::Array(vec![nested]);
        assert_eq!(decode_exact(&too_deep.to_vec()), None);
    }

    fn item() -> impl Strategy<Value = Item> {
        let leaf = prop_oneof![
            any::<i64>().prop_map(Item::Int),
            proptest::collection::vec(any::<u8>(), 0..40).prop_map(Item::Bytes),
            ".{0,20}".prop_map(Item::Text),
            any::<bool>().prop_map(Item::Bool),
        ];
        leaf.prop_recursive(4, 32, 6, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..6).prop_map(Item::Array),
                proptest::collection::vec((any::<i64>(), inner), 0..6).prop_map(|kv| {
                    let mut seen = std::collections::HashSet::new();
                    Item::Map(
                        kv.into_iter()
                            .filter(|(k, _)| seen.insert(*k))
                            .map(|(k, v)| (Item::Int(k), v))
                            .collect(),
                    )
                }),
            ]
        })
    }

    proptest! {
        #[test]
        fn decodes_what_encoder_produces(it in item()) {
            let bytes = it.to_vec();
            prop_assert!(decode_exact(&bytes).is_some());
        }

        #[test]
        fn never_overreads(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            if let Some((_, used)) = decode_prefix(&bytes) {
                prop_assert!(used >= 1 && used <= bytes.len());
            }
        }
    }
}
