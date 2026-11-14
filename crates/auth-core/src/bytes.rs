//! Verified byte-string helpers used by the decision layer.

// Verus-verified code follows the subset of Rust that Verus supports: explicit
// `match` instead of `let ... else`, `&Vec` parameters (their views are used in
// specifications), `as` casts with proven ranges, and glob imports of spec items.
#![allow(
    clippy::manual_let_else,
    clippy::ptr_arg,
    clippy::ref_option,
    clippy::too_many_arguments,
    clippy::match_like_matches_macro,
    clippy::manual_range_contains,
    clippy::many_single_char_names,
    clippy::cast_lossless,
    clippy::unreadable_literal,
    clippy::wildcard_imports,
    clippy::nonminimal_bool
)]

use vstd::prelude::*;

verus! {

/// `x` is one of the byte strings in `set`.
pub open spec fn seq_in(x: Seq<u8>, set: Seq<Vec<u8>>) -> bool {
    exists|i: int| 0 <= i < set.len() && #[trigger] set[i]@ == x
}

/// Byte-string equality. Not constant time: only used on public values.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> (r: bool)
    ensures
        r == (a@ == b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            a.len() == b.len(),
            i <= a.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}

/// Membership of `x` in `set`.
pub fn contains(set: &Vec<Vec<u8>>, x: &[u8]) -> (r: bool)
    ensures
        r == seq_in(x@, set@),
{
    let mut i: usize = 0;
    while i < set.len()
        invariant
            i <= set.len(),
            forall|j: int| #![trigger set@[j]] 0 <= j < i ==> set@[j]@ != x@,
        decreases set.len() - i,
    {
        if bytes_eq(set[i].as_slice(), x) {
            assert(set@[i as int]@ == x@);
            return true;
        }
        i += 1;
    }
    false
}

/// Copies `src[start..end]` into a new vector.
pub fn copy_range(src: &[u8], start: usize, end: usize) -> (r: Vec<u8>)
    requires
        start <= end <= src@.len(),
    ensures
        r@ == src@.subrange(start as int, end as int),
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = start;
    while i < end
        invariant
            start <= i <= end <= src@.len(),
            out@ == src@.subrange(start as int, i as int),
        decreases end - i,
    {
        out.push(src[i]);
        i += 1;
        assert(out@ =~= src@.subrange(start as int, i as int));
    }
    out
}

/// Copies a whole slice.
pub fn copy_all(src: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == src@,
{
    let r = copy_range(src, 0, src.len());
    assert(src@.subrange(0, src@.len() as int) =~= src@);
    r
}

/// `a ++ b`.
pub fn concat(a: &[u8], b: &[u8]) -> (r: Vec<u8>)
    ensures
        r@ == a@ + b@,
{
    let mut out = copy_all(a);
    let mut i: usize = 0;
    while i < b.len()
        invariant
            i <= b@.len(),
            out@ == a@ + b@.subrange(0, i as int),
        decreases b.len() - i,
    {
        out.push(b[i]);
        i += 1;
        assert(out@ =~= a@ + b@.subrange(0, i as int));
    }
    assert(b@.subrange(0, b@.len() as int) =~= b@);
    out
}

/// Index of the first occurrence of `c` in `s[from..]`, if any.
pub fn find_byte(s: &[u8], from: usize, c: u8) -> (r: Option<usize>)
    requires
        from <= s@.len(),
    ensures
        r matches Some(i) ==> from <= i < s@.len() && s@[i as int] == c
            && forall|j: int| from <= j < i ==> s@[j] != c,
        r is None ==> forall|j: int| from <= j < s@.len() ==> s@[j] != c,
{
    let mut i = from;
    while i < s.len()
        invariant
            from <= i <= s@.len(),
            forall|j: int| from <= j < i ==> s@[j] != c,
        decreases s.len() - i,
    {
        if s[i] == c {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Big-endian `u16` at `s[i..i+2]` (spec).
pub open spec fn be_u16(s: Seq<u8>, i: int) -> nat {
    (s[i] as nat) * 256 + (s[i + 1] as nat)
}

/// Big-endian `u32` at `s[i..i+4]` (spec).
pub open spec fn be_u32(s: Seq<u8>, i: int) -> nat {
    (s[i] as nat) * 16777216 + (s[i + 1] as nat) * 65536 + (s[i + 2] as nat) * 256 + (s[i + 3] as nat)
}

/// Reads a big-endian `u16`.
pub fn read_be_u16(s: &[u8], i: usize) -> (r: usize)
    requires
        i + 2 <= s@.len(),
    ensures
        r as nat == be_u16(s@, i as int),
        r <= 65535,
{
    (s[i] as usize) * 256 + (s[i + 1] as usize)
}

/// Reads a big-endian `u32`.
pub fn read_be_u32(s: &[u8], i: usize) -> (r: u32)
    requires
        i + 4 <= s@.len(),
    ensures
        r as nat == be_u32(s@, i as int),
{
    let a = s[i] as u32;
    let b = s[i + 1] as u32;
    let c = s[i + 2] as u32;
    let d = s[i + 3] as u32;
    assert(a * 16777216 + b * 65536 + c * 256 + d <= 0xffff_ffff) by (nonlinear_arith)
        requires
            a <= 255,
            b <= 255,
            c <= 255,
            d <= 255,
    ;
    a * 16777216 + b * 65536 + c * 256 + d
}

} // verus!
