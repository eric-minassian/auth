use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn b64u(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// SHA-256 of the input, base64url-encoded. Used everywhere a secret
/// (session id, auth code, refresh secret, recovery code) is stored at rest.
pub fn sha256_b64u(input: impl AsRef<[u8]>) -> String {
    b64u(sha256_bytes(input))
}

/// Raw SHA-256 digest bytes (for bit-level work like the PoW difficulty check).
pub fn sha256_bytes(input: impl AsRef<[u8]>) -> [u8; 32] {
    let digest = Sha256::digest(input.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// `n` random bytes from the thread CSPRNG, base64url-encoded.
pub fn random_b64u(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    b64u(buf)
}

/// Constant-time string equality (compares hashes, never raw secrets of
/// differing provenance).
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// HMAC-SHA256 tag. Used to derive self-validating values (DPoP nonces) from
/// a server-side key without per-value storage.
pub fn hmac_sha256(key: &[u8; 32], msg: impl AsRef<[u8]>) -> [u8; 32] {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    // HMAC-SHA256 accepts keys of any length, so this arm is unreachable for
    // our fixed 32-byte key; the zero tag keeps the function total without an
    // unwrap (both derivation and validation share this same path).
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) else {
        return [0u8; 32];
    };
    Mac::update(&mut mac, msg.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

// ---- Recovery codes -------------------------------------------------------

/// Crockford base32 alphabet — excludes I, L, O, U to avoid transcription
/// ambiguity. 16 random bytes encode to 26 symbols (128 bits of entropy).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn crockford_encode(bytes: &[u8]) -> String {
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::new();
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(CROCKFORD[((acc >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(CROCKFORD[((acc << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// A freshly generated recovery code in two forms.
pub struct RecoveryCode {
    /// Uppercase, no separators — the form we hash (SHA-256) and compare. At
    /// 128 bits, plain SHA-256 at rest is sufficient (no slow KDF required).
    pub canonical: String,
    /// Dash-grouped for display; shown to the user exactly once.
    pub display: String,
}

/// Generate one 128-bit recovery code.
pub fn generate_recovery_code() -> RecoveryCode {
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    let canonical = crockford_encode(&buf);
    let display = canonical
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-");
    RecoveryCode { canonical, display }
}

/// Normalize user-entered recovery-code input to canonical form, or `None` if
/// it can't be a valid code. Drops separators/whitespace, uppercases, folds
/// Crockford-confusable characters (`I`/`L` → `1`, `O` → `0`), then validates
/// the alphabet and length. Identical normalization on generate and redeem is
/// what prevents a valid code from being silently rejected.
pub fn normalize_recovery_code(input: &str) -> Option<String> {
    let mut s = String::with_capacity(26);
    for c in input.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(match c.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                other => other,
            });
        }
    }
    if s.len() != 26 || !s.bytes().all(|b| CROCKFORD.contains(&b)) {
        return None;
    }
    Some(s)
}

// ---- Proof of work --------------------------------------------------------

/// Count leading zero bits across a byte slice (PoW difficulty metric).
pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Verify a proof-of-work solution: `SHA-256("{challenge}:{nonce}")` must have
/// at least `difficulty` leading zero bits.
pub fn verify_pow(challenge: &str, nonce: &str, difficulty: u32) -> bool {
    leading_zero_bits(&sha256_bytes(format!("{challenge}:{nonce}"))) >= difficulty
}
