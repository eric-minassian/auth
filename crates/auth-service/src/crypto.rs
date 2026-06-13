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
/// (session id, auth code, refresh secret, OTP) is stored at rest.
pub fn sha256_b64u(input: impl AsRef<[u8]>) -> String {
    b64u(Sha256::digest(input.as_ref()))
}

/// `n` random bytes from the thread CSPRNG, base64url-encoded.
pub fn random_b64u(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    b64u(buf)
}

/// Six-digit, zero-padded OTP code.
pub fn random_otp() -> String {
    let mut buf = [0u8; 4];
    rand::rng().fill_bytes(&mut buf);
    format!("{:06}", u32::from_be_bytes(buf) % 1_000_000)
}

/// Constant-time string equality (compares hashes, never raw secrets of
/// differing provenance).
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
