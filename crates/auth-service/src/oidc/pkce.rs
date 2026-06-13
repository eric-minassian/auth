use sha2::{Digest, Sha256};

use crate::crypto::{b64u, ct_eq};

/// RFC 7636 §4.1 verifier charset: ALPHA / DIGIT / "-" / "." / "_" / "~",
/// length 43–128.
pub fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// S256: challenge == BASE64URL(SHA256(verifier)), compared constant-time.
pub fn verify_s256(challenge: &str, verifier: &str) -> bool {
    valid_verifier(verifier) && ct_eq(&b64u(Sha256::digest(verifier.as_bytes())), challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_s256(challenge, verifier));
        assert!(!verify_s256(
            challenge,
            "wrong-verifier-wrong-verifier-wrong-verifier"
        ));
    }
}
