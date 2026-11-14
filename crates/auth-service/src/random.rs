//! Random values from the operating system CSPRNG (via AWS-LC).

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// `N` random bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N], crate::error::ApiError> {
    let mut out = [0u8; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| crate::error::ApiError::Internal("CSPRNG failure".into()))?;
    Ok(out)
}
