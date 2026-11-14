//! Time source, injectable for tests.

use std::fmt::Debug;

/// A source of Unix time in seconds.
pub trait Clock: Send + Sync + Debug {
    /// Current Unix time in seconds.
    fn now(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        auth_verifier::unix_now()
    }
}
