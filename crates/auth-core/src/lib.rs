//! Formally verified decision core of the passkey auth service.
//!
//! - [`decide`] holds every security decision, verified with Verus: each check
//!   accepts if and only if its specification holds.
//! - [`axioms`] is the trusted boundary: contracts for the parsers and crypto
//!   primitives the verified code calls.
//! - [`b64`], [`cbor`], [`cose`], [`der`], [`spki`], [`crockford`] and [`wire`]
//!   are the parsers, checked by Kani harnesses, tests and fuzzing.
//! - [`webauthn`] and [`jose`] are the ergonomic API used by the service.
//!
//! See `docs/verification.md` for what is proven and what is trusted.
#![forbid(unsafe_code)]

pub mod axioms;
pub mod b64;
pub mod bytes;
pub mod cbor;
pub mod cose;
pub mod crockford;
pub mod crypto;
pub mod decide;
pub mod der;
pub mod jose;
pub mod spki;
pub mod vtypes;
pub mod webauthn;
pub mod wire;

#[cfg(any(test, feature = "test-support"))]
pub mod testing;

#[cfg(kani)]
mod kani_proofs;
