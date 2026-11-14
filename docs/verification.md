# Verification

This document says exactly what is machine-checked, by which tool, under which
assumptions, and what is trusted without proof. If something is not listed as
proven here, it is not.

## Summary

| Layer | Tool | What is proven | Where |
|---|---|---|---|
| Protocol design | Tamarin 1.12 | Authentication, token-theft resistance, revocation, recovery and phishing-resistance properties of the protocol against a network attacker (see [`model/README.md`](../model/README.md)) | `model/` |
| Security decisions | Verus | Every check accepts **if and only if** its specification holds; outputs are read from the right bytes; token lifetimes are bounded; no overflow, no panics | `crates/auth-core/src/decide.rs`, `bytes.rs` |
| Parsers | Kani 0.68 (bounded model checking) | No panics, overflows or out-of-bounds accesses for every input up to the stated size; round-trip and canonicity properties; the contracts Verus assumes | `crates/auth-core/src/kani_proofs.rs` |
| Parsers, larger inputs | cargo-fuzz (libFuzzer) | No crashes found; no forged token accepted; encodings canonical | `fuzz/` |
| Behaviour | Unit, property and end-to-end tests | Every rejection path, every protocol flow against DynamoDB and KMS (aws-emulator) | `crates/*/tests`, `#[cfg(test)]` modules |
| Memory safety | Rust | No undefined behaviour outside dependencies: `#![forbid(unsafe_code)]` in every crate | all crates |

## Verus: the decision layer

`crates/auth-core/src/decide.rs` contains every accept/reject decision the
service and resource servers make:

| Function | Specification | Protocol |
|---|---|---|
| `check_registration` | `registration_ok`: client data (type, challenge, origin, no cross-origin, no top origin), RP ID hash, UP, UV, BS⇒BE, AT, credential ID length and equality, COSE key prefix with an allowed algorithm, extensions exactly one CBOR map iff ED, attestation `none` or verified `packed` self-attestation with matching algorithm | §8 |
| `check_assertion` | `assertion_ok`: credential and user handle match the stored record, client data, RP ID hash, UP, UV, BS⇒BE, no AT, unchanged BE, extensions, signature counter rule, signature over `authData ‖ SHA-256(clientDataJSON)` with the stored key | §8 |
| `check_dpop` | `dpop_ok`: compact JWS, `alg = ES256`, `typ = dpop+jwt`, no forbidden headers, public P-256 `jwk` without private members, valid signature by that key, `jti` length, exact `htm`/`htu`, `iat` window, nonce (when required), `ath` = SHA-256 of the presented access token and absent otherwise | §7 |
| `check_resource_request` | access token valid (`at+jwt`, ES256, `kid` of a trusted key, valid signature, issuer, audience, unexpired, not issued in the future, lifetime ≤ 300 s, `auth_time ≤ iat`) **and** DPoP proof valid for this token **and** `cnf.jkt` = proof key thumbprint | §6.1, §7 |
| `check_refresh_token` | `refresh_token_ok`: `rt+jwt`, ES256, trusted `kid`, valid signature, issuer and audience, client, unexpired, not issued in the future, `exp ≤ auth_time + 1 year`, `cnf.jkt` = proof key | §6.2 rules 1–4 |
| `authorize_refresh` | `refresh_authorized`: passkey still registered, epoch unchanged, session extendable | §6.2 rules 5–6 |
| `lifetimes` | access token lives exactly 300 s; refresh expiry is `min(now + 30 d, auth_time + 365 d)` and strictly after `now` | §6 |
| `check_session_active` | `session_active`: the token carries an epoch equal to the account's and its passkey is still registered (immediate revocation at the account API) | §10.7 |
| `check_step_up`, `check_ceremony`, `nonce_windows` | step-up age, ceremony kind and expiry, valid nonce windows | §7.2, §10.7 |

Properties worth calling out:

- **Completeness of checks.** Each `check_*` has the postcondition
  `r is Ok <==> spec(...)`. A check cannot be skipped or weakened without the
  proof failing, and the specification is written to be read against the
  protocol document rather than against the code.
- **Bounded sessions.** `lifetimes` and `authorize_refresh` prove that every
  refresh token issued for a session expires no later than
  `auth_time + REFRESH_ABSOLUTE_TTL`, and `auth_time` is carried over unchanged
  on refresh, so no chain of refreshes can extend a session past one year.
- **Type-level ordering.** `authorize_refresh` takes a `VerifiedRefresh`, which
  can only be constructed by `check_refresh_token`, so the stateful rules can
  never run on an unverified token.
- **No preconditions on public functions.** Callers in unverified code cannot
  invalidate the guarantees by violating an unchecked `requires`.

Run: `cd crates/auth-core && cargo verus verify` (expects
`verification results:: 67 verified, 0 errors`).

### What Verus assumes (`crates/auth-core/src/axioms.rs`)

The decision layer calls parsers and cryptographic primitives through wrappers
marked `#[verifier::external_body]`. Each has a contract stated in terms of an
**uninterpreted** specification function: the proofs assume only that it is a
function (same input, same output) plus the explicitly stated bounds. This is
the trusted boundary:

| Primitive | Implemented by | Contract assumed | How it is checked |
|---|---|---|---|
| SHA-256 | AWS-LC | output is 32 bytes | AWS-LC (FIPS-validated; core algorithms formally verified upstream), known-answer test |
| WebAuthn signature verification (ES256 DER, Ed25519, RS256) | AWS-LC via `crypto::verify_cose` | none beyond being a function | AWS-LC, tests with real signatures from three algorithms |
| JWS ES256 verification | AWS-LC | none | AWS-LC, tests |
| RFC 7638 thumbprint | `crypto::jwk_thumbprint_p256` | none | RFC 9449 §6.1 test vector |
| base64url decoding | `b64::decode` | none | Kani (canonicity, round trip, no panics), property tests, fuzzing |
| `clientDataJSON`, JWS header and claims parsing | `wire` (serde_json) | none | unit tests, fuzzing |
| `attestationObject` parsing | `wire` + `cbor` | none | Kani (CBOR bounds), unit tests, fuzzing |
| COSE key prefix | `cose::parse_prefix` | reported length `n` satisfies `0 < n ≤ len` | `parse_prefix` returns `cbor::item_len`'s result, which Kani proves bounded (`cbor_item_len_within_bounds`); fuzzing |
| Extensions map | `cbor::is_single_map` | none | Kani, fuzzing |
| JWS compact split | `wire::split_jws` | none (Kani checks the separator scan: exactly two dots at the reported positions; the signing input is the prefix before the second) | Kani `split_jws_separators`, fuzzing |

Because the specifications are written over these same uninterpreted functions,
"the check accepts iff the specification holds" is exact; what remains trusted
is that the primitives compute what their names say.

## Kani: parsers and contracts

Each harness in `crates/auth-core/src/kani_proofs.rs` explores **every** input
in its domain. Kani checks every arithmetic operation, index and `unwrap`
automatically, in addition to the assertions. Cryptographic calls are replaced
by nondeterministic stubs (`crypto.rs`, `#[cfg(kani)]`), which over-approximate
every possible result. The CBOR walker's UTF-8 check is modeled the same way
(`cbor::is_utf8`): it can only reject an item, never change its length, so the
bounds proof covers both outcomes, and UTF-8 validation itself is the standard
library's.

The parsers are structured for this: the part that decides what is accepted is
allocation-free (base64url group codecs, the CBOR item walker, the JWS separator
scan, recovery-code bit packing, DER integer encoding), and the public functions
only concatenate its results. Bounded model checkers handle fixed-size data
exhaustively, so several properties below hold for *all* inputs, not just small
ones.

| Harness | Property | Domain |
|---|---|---|
| `b64_group_roundtrip` | encoding then decoding any 1–3 byte group gives it back | all groups |
| `b64_group_canonical` | every accepted 2–4 symbol group is the canonical encoding of its bytes (so decoding is injective); other group sizes are rejected | all groups |
| `b64_decode_never_panics` | the full decoder never panics | inputs ≤ 9 symbols |
| `cbor_item_len_within_bounds` | the item walker that fixes what `decode_prefix` and `cose::parse_prefix` report as consumed returns `1 ≤ used ≤ len`; this discharges the contract of `axioms::cose_prefix` | inputs ≤ 6 bytes |
| `der_to_fixed_never_panics` | the strict DER parser never panics | inputs ≤ 12 bytes |
| `der_roundtrip` | every fixed signature with non-zero `r`, `s` survives DER encoding and strict decoding; zero `r` or `s` is refused | all 2^512 inputs |
| `spki_accepts_only_exact_length` | only a 91-byte SubjectPublicKeyInfo is accepted | inputs ≤ 93 bytes |
| `crockford_symbols_roundtrip` | recovery-code bit packing round-trips | all 2^160 codes |
| `crockford_alphabet_inverse` | parsing inverts display for every symbol, either case | all symbols |
| `crockford_decode_never_panics` | parsing typed input never panics | inputs ≤ 10 bytes |
| `split_jws_separators` | contract of `axioms::split_jws`: a split exists only with exactly two `.`, at the reported positions; the signing input is the prefix before the second | inputs ≤ 10 bytes |

Composition arguments that are not machine-checked: `b64::encode`/`decode`
concatenate group results over `chunks(3)`/`chunks(4)`, which align exactly;
`cbor::decode_prefix` returns `item_len`'s value (and fails if the value builder
disagrees); `cose::parse_prefix` returns `item_len`'s value directly;
`wire::split_jws` slices at `dot_positions`. Property tests and fuzzing exercise
the full functions on large inputs.

Run: `cd crates/auth-core && cargo kani --jobs 8 --output-format terse`.

## Tamarin: the protocol

See [`model/README.md`](../model/README.md) for the model, its abstractions,
the threat model and each lemma. Run: `scripts/prove-model.sh`.

## Trusted computing base

Not proven, and trusted:

1. **Cryptography**: AWS-LC (signature verification, SHA-256, randomness) and
   AWS KMS (token signing keys and the nonce MAC key).
2. **The verifiers themselves**: Verus (with Z3), Kani (with CBMC), Tamarin
   (with Maude), and the Rust compiler.
3. **The primitives' contracts** listed above.
4. **Unverified plumbing**: HTTP handling (axum, hyper, lambda_http), the
   DynamoDB and KMS clients, and the service's orchestration code
   (`crates/auth-service`). Orchestration is covered by end-to-end tests, and
   every decision in it is delegated to `decide`. In particular, the
   orchestration is trusted to (a) consume each challenge before verifying it,
   (b) read the account state with strongly consistent reads, (c) apply
   state changes with the conditional transactions in `store.rs`.
5. **Platform**: browsers and operating systems (origin binding, non-extractable
   key storage), passkey providers, and AWS (API Gateway, Lambda, DynamoDB).
6. **Side channels**: functional proofs say nothing about timing. Secret
   comparisons are done by AWS-LC (constant time); the values compared in
   `decide` with ordinary equality are public (nonces, identifiers, hashes of
   public data).

## Limits

- Verus proves the code matches the specification. Whether the specification
  says the right thing is checked by review against `docs/protocol.md` and by
  the Tamarin model, not by a proof.
- Kani's guarantees hold up to the stated bounds.
- The Tamarin model abstracts time (expiry and TTLs are covered by the Verus
  proofs of `lifetimes`, `check_step_up` and `check_ceremony` instead).
