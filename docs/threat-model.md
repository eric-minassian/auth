# Threat model

## Assets

| Asset | Why it matters |
|---|---|
| Control of an account | Everything downstream authorizes on `sub` |
| Unlinkability of users to real identities | The service promises to hold no PII |
| Availability of sign-in | Users have no fallback channel |

## Actors and capabilities

| Actor | Capabilities assumed |
|---|---|
| Network attacker | Reads, drops, replays and injects any message (Dolev–Yao); TLS is assumed to hold for the in-scope properties, but the protocol is designed so that captured tokens are useless anyway |
| Phishing site | Lures the user to an attacker-controlled origin and relays anything it receives |
| Malware on a user's device (infostealer) | Copies cookies, local storage and files, then uses them elsewhere |
| XSS on the web app's origin | Runs script in the app's origin while the page is open |
| Malicious client | Sends arbitrary, malformed or oversized requests |
| Bot operator | Creates many accounts |
| Compromised database snapshot | Reads every DynamoDB item |
| AWS operator / KMS | Trusted |

## Threats and mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Password or OTP phishing | No passwords or OTPs exist. Passkeys are bound to the RP ID by the authenticator and the origin is checked exactly | protocol §8; verified `check_assertion` |
| Real-time phishing relay | The relaying site's origin is in `clientDataJSON` and is rejected; the authenticator refuses to sign for a foreign RP ID | §8; Tamarin phishing lemma |
| Stolen access or refresh token (network, logs, infostealer) | Every token is DPoP-bound (`cnf.jkt`); requests need a fresh proof signed by a non-extractable device key | §6, §7; verified `check_resource_request`, `check_refresh_token`; Tamarin token-theft lemma |
| Replayed DPoP proof | Server nonces (current and previous 5-minute window), `iat` window, single-use `jti` at the auth service, optional replay cache at resource servers | §7.2–7.3 |
| Replayed WebAuthn response | 32-byte single-use challenges, consumed with a conditional delete before verification and expiring after 5 minutes | §8; Tamarin injective-agreement lemma |
| Cloned authenticator | Signature counter must strictly increase unless it is always zero (synced passkeys) | §8; verified `sign_count_ok` |
| Token confusion (refresh as access, DPoP proof as token) | Explicit `typ` per token kind, separate signing keys, refresh key never published | §5; verified header checks |
| Algorithm confusion, `alg: none`, embedded or remote keys | Only `ES256`; `jku`/`x5u`/`x5c`/`crit`/`b64` rejected; issued tokens may not carry `jwk` | §5; verified `issued_header_ok`, `dpop_header_ok` |
| Signing key theft | Private keys live in KMS HSMs; signatures are verified locally before release | `kms.rs` |
| Lost device | Synced passkeys, additional passkeys, recovery code; "sign out everywhere" | §6.3, §9 |
| Stolen recovery code | 160-bit entropy, stored hashed, single-use; using it revokes every session and passkey, which the legitimate user notices immediately | §9 |
| Session outliving revocation | Refresh checks the passkey and epoch with strongly consistent reads; the account API checks them on every request; access tokens live 5 minutes | §6.2, §10.7; verified `authorize_refresh`, `check_session_active`; Tamarin revocation lemmas |
| Endless sessions | Absolute one-year cap from `auth_time` | verified `lifetimes` |
| Sensitive actions with an old session | Step-up: `auth_time` within 5 minutes (RFC 9470) | verified `check_step_up` |
| Concurrent state changes (race to bypass limits or leave zero passkeys) | Conditional DynamoDB transactions with optimistic concurrency on counters and epochs | `store.rs` |
| Malformed input | Strict parsers (base64url canonical, CBOR without tags or indefinite lengths, duplicate keys rejected), 64 KiB body limit, Kani and fuzzing | `auth-core`, `http.rs` |
| Database leak | Contains random IDs, public keys, hashes and timestamps only | §12 |
| PII in logs | Requests are logged by route template only; no IP addresses, user agents, tokens or headers. WAF logging is disabled; API access logs exclude identity fields | `lib.rs`, `infra/` |
| Bulk account creation | WAF rate limits (stricter on sign-up and recovery). See residual risks | `infra/` |
| XSS in the web app | Can use the non-extractable key while the page is open but cannot export it, so stolen material is useless once the page closes. XSS is still a full compromise of the app session and must be prevented by the app | SDK README |

## Residual risks (accepted, documented)

1. **No identity-based sybil resistance.** Without email or phone checks, anyone
   can create accounts. Rate limits slow this down; apps that need stronger
   guarantees can add proof-of-work or platform attestation at sign-up.
2. **Losing every passkey and the recovery code loses the account.** There is no
   support override, because one would be the weakest link.
3. **At resource servers, access tokens remain valid for up to 5 minutes after
   revocation.** The auth service's account API checks the session on every
   request, so revocation is immediate there; other resource servers can do the
   same with the token's `cid` and `epoch` (`auth_verifier::Identity::session`).
4. **XSS on the app origin** can act as the user while the page is open.
5. **Pseudonymous, not unlinkable.** The account ID is stable, so the app can
   link a user's actions to each other. That is inherent to accounts.
6. **The AWS account and its operators** are trusted.
