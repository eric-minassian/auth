# Formal model of the protocol (Tamarin)

`model/auth.spthy` is a [Tamarin](https://tamarin-prover.com) model of the
protocol in [`docs/protocol.md`](../docs/protocol.md): passkey sign-up and
sign-in with single-use challenges bound to the client's DPoP key,
DPoP-bound access and refresh tokens carrying `sid`, `cid`, `rid` and
`epoch`, stateless refresh guarded by `cnf.jkt`, `cid`+`rid` and `epoch`,
sign-out everywhere, passkey removal, recovery codes, the account API (which
re-checks that the session is active), and resource access. Every lemma is
machine-checked; nothing is admitted (`sorry`) and no external oracle is
used.

## Running it

```sh
scripts/prove-model.sh                  # both configurations; fails unless every lemma is verified
scripts/prove-model.sh --default-only
scripts/prove-model.sh --attacks-only
```

or directly:

```sh
tamarin-prover --prove --derivcheck-timeout=120 model/auth.spthy              # 44 lemmas
tamarin-prover --prove --derivcheck-timeout=120 -D=ATTACKS model/auth.spthy   # 6 lemmas
```

Requirements: `tamarin-prover` ≥ 1.10 (tested with 1.12.0) and Maude 3.x
(tested with 3.5.1). If `maude` is a symlink, set `MAUDE_LIB` to the
directory containing `prelude.maude` (the script does this automatically).

* Tamarin's derivation check needs more than its 5 s default on this model;
  the script passes `--derivcheck-timeout=120`.
* Tamarin 1.12.0 occasionally aborts right after loading the theory with the
  GHC runtime error `<<loop>>`, before analysing any lemma (seen a handful
  of times in ~100 runs). That is a crash, not a result; the script retries
  such a run up to twice. A real failure
  (`falsified`, `analysis incomplete`, a wellformedness warning, a missing
  summary) always fails the script.
* Run one Tamarin process at a time: each uses every core. Peak memory is
  about 12 GB (default configuration) and 9 GB (`ATTACKS`): Tamarin keeps
  every proof tree until it prints the results.

Observed runtime (10 cores, 26 GB RAM, Tamarin 1.12.0 / Maude 3.5.1): see
[Last observed run](#last-observed-run).

## What changed in this version

The previous version of this model found five weaknesses (its witnesses
A3–A6 and the server-key witness A2). `docs/protocol.md` was fixed; the
model now follows the fixed protocol:

1. **Ceremonies are bound to the device key** (§8, §10.3–§10.7). Every
   `*/options` request carries a DPoP proof; the challenge item stores the
   proof key's thumbprint (`Chal_*(c, kind, …, jkt)`) and the matching
   `*/verify` must be proven by the same key. For the account API's
   add-passkey ceremony the challenge is bound to the caller's DPoP key.
   To exercise this, the threat model now gives the adversary **every
   WebAuthn response** honest clients produce (registration responses and
   assertions are `Out`): previously this was a separate "leaked assertion"
   capability that broke sign-in (old witness A3); now it is proved harmless.
2. **The account API re-checks revocation** (§6.1, §10.7). Access tokens
   carry `sid`, `cid`, `rid`, `epoch`; every account-API rule reads the
   account record and the session's credential record, and accepts only if
   the passkey `cid` is still registered with registration ID `rid` (record
   not removed, current generation) and the epoch equals the token's `epoch`.
   (Old witness A4, "access token outlives sign-out", is now a proved
   property.)
3. **Registration IDs** (§6.2 rule 5, §8). Every registration (sign-up, add
   passkey, recovery) creates a fresh registration ID, which is the handle
   `~rec` of the `!Cred` record; it is carried as `rid` in refresh and access
   tokens, and refresh and the account API look up exactly that record.
   (Old witness A5, "re-registered credential ID revives sessions", is now a
   proved property, and a new executability lemma shows that re-registering
   a removed credential ID is reachable, so the property is not vacuous.)
4. **RP ID scope** (§8, deployment requirement). In the honest configuration
   attacker pages live only *outside* the RP ID scope (their registrable
   domain is `<'evil', y>`, never `'rp'`), and phishing resistance is still
   proved against them. Hostile pages *inside* the scope exist only in the
   `ATTACKS` configuration, where witness A3 shows the account-swap attack
   that justifies the requirement, and phishing resistance of sign-in is
   proved again with those pages present.
5. **Server signing keys** stay trusted (KMS). The witnesses A1/A2 for their
   compromise remain in `ATTACKS`; forging a usable refresh token now also
   needs the session's `rid` (16 random bytes in the deployed system), which
   A2 takes from a leaked token.

The security lemmas are strengthened accordingly (section "Lemmas"):
revocation lemmas cover refresh **and** the account API with no exclusions;
passkey removal is proved for the registration, including re-registration
of the same credential ID; sign-in agreement also binds the device key; and
`AccountCompromised` is tightened so that a device compromise counts only
while that device can still act for the account.

## What is modelled

| Party | Model |
|---|---|
| Auth service | One instance (`AS_Setup`) with separate access- and refresh-token signing keys (KMS). Every endpoint of §10 is a rule: register/login/recover options and verify, token (refresh), and the account API (logout-all, add passkey options/verify, delete passkey, rotate recovery code, delete account). Every endpoint checks a DPoP proof and its `jti` (single use per key). |
| Account state | One linear fact per account `Acct(~a, status, gen, epoch, recovery-hash)` (pending → active → deleted), so every state change is atomic. Passkeys are records `!Cred(rid, a, cid, gen, pk)`; `rid` is the fresh registration ID; deletion is enforced by a restriction ("a deleted record is never read again"); recovery replaces every passkey by moving to a new credential generation. |
| Challenges | Linear facts per kind (`Chal_register`, `Chal_login`, `Chal_recover`, `Chal_add_passkey`) holding the thumbprint of the key that requested them, consumed by the verify step: single use, kind-checked, key-bound. |
| Platform authenticator | Generates credentials (`Authenticator_NewCredential`) scoped to an RP ID; signs `rpIdHash ‖ SHA-256(clientDataJSON)`; returns the (unsigned) user handle. Credential IDs and public keys are public. |
| Browser | Writes the real origin into clientDataJSON and only lets an origin use its own registrable domain as RP ID. |
| Client device | One non-extractable DPoP key per device (`Device_Init`); performs the ceremonies, stores tokens and recovery codes, refreshes, calls resource servers and the account API. Its WebAuthn responses are published to the adversary. |
| Resource server | Verifies the access token (published key, `typ`, `aud = rs`) and a DPoP proof for its URI whose key matches `cnf.jkt` and whose `ath` is the hash of that token. It does not check revocation (that is optional in §6.1). |

Messages follow the spec closely: JWTs are JWS (`revealSign`: claims
readable, signature unforgeable) with distinct `typ` values and keys; DPoP
proofs carry `typ`, `jwk`, `htu` (method + URI, including the credential ID
in `DELETE /v1/account/passkeys/{cid}`), `ath` and `jti`; refresh checks
rules 1, 4, 5 and 6 of §6.2 (rule 2's `iss`/`aud` check is subsumed by the
dedicated refresh key and `typ`, `client_id` is not modelled, rule 3 is
timing); login checks challenge (kind, bound key), type, origin, RP ID hash,
user handle, the signature and that the credential record is current;
registration (attestation `none`) checks challenge (kind, bound key), type,
origin and RP ID hash; add-passkey checks that the challenge belongs to the
token's account and to the caller's key; recovery verify checks that the code
bound to the challenge is still the current one.

Channels: honest clients reach the auth service and resource servers over
TLS. A request from an honest client is a private linear fact keyed by a
fresh connection id, so the adversary can delay or drop it but not read,
modify or replay it (the WebAuthn response inside it is nevertheless given
to the adversary, see above); the response returns on the same connection.
The adversary can open its own connections with arbitrary content. Each
server endpoint therefore appears twice, `*_H` (honest connection) and
`*_A` (adversary connection), with identical checks and state updates.

## Threat model

The adversary controls the network (Dolev–Yao) and can:

* sign up its own accounts, use its own devices and keys, call every
  endpoint with any message it can build;
* see **every WebAuthn response** an honest client produces (registration
  responses and assertions, e.g. logged by a TLS-terminating proxy or WAF,
  or read by a browser extension), including the challenge inside;
* run phishing pages at any origin **outside the RP ID scope**, and make the
  user's authenticator create credentials and produce assertions over any
  challenge there (the user approves every prompt);
* receive DPoP proofs that honest clients send to adversary-run resource
  servers (for those servers' URIs);
* **leak** any access or refresh token issued to an honest client
  (`LeakAT`, `LeakRT`), **compromise** any device's DPoP key
  (`CompromiseDevice`), any passkey private key (`CompromisePasskey`), and
  any recovery code (`LeakRecovery`), at any time. Each is an action fact,
  so lemmas state exactly which compromises they tolerate.

### Honest-configuration assumptions

These are trusted in the default configuration; each is a documented
deployment requirement, and the `ATTACKS` configuration shows what breaks
without it:

| Assumption | Where required | Without it |
|---|---|---|
| **RP ID scope**: every host under `AUTH_RP_ID` is operator-controlled (no hostile page can use RP ID `'rp'`). | §8 "RP ID scope" | Witness A3: account swap via a planted credential. Sign-in itself stays phishing resistant (proved in `ATTACKS`). |
| **Signing keys** for access and refresh tokens stay in KMS. | §5 | Witnesses A1 (forged access token accepted by the resource server) and A2 (forged refresh token: full session takeover; needs the session's `cid` and `rid`, e.g. from any leaked token; with the deployed counter epoch it also survives sign-out everywhere). |
| The auth service, the honest resource server, the browser and platform authenticator (origin and RP ID enforcement), TLS / Web PKI, and the honest origin itself (script injection into it is equivalent to the device/passkey compromises above). | — | Out of scope. |

### What "account *A* is compromised" means

`AccountCompromised(A)` is the exclusion used by the authentication lemmas.
It holds when the adversary obtained, at some time *c*:

* the DPoP key of an honest device **while that device could still act for
  A**: the device holds a session of *A* that is still active at *c* (its
  epoch has not been replaced by sign-out everywhere, recovery or deletion,
  and its passkey registration `rid` has not been removed), or the device has
  a passkey ceremony for *A* whose challenge has not been redeemed by *c*.
  Compromising a device after all its sessions of *A* were revoked and all
  its ceremonies for *A* were redeemed is harmless and does not count;
* the private key of a passkey registered on *A*; or
* a recovery code of *A*.

An *honest account* is one whose ID the auth service created for an honest
client's sign-up (`HonestAccount`).

## Abstractions (and why they are sound for the properties proved)

* **Time is not modelled.** Access/refresh TTLs, the absolute session
  lifetime, `CEREMONY_TTL`, DPoP `iat` skew, nonce windows and step-up
  `max_age` are all checks that only *reject* requests; dropping them gives
  the adversary strictly more behaviours, so every safety lemma proved here
  also holds with them. They are covered by the Rust proofs. In this model
  tokens never expire and step-up always passes, so the revocation lemmas are
  stated for the operations that check revocation (refresh and the account
  API), and witness A4 is bounded by the step-up window in reality.
* **DPoP nonces** are omitted for the same reason; `jti` single use at the
  auth service is modelled; the optional resource-server replay cache is not
  assumed.
* **Epoch and credential generation** are fresh values instead of counters:
  they are only ever compared for equality, and an increment yields a value
  that never occurred before, which is exactly what a fresh value provides.
* **Registration ID** = the fresh handle of the credential record; the
  protocol's 16 random bytes are modelled as a fresh value, so two
  registrations never share one.
* **Account IDs, credential IDs and public keys are public**: the model
  publishes account IDs at creation, which only strengthens the adversary.
* **Typed values.** Account IDs, session IDs, token IDs, challenges,
  recovery codes and platform credential IDs carry public constructors
  (`uid`, `sid`, `tid`, `chal`, `rcode`, `credid`; `cred`, `regid`, `epoch`
  wrap token claims). The adversary can apply them too, so this restricts
  nothing it can send; it only stops Tamarin from considering, for example,
  an account ID that happens to equal a signing key. Rules match the shape
  that the honest party always produces: honest-connection rules match the
  fresh credential IDs and DPoP keys honest clients send, and token rules
  match `sid(~sid)` because every token is signed by the (trusted) auth
  service, which only ever issues fresh session IDs. No honest behaviour is
  lost.
* **Signature verification by pattern matching** (`revealSign(m, k)` with
  `pk(k)`), the standard Tamarin encoding of `verify(...) = true`. Rules that
  do this are marked `[no_derivcheck]`.
* **Not modelled because it cannot weaken the properties:** `client_id`,
  `resource` allow-listing (audiences are public names; each verifier checks
  its own audience), global uniqueness of credential IDs, the 20-passkey
  limit, the last-passkey rule, signature counters (clone detection
  heuristic), key rotation ("previous" keys), request-size limits and CORS.
  Each only rejects more requests.
* **Not modelled at all:** the account `GET`, CLI/native client variants
  (RFC 8252 / 8628), timing side channels, availability/DoS, and the Rust
  implementation itself (the model checks the protocol design; the Rust
  proofs check the code).

## Lemmas

### Default configuration (`tamarin-prover --prove model/auth.spthy`)

#### Helper lemmas (used by the main proofs)

| Lemma | Statement |
|---|---|
| `passkey_secret` | A passkey private key is known to the adversary only after (and because of) `CompromisePasskey`. |
| `as_keys_secret` | The auth service's signing keys are never known to the adversary. |
| `device_key_secret` | A device's DPoP private key is known only after `CompromiseDevice`. |
| `ceremony_device` | Honest ceremonies use honest device keys. |
| `chal_single_use` | Each challenge is consumed by at most one verify request. |
| `chal_bound` | Every accepted verify request (any ceremony) is proven by the key that requested the challenge. |
| `token_origin` | Every refresh and account-API request presents a token of a session that started earlier with the same account, `sid`, `cid`, `rid`, `epoch` and `cnf.jkt`. |
| `at_origin` | The same for access tokens accepted by the resource server. |
| `session_origin` | A session started on an honest client's connection was started by that client's passkey ceremony with its own DPoP key. |
| `epoch_no_return`, `gen_no_return` | Once the epoch (sign-out everywhere, recovery, deletion) or the credential generation (recovery) moves on, an older value is never current again. |
| `epoch_origin`, `gen_origin` | Every epoch/generation read was created earlier. |
| `epoch_change_origin`, `epoch_changed_gone` | A replaced epoch was created before it was replaced, and is never read again (corollaries used by the central invariant). |
| `adv_step_*` (5) | One per kind of request made on an adversary connection for an honest account: a new account is never an honest one; a refresh/account-API call needs, before the call, the device key of the honest session the token belongs to; a sign-in needs the private key of a passkey registered on the account or the key of the device that requested the challenge; a sign-up/recovery verify needs the key of the device that requested the challenge; recovery options need a recovery code — or, in each case, an earlier adversary request for that account. |
| `adversary_needs_compromise` | Central invariant (by induction): the auth service never processes a request for an honest account on an adversary connection unless the account is compromised (tight definition above). |
| `session_origin_honest` | Every session of an honest account was started by an honest device with its own key, or the account is compromised. |

#### 1. Executability (each flow completes with no compromise and no adversary request)

`exec_sign_up`, `exec_sign_in`, `exec_refresh`, `exec_resource_access`,
`exec_sign_out_everywhere`, `exec_passkey_add`, `exec_passkey_removal`,
`exec_recovery`, `exec_recovery_code_rotation`, `exec_account_deletion`.
Each pins the shortest honest run for that flow (the extra constraints only
exclude longer alternatives), which keeps the trace search fast.

`exec_reregistration`: after the registration of credential ID *C* was
removed, *C* is registered again on the same account with a new
registration ID and a session is started with it. Honest authenticators
never reuse a credential ID, so this trace uses the adversary (a leaked
recovery code). It shows the "including re-registration" part of lemma 6 is
not vacuous.

#### Security properties

| # | Lemma | Plain English |
|---|---|---|
| 2a | `resource_access_authentication` | If the resource server accepts a request for honest account *A* bound to key thumbprint *jkt*, then an honest device whose DPoP key matches *jkt* performed a passkey ceremony (sign-up, sign-in or recovery) for *A* — unless *A* is compromised (a device key while it could still act for *A*, a passkey of *A*, or a recovery code of *A*). |
| 2b | `resource_access_device_binding` | If the resource server accepts a request for account *A* bound to an honest device's key *K*, then device *K* itself performed a passkey ceremony for *A* — unless *K* is compromised. No other exclusion (not even passkey or recovery-code compromise). |
| 3a | `token_theft_needs_device_key` | Every request accepted with a token bound to an honest device's key was sent by that device, unless that key was compromised — even if every access and refresh token (and every DPoP proof sent to other resource servers) leaked. |
| 3b | `token_theft_alone_insufficient` | If the only compromises are token leaks (and WebAuthn responses, which are always public here), every request accepted for an honest account was sent by an honest device. |
| 4 | `ceremony_bound_to_device` | A WebAuthn response produced in an honest client's ceremony (sign-up, sign-in, recovery, add passkey) can only be redeemed with the DPoP key of the device that requested the challenge, even though the adversary sees the response. No exclusions. |
| 5 | `sign_out_everywhere_revokes` | After sign-out everywhere for *A*, no session of *A* that started before it is ever used again: no refresh and no account-API request. No exclusions (device keys — including that session's —, passkeys, tokens and codes may all be compromised, before or after). |
| 6 | `passkey_removal_revokes` | After passkey registration (*C*, *rid*) is removed from *A*, no session started with it is used again (refresh or account API), even if credential ID *C* is registered again later. No exclusions. |
| 7a | `recovery_revokes_sessions` | After a recovery of *A*, no session of *A* that started before it is used again (refresh or account API). No exclusions. |
| 7b | `recovery_revokes_old_passkeys` | After a recovery of *A*, no passkey registered before it is ever accepted again: not for sign-in, not as the passkey of a session (refresh, account API), and not as the target of a removal. No exclusions. |
| 8 | `sign_in_injective_agreement` | Every sign-in accepted with a platform credential and DPoP key *jkt* corresponds to an assertion the authenticator produced at the honest origin for the honest RP ID over that challenge, in a ceremony started by the device with key *jkt*; the challenge was requested by an options request proven with that same key; and no other sign-in accepts the same assertion — unless that passkey was compromised. (The challenge-to-key binding holds with no exclusion at all: `chal_bound`.) |
| 9 | `phishing_resistance` | Every sign-in accepted with a platform credential used an assertion the authenticator produced at the honest origin for the honest RP ID — never one made for a page at another origin — unless the passkey was compromised. In the honest configuration the browser already confines out-of-scope pages to their own RP ID; the stronger result is the `ATTACKS` run below, where hostile pages inside the RP ID scope also exist. |

#### Resource-access authentication: the originally intended statement

The intended statement was: *if the resource server accepts a request for
A bound to K, an honest device holding K performed a ceremony for A, unless
K is compromised, a passkey of A is compromised, or A's recovery code
leaked.*

* **If *K* is an honest device's key**, it holds, with even fewer
  exclusions: `resource_access_device_binding` needs only "K compromised".
  Binding ceremonies to the device key is what makes the sign-in part of
  this hold even though WebAuthn responses leak.
* **If *K* may be any key** (in particular one the adversary generated), it
  does **not** hold, and no protocol that lets an active session add
  passkeys can make it hold. Witness A4 (`limit_other_device_compromise`)
  is a concrete trace: the adversary compromises the DPoP key of *another*
  device that holds an active session of *A* (here the sign-up device),
  uses the account API through that session to register its own passkey
  (step-up passes while that session's ceremony is less than
  `STEP_UP_MAX_AGE` old), signs in with it using its own DPoP key *K*, and
  the resource server accepts a request for *A* bound to *K*. *K* is not a
  compromised device key, no passkey of *A* is compromised and no recovery
  code leaked. (Rotating the recovery code through that session and then
  recovering is another route; it is not separately witnessed.) In the
  deployed system the window is the step-up age (300 s
  after that device's passkey ceremony); within it — e.g. malware present
  when the user signs in — the attack is real.
* **What is proved instead** (`resource_access_authentication`): the
  exclusion "a device key of *A*" is narrowed to the two cases that do let
  the adversary in — a device that, when compromised, still holds an active
  session of *A* (witness A4) or an unredeemed ceremony for *A* (whose
  WebAuthn response the adversary can then redeem with that device's key). Thanks to fix 2 (the account API re-checks
  revocation), a device compromised after its sessions were signed out,
  recovered away, deleted or had their passkey removed gives the adversary
  nothing, and the lemma says so.

### `ATTACKS` configuration (`-D=ATTACKS`)

Adds server signing-key compromise and hostile pages inside the RP ID scope
(`Phish_Create_InScope`, `Phish_Assert_InScope`). The exists-trace lemmas
are witnesses: **verified means Tamarin found the trace.**

| Lemma | Kind | What it shows |
|---|---|---|
| `passkey_secret` | all-traces | As above, with the extra capabilities. |
| `phishing_resistance` | all-traces | Sign-in stays phishing resistant **even with hostile pages inside the RP ID scope**: an assertion they obtain (over any challenge, with any user handle) is never accepted, because the signed clientData carries their origin. |
| `attack_at_key_compromise_breaks_resource_auth` (A1) | witness | With the access-token signing key the adversary forges a token for an honest, uncompromised account bound to its own DPoP key; the resource server accepts. |
| `attack_rt_key_compromise_hijacks_session` (A2) | witness | With the refresh-token signing key (plus `cid`, `rid` and `epoch` from a leaked refresh token) the adversary mints a refresh token bound to its own key and the auth service issues it tokens: full takeover. (Not part of the trace, but follows from the rules: with the deployed counter epoch and the unchanged `rid`, the adversary can also forge a token for the epoch after a sign-out everywhere, so the takeover survives it.) |
| `weakness_hostile_subdomain_account_swap` (A3) | witness | A hostile page inside the RP ID scope plants a credential for the RP ID under the attacker's account in the user's authenticator and registers its public key (attestation `none` signs nothing); the user later signs in to the attacker's account at the honest origin. Justifies the RP ID scope requirement. |
| `limit_other_device_compromise` (A4) | witness | The intended form of lemma 2 fails for adversary-chosen keys (see above). |

## Remaining weaknesses (documented, not fixed by the protocol)

* **RP ID scope** is a deployment requirement (A3). It cannot be enforced by
  the service; `AUTH_RP_ID` should be the app's exact host.
* **Signing-key compromise** (A1, A2) is a full, silent compromise. Key
  rotation alone does not help while previous keys stay accepted; it needs
  an incident procedure (rotate and stop accepting previous keys).
* **Compromise of any device during its step-up window** (A4) lets the
  adversary add a passkey or rotate the recovery code, i.e. take over the
  account; sign-out everywhere does not remove passkeys the adversary added,
  so recovery (which replaces all passkeys) is the right response to a
  suspected compromise.
* **Resource servers that do not check `sid`/`cid`/`rid`/`epoch`** keep
  accepting already-issued access tokens for up to `ACCESS_TOKEN_TTL`
  after revocation (the model's resource server does not check them, so
  lemmas 5–7 are stated for refresh and the account API).
* **A DPoP proof does not cover the request body**; a leaked proof with its
  access token can be replayed to the same method and URI within the `iat`
  window unless the resource server uses a replay cache. TLS prevents the
  leak.

## Findings for `docs/protocol.md` (still open)

1. **§10.7 omits the registration ID.** It says the account API requires
   "the passkey `cid` is still registered" — it must say "registered **with
   registration ID `rid`**" as §6.1 and §6.2 rule 5 do. With only `cid`,
   re-registering a removed credential ID would revive account-API access
   for the removed passkey's sessions. The model checks `rid`.
2. **Verify-side challenge checks are only implied by the storage table
   (§12).** Make normative: every `*/verify` MUST check the challenge `kind`;
   add-passkey verify MUST check `CHAL.account_id == sub`; recover/verify
   MUST check, in the same transaction, that `CHAL.recovery_key` still
   equals `META.recovery_key` (the code was not rotated or used since
   recover/options). The model relies on all three.
3. **The step-up window is the residual account-takeover window** after a
   device compromise (A4). Consider requiring, for add-passkey and
   recovery-code rotation, a fresh passkey assertion over a challenge that
   commits to the operation, and showing the account's passkeys and recent
   additions to the user.

## Proof engineering notes

* Goal ranking uses small in-file **tactics** (`tactic:` blocks with regex
  priorities on top of the default "smart" ranking) selected per lemma with
  `heuristic={...}`, and `hide_lemma=...` so each proof only sees the helper
  lemmas it needs. They only change the order in which goals are solved,
  never what is proved. No oracle script is used.
* Server state and persistent facts are annotated `[no_precomp]`; without
  it the source precomputation does not finish. Rules that verify a
  signature by pattern matching, and the four client ceremony rules that
  match the typed shapes honest parties produce, are `[no_derivcheck]`. Values that rules output
  must stay typed (e.g. `sid(~sid)`, `credid(~cid)`, `pk(~dk)`): an untyped
  variable taken from a `[no_precomp]` fact or an adversary message in an
  output makes Tamarin consider that any secret could be extracted from it,
  and even `passkey_secret` stops terminating.
* The central invariant is split into five non-inductive step lemmas and a
  short induction; its token-use case uses the corollary
  `epoch_changed_gone`, which keeps it at a few hundred steps.
* Proof size matters for memory, not just time: the account-state
  invariants case-split on every rule that reads the account record, so
  their tactic (`state_chain`) solves the reading rule and its account
  premise first and client-side state last (this cut `epoch_no_return` from
  10 293 to 2 751 steps and the peak memory of the whole run from 18 GB to
  12 GB).
* The executability lemmas and the `ATTACKS` witnesses add scenario
  constraints (e.g. "at most two session uses", "no recovery in this
  trace") so that the depth-first trace search does not wander through the
  account-record chain; the attack conditions themselves are stated
  explicitly in each lemma.

## Last observed run

`scripts/prove-model.sh` (logs in `target/tamarin/`):

```
default:  processing time: 186.93s   44/44 lemmas verified   (wall 189 s)
ATTACKS:  processing time: 224.55s    6/6 lemmas verified    (wall 225 s)
OK: all lemmas verified              (script wall time 415 s, peak RSS 11.9 GB)
```

Largest proofs: `epoch_no_return` 2 751 steps, `recovery_revokes_old_passkeys`
1 316, `gen_no_return` 1 079, `epoch_origin` 704; every other lemma is under
450 steps. No `sorry`, no oracle, no wellformedness warning (derivation
check completed within its 120 s budget).
