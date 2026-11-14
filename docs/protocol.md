# Protocol specification

This document is the normative contract between the auth service, its clients
(web SDK, future iOS/Android/CLI clients) and resource servers (via the
`auth-verifier` crate). The key words MUST, MUST NOT, SHOULD and MAY are used as
in RFC 2119.

## 1. Goals and non-goals

- **Authentication only.** The service proves *which account* is making a
  request. Authorization is the job of each resource server, keyed on `sub`.
- **No PII.** The service never asks for, receives, stores or logs email,
  phone, name, IP address or user agent. Accounts are random identifiers.
- **Phishing-resistant sign-in.** Passkeys (WebAuthn Level 3) with user
  verification are the only sign-in method. There are no passwords, no OTPs and
  no fallback channels.
- **Automatic sessions.** After a passkey ceremony, the session is renewed
  silently with a device-bound key (DPoP, RFC 9449). Users only see a passkey
  prompt on a new device, after 30 days of inactivity, after one year, or for
  step-up.
- **Standards first.** Every message is an existing standard or a narrow
  profile of one. Where we deviate, this document says so explicitly.

## 2. Conventions

- All binary values in JSON are **base64url without padding** (RFC 4648 §5).
  Decoders MUST reject padding, characters outside the alphabet and
  non-canonical encodings (non-zero trailing bits).
- All times are **NumericDate** (RFC 7519): integer seconds since the Unix epoch.
- JSON request bodies MUST be `application/json` (UTF-8), except the token
  endpoint, which is `application/x-www-form-urlencoded` (RFC 6749 §3.2).
- Request bodies larger than 64 KiB are rejected with `413`.
- `/v1/token` parameters must not be repeated (RFC 6749 §3.2).
- Unknown JSON fields in requests are ignored (forward compatibility).

## 3. Identifiers

| Name | Format |
|---|---|
| Account ID | 16 bytes from a CSPRNG. Its base64url form (22 chars) is the token `sub`. The raw 16 bytes are the WebAuthn `user.id` / `userHandle`. |
| Credential ID | Bytes chosen by the authenticator, 1–1023 bytes. |
| Client ID | A short string from the configured allowlist (`AUTH_CLIENT_IDS`), e.g. `web`, `ios`, `android`, `cli`. Public clients only (RFC 6749 §2.1). |
| Key thumbprint (`jkt`) | RFC 7638 SHA-256 JWK thumbprint, base64url. |

## 4. Fixed parameters

These are constants in `auth-core` and are part of what is formally verified.

| Constant | Value |
|---|---|
| `ACCESS_TOKEN_TTL` | 300 s |
| `REFRESH_IDLE_TTL` | 2 592 000 s (30 days) |
| `REFRESH_ABSOLUTE_TTL` | 31 536 000 s (365 days), measured from `auth_time` |
| `CEREMONY_TTL` | 300 s (WebAuthn challenge lifetime) |
| `DPOP_NONCE_WINDOW` | 300 s; the current and the previous window are accepted |
| `DPOP_MAX_IAT_SKEW_AUTH_SERVER` | 120 s (either direction) |
| `DPOP_MAX_IAT_SKEW_RESOURCE_DEFAULT` | 60 s (either direction, configurable in the verifier) |
| `STEP_UP_MAX_AGE` | 300 s |
| `MAX_PASSKEYS_PER_ACCOUNT` | 20 |
| `CHALLENGE_LEN` | 32 bytes |
| `RECOVERY_CODE_LEN` | 20 bytes (160 bits) |

## 5. Cryptography

| Purpose | Algorithm | Key location |
|---|---|---|
| Access token signature | JWS `ES256` | KMS `ECC_NIST_P256`, `SIGN_VERIFY` (published in JWKS) |
| Refresh token signature | JWS `ES256` | A **separate** KMS `ECC_NIST_P256` key (never published) |
| DPoP nonce MAC | HMAC-SHA-256 | KMS `HMAC_256`, `GENERATE_VERIFY_MAC` |
| DPoP proofs | JWS `ES256` only | Client device key (non-extractable) |
| Passkey signatures | COSE `-7` (ES256), `-8` (EdDSA / Ed25519), `-257` (RS256, modulus ≥ 2048 bits, `e = 65537`) | Authenticator |
| Hashes | SHA-256 | — |

KMS signs a locally computed SHA-256 digest (`MessageType=DIGEST`). KMS returns
a DER `ECDSA-Sig-Value`, which is converted to the fixed 64-byte `r || s` form
required by JWS (RFC 7518 §3.4). The verifying side only accepts the fixed form.

Explicit typing (RFC 8725 §3.11) separates every JWT kind:

| JWT | `typ` header |
|---|---|
| Access token | `at+jwt` (RFC 9068) |
| Refresh token | `rt+jwt` (internal to the auth service) |
| DPoP proof | `dpop+jwt` (RFC 9449) |

Verifiers MUST reject a JWT whose `typ` or `alg` differs from the one expected
in that position. `alg: none` and every algorithm other than `ES256` are
rejected. `jku`, `x5u`, `x5c` and `crit` headers are rejected.

## 6. Tokens

### 6.1 Access token (RFC 9068 profile)

Header: `{"alg":"ES256","typ":"at+jwt","kid":"<jkt of the signing key>"}`

| Claim | Value |
|---|---|
| `iss` | `AUTH_ISSUER` |
| `sub` | Account ID |
| `aud` | A single string: the requested resource (RFC 8707). Defaults to the first entry of `AUTH_AUDIENCES`. `AUTH_ISSUER` itself is always an allowed audience (the account API). |
| `client_id` | Client ID |
| `iat` | Issue time |
| `exp` | `iat + ACCESS_TOKEN_TTL` |
| `jti` | 16 random bytes, base64url |
| `auth_time` | Time of the passkey ceremony that started this session |
| `amr` | `["pop","mfa"]` (RFC 8176): proof of possession of a key, with user verification |
| `cnf` | `{"jkt":"<device key thumbprint>"}` (RFC 9449 §6.1) |
| `sid` | Session ID (as in the refresh token) |
| `cid` | base64url credential ID of the passkey that started the session |
| `rid` | base64url registration ID of that passkey (§8) |
| `epoch` | The account's session epoch when the session started |

`sid`, `cid`, `rid` and `epoch` let a resource server check that the session is
still active (the passkey `cid` is registered with registration ID `rid` and the
account epoch equals `epoch`) when it needs revocation to take effect
immediately. The auth service's own account API always does (§10.7).

### 6.2 Refresh token

Stateless, DPoP-bound (RFC 9449 §5), sliding. Only the auth service accepts it.

Header: `{"alg":"ES256","typ":"rt+jwt","kid":"<jkt of the refresh signing key>"}`

| Claim | Value |
|---|---|
| `iss` | `AUTH_ISSUER` |
| `aud` | `AUTH_ISSUER` |
| `sub` | Account ID |
| `client_id` | Client ID |
| `iat` | Issue time |
| `exp` | `min(iat + REFRESH_IDLE_TTL, auth_time + REFRESH_ABSOLUTE_TTL)` |
| `jti` | 16 random bytes |
| `sid` | Session ID: 16 random bytes, constant for the life of the session |
| `auth_time` | Time of the passkey ceremony that started the session |
| `cid` | base64url credential ID of the passkey that started the session |
| `rid` | base64url registration ID of that passkey (§8) |
| `epoch` | The account's session epoch when the session started |
| `cnf` | `{"jkt":"<device key thumbprint>"}` |

A refresh is accepted **only if all** of these hold:

1. The JWS verifies with a current or previous refresh signing key, `typ` is
   `rt+jwt`, `alg` is `ES256`.
2. `iss` and `aud` equal `AUTH_ISSUER`; `client_id` equals the request's
   `client_id`.
3. `now < exp` and `iat <= now + DPOP_MAX_IAT_SKEW_AUTH_SERVER`.
4. A valid DPoP proof (§7) was presented whose key thumbprint equals `cnf.jkt`.
5. The passkey `cid` is still registered on the account **with registration ID
   `rid`** (strongly consistent read). Registering the same credential ID again
   creates a new registration ID, so it never revives sessions of a removed
   passkey.
6. `epoch` equals the account's current epoch (strongly consistent read).

On success the service issues a new access token and a new refresh token with
the same `sid`, `auth_time`, `cid`, `rid`, `epoch` and `cnf`, and with
`exp = min(now + REFRESH_IDLE_TTL, auth_time + REFRESH_ABSOLUTE_TTL)`. Old
refresh tokens are not tracked; they remain usable until their own `exp`, but
only by the holder of the device key.

### 6.3 Revocation

| Action | Effect |
|---|---|
| Sign out (one device) | The client destroys its device key and tokens. Without the key, no DPoP proof can be produced, so the session is cryptographically dead. |
| Sign out everywhere | The account's `epoch` is incremented. Every refresh token with an older epoch fails rule 6, and the account API rejects older sessions' access tokens at once. Elsewhere, access tokens already issued expire within `ACCESS_TOKEN_TTL` unless the resource server checks `cid`/`epoch`. |
| Passkey removed | Sessions started with that passkey fail rule 5 (and the account API check), even if the same credential ID is registered again later. |
| Account recovered | `epoch` incremented and all passkeys replaced. |
| Account deleted | All rules fail. |

## 7. DPoP

Clients MUST hold a P-256 key pair whose private key cannot be exported
(WebCrypto `extractable: false`, Secure Enclave, Android Keystore, OS keychain).

### 7.1 Proof format (RFC 9449 §4.2)

Header: `{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"…","y":"…"}}`.
The `jwk` MUST NOT contain private members (`d`) and MUST contain only `kty`,
`crv`, `x`, `y` (and optionally `use`, `key_ops`, `alg`, `kid`, which are
ignored). `x` and `y` MUST each decode to exactly 32 bytes.

| Claim | Requirement |
|---|---|
| `jti` | 16–128 characters |
| `htm` | The request method, exactly (`GET`, `POST`, `DELETE`) |
| `htu` | The request URI without query or fragment, in canonical form: lowercase scheme and host, no default port, path as sent. The comparison is **exact string equality** with the URI the server expects. |
| `iat` | Within the allowed skew of server time |
| `nonce` | REQUIRED at every auth-service endpoint that takes a proof |
| `ath` | REQUIRED when an access token is presented: base64url(SHA-256(ASCII(access_token))) |

### 7.2 Nonces (RFC 9449 §8, §9)

The auth service returns a `DPoP-Nonce` response header on **every** response.
The nonce is

```
window = floor(now / DPOP_NONCE_WINDOW)          (u64, big-endian, 8 bytes)
mac    = HMAC-SHA-256(K_nonce, "auth-dpop-nonce-v1" || window)
nonce  = base64url(window || mac)                (40 bytes → 54 chars)
```

A nonce is valid when it equals the nonce of the current or the previous
window (the MAC is deterministic, so the service computes both and checks
membership). Rotating `K_nonce` invalidates outstanding nonces; clients recover
with one `use_dpop_nonce` retry, so no previous-key list is needed. On a missing or stale nonce the
service responds:

- token-style endpoints (`/v1/token`, `/v1/*/options`, `/v1/*/verify`): `400`
  `{"error":"use_dpop_nonce"}` with a fresh `DPoP-Nonce` header;
- resource-style endpoints (`/v1/account*`): `401` with
  `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a fresh `DPoP-Nonce`.

The client retries once with the new nonce.

### 7.3 Replay protection

At the auth service every proof `jti` is single-use: the service records
`SHA-256(jkt || 0x00 || jti)` with a 10-minute expiry using a conditional write
and rejects a second use. Resource servers MAY plug in a replay cache via the
`auth-verifier` `ReplayCache` trait.

### 7.4 Clock skew

Clients SHOULD estimate the offset between their clock and the server's from
the `Date` response header and use corrected time for `iat`.

## 8. WebAuthn profile

- **RP ID** is `AUTH_RP_ID` (a registrable domain such as `example.com`).
- **Allowed origins** are `AUTH_ALLOWED_ORIGINS`, matched exactly. Web origins
  are `https://…`; Android apps use `android:apk-key-hash:<base64url SHA-256 of the signing cert>`.
- `crossOrigin` MUST be absent or `false`; `topOrigin` MUST be absent.
- **User verification is required.** Flags `UP` and `UV` MUST be set.
- `BS` set without `BE` is rejected.
- **Registration**: flag `AT` MUST be set. Attestation conveyance is `"none"`.
  Accepted formats are `none` (with an empty `attStmt`) and `packed`
  self-attestation (no `x5c`; the signature is verified with the new credential
  key and its `alg` must equal the credential's). Every other format is rejected.
- **Authentication**: flag `AT` MUST NOT be set. `userHandle` MUST be present
  and equal the account ID of the stored credential.
- If flag `ED` is set, the extensions CBOR map is parsed and MUST consume the
  rest of the authenticator data exactly. Trailing bytes are rejected.
- **Signature counter**: if the stored counter and the received counter are
  both 0, accept. Otherwise the received counter MUST be strictly greater than
  the stored one; otherwise the assertion is rejected as a possible clone.
- Credential IDs MUST be 1–1023 bytes; `rawId` MUST equal the credential ID in
  the authenticator data, and `id` MUST equal `base64url(rawId)`.
- A credential ID can be registered to at most one account.
- Challenges are 32 random bytes, single-use (consumed with a conditional
  delete before verification), and expire after `CEREMONY_TTL`.
- **Ceremonies are bound to the device key.** Every options request carries a
  DPoP proof (§7); the service stores the proof key's thumbprint with the
  challenge, and the matching verify request MUST carry a proof by the same
  key. A WebAuthn response captured in transit therefore cannot be redeemed by
  anyone else, and the session it starts is bound to the key that asked for it.
  For the account API, the binding is to the caller's DPoP key.
- **Registration IDs.** Every successful registration (sign-up, adding a
  passkey, recovery) is assigned a fresh 16-byte registration ID, stored with
  the credential and carried in every token of sessions it starts (`rid`).

### RP ID scope (deployment requirement)

A registration with attestation `"none"` is not signed, so its
`clientDataJSON` (and therefore its origin) is not authenticated. Browsers let
any page whose host is the RP ID or a subdomain of it create passkeys for that
RP ID. A hostile page under the RP ID could therefore have the user create a
passkey and register it to an account of the attacker's choosing; if the user
later signs in with it, they are signed in to the attacker's account. Sign-in
itself is not affected (assertions sign the origin, which is checked exactly).

Therefore **`AUTH_RP_ID` MUST be the narrowest domain that covers the allowed
web origins, and every host under it MUST be under the operator's control**
(never user-generated content, never a third party). Using the app's exact host
(for example `app.example.com`) is recommended.

### 8.1 Creation options returned by the service

```json
{
  "rp": { "id": "<AUTH_RP_ID>", "name": "<AUTH_RP_NAME>" },
  "user": { "id": "<b64url account id>", "name": "<AUTH_RP_NAME> · <4 chars>", "displayName": "<same>" },
  "challenge": "<b64url 32 bytes>",
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -8 },
    { "type": "public-key", "alg": -257 }
  ],
  "timeout": 300000,
  "excludeCredentials": [ { "type": "public-key", "id": "<b64url>" } ],
  "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
  "attestation": "none",
  "extensions": { "credProps": true }
}
```

The `user.name` suffix is the first 4 characters of the account ID's Crockford
base32 form. It only helps users tell accounts apart in the passkey picker.

### 8.2 Request options returned by the service

```json
{
  "challenge": "<b64url 32 bytes>",
  "rpId": "<AUTH_RP_ID>",
  "timeout": 300000,
  "allowCredentials": [],
  "userVerification": "required"
}
```

The options objects are the WebAuthn Level 3 JSON forms
(`PublicKeyCredentialCreationOptionsJSON`, `PublicKeyCredentialRequestOptionsJSON`),
and responses are `RegistrationResponseJSON` / `AuthenticationResponseJSON`
(the output of `PublicKeyCredential.prototype.toJSON()`).

## 9. Recovery codes

- 20 random bytes, shown once as Crockford base32 in groups of four
  (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`).
- Input normalization: ignore `-` and spaces, uppercase, map `I`/`L` → `1`
  and `O` → `0`. Any other character outside the Crockford alphabet is rejected.
- Stored only as `SHA-256("auth-recovery-v1" || code_bytes)`.
- Single-use: using it replaces every passkey, increments the epoch and issues a
  new code in the same atomic transaction.

## 10. HTTP API

All responses generated by the service carry `Cache-Control: no-store` unless
stated otherwise, plus a `DPoP-Nonce` header. Requests blocked in front of the
service (WAF rules, API Gateway throttling) get the gateway's own response
without those headers: `403 {"error":"access_denied"}`,
`413 {"error":"payload_too_large"}` or `429`. Errors use the OAuth error object
`{"error":"<code>","error_description":"<human text>"}`.

### 10.0 Rules for every ceremony

Every `*/verify` endpoint (sign-up, sign-in, recovery, adding a passkey) MUST,
in this order:

1. check the request's DPoP proof (nonce required, `jti` single-use);
2. consume the challenge named in `clientDataJSON` with a conditional delete
   (an unknown or already used challenge is `invalid_grant`);
3. check that the challenge's `kind` matches the endpoint, that it is bound to
   the proof's key thumbprint, and that it has not expired;
4. for adding a passkey, check that the challenge's `account_id` equals the
   caller's `sub`; for recovery, apply the change in one transaction that is
   conditional on the account's recovery-code hash still being the one the
   challenge was issued for (a code replaced in between makes recovery fail);
5. only then verify the WebAuthn response.

### 10.1 Discovery

**`GET /.well-known/oauth-authorization-server`** — RFC 8414 metadata.
`Cache-Control: public, max-age=300`.

```json
{
  "issuer": "<AUTH_ISSUER>",
  "token_endpoint": "<AUTH_ISSUER>/v1/token",
  "jwks_uri": "<AUTH_ISSUER>/.well-known/jwks.json",
  "grant_types_supported": ["refresh_token"],
  "response_types_supported": [],
  "token_endpoint_auth_methods_supported": ["none"],
  "dpop_signing_alg_values_supported": ["ES256"],
  "authorization_response_iss_parameter_supported": false
}
```

The service does not issue ID tokens and is not an OpenID Provider, so it does
not publish `/.well-known/openid-configuration`.

**`GET /.well-known/jwks.json`** — RFC 7517 JWK Set with the active and
previous access-token public keys:
`{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"<jkt>","alg":"ES256","use":"sig"}]}`.
`Cache-Control: public, max-age=300`.

### 10.2 Token response

Returned by every endpoint that starts or renews a session (RFC 6749 §5.1):

```json
{
  "access_token": "<jwt>",
  "token_type": "DPoP",
  "expires_in": 300,
  "refresh_token": "<jwt>",
  "refresh_token_expires_in": 2592000
}
```

### 10.3 Sign-up

**`POST /v1/register/options`** — header `DPoP`; body `{}`. Creates a challenge
bound to a new random account ID and to the proof key. Response
`200 {"publicKey": <creation options>}`.

**`POST /v1/register/verify`** — header `DPoP: <proof>`; body
`{"client_id":"web","resource":"<optional aud>","credential":<RegistrationResponseJSON>}`.
Creates the account, the passkey and a recovery code atomically. Response
`201`: token response plus `"account_id"` and `"recovery_code"`.

### 10.4 Sign-in

**`POST /v1/login/options`** — header `DPoP`; body `{}`. Creates a challenge bound
to the proof key. Response `200 {"publicKey": <request options>}`.

**`POST /v1/login/verify`** — header `DPoP`; body
`{"client_id":"web","resource":"<optional>","credential":<AuthenticationResponseJSON>}`.
Response `200` token response. If the credential is not registered:
`401 {"error":"unknown_credential","credential_id":"<b64url>"}` so the client can
call `PublicKeyCredential.signalUnknownCredential()`.

### 10.5 Refresh (RFC 6749 §6, RFC 9449 §5)

**`POST /v1/token`** — header `DPoP`; form body
`grant_type=refresh_token&refresh_token=<jwt>&client_id=web[&resource=<aud>]`.
Response `200` token response. Failures: `400 {"error":"invalid_grant"}`,
`400 {"error":"invalid_dpop_proof"}`, `400 {"error":"use_dpop_nonce"}`,
`400 {"error":"invalid_target"}` (resource not allowed, RFC 8707).

### 10.6 Recovery

**`POST /v1/recover/options`** — header `DPoP`; body `{"recovery_code":"XXXX-…"}`. Response
`200 {"publicKey": <creation options for the recovered account>}`. An unknown
code returns `400 {"error":"invalid_grant"}`.

**`POST /v1/recover/verify`** — header `DPoP`; body
`{"client_id":"web","resource":"<optional>","credential":<RegistrationResponseJSON>}`.
Atomically consumes the code, removes every existing passkey, registers the new
one, increments the epoch and issues a new code. Response `200`: token response
plus `"recovery_code"`.

### 10.7 Account API (resource endpoints)

Every request carries `Authorization: DPoP <access token with aud = AUTH_ISSUER>`
and a `DPoP` proof with `ath` and `nonce`. In addition to the token and proof
checks, every request requires the session to be **active**: the passkey `cid`
is still registered **with the token's registration ID `rid`** and the
account's epoch equals the token's `epoch` (strongly consistent reads). Revoked sessions are therefore rejected
immediately, not when their access token expires. Failures use
`WWW-Authenticate: DPoP error="invalid_token", algs="ES256"` (RFC 9449 §7.1).

Endpoints marked **step-up** require `now - auth_time <= STEP_UP_MAX_AGE`.
Otherwise they return `401` with
`WWW-Authenticate: DPoP error="insufficient_user_authentication", error_description="…", max_age=300, algs="ES256"`
(RFC 9470). The client then performs a passkey sign-in and retries.

| Method and path | Step-up | Behavior |
|---|---|---|
| `GET /v1/account` | no | `200 {"account_id","created_at","passkeys":[{"credential_id","created_at","last_used_at","aaguid","backup_eligible","backup_state"}]}`. `aaguid` is the canonical UUID string (all zeros for most passkey providers). |
| `POST /v1/account/passkeys/options` | yes | `200 {"publicKey": <creation options with excludeCredentials>}`; the challenge is bound to the caller's DPoP key |
| `POST /v1/account/passkeys/verify` | yes | body `{"credential":<RegistrationResponseJSON>}` → `201` passkey object. `409 {"error":"too_many_passkeys"}` at the limit. |
| `DELETE /v1/account/passkeys/{credential_id}` | yes | `204`. `409 {"error":"last_passkey"}` if it is the only one. |
| `POST /v1/account/logout-all` | no | `204`; increments the epoch. |
| `POST /v1/account/recovery-code` | yes | `200 {"recovery_code":"…"}`; the old code stops working. |
| `DELETE /v1/account` | yes | `204`; deletes every item belonging to the account. |

### 10.8 Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | Malformed body, missing field |
| `invalid_client` | 400 | `client_id` not in the allowlist |
| `invalid_grant` | 400 | Refresh token, recovery code or ceremony rejected |
| `unsupported_grant_type` | 400 | `grant_type` other than `refresh_token` (RFC 6749 §5.2) |
| `invalid_target` | 400 | Requested `resource` not allowed |
| `invalid_dpop_proof` | 400 / 401 | DPoP proof rejected |
| `use_dpop_nonce` | 400 / 401 | Retry with the nonce in `DPoP-Nonce` |
| `invalid_token` | 401 | Access token rejected |
| `insufficient_user_authentication` | 401 | Step-up needed |
| `unknown_credential` | 401 | Passkey not registered |
| `webauthn_rejected` | 400 | The WebAuthn response failed verification |
| `too_many_passkeys` | 409 | Limit reached |
| `last_passkey` | 409 | Cannot remove the only passkey |
| `payload_too_large` | 413 | Body over 64 KiB |
| `rate_limited` | 429 | Too many requests |
| `access_denied` | 403 | Blocked by a WAF rule before reaching the service |
| `server_error` | 500 | Internal failure (no details are leaked) |

## 11. CORS

Only origins in `AUTH_CORS_ORIGINS` are allowed. Allowed methods: `GET`, `POST`,
`DELETE`. Allowed request headers: `Authorization`, `DPoP`, `Content-Type`.
Exposed response headers: `DPoP-Nonce`, `WWW-Authenticate`, `Date`. No
credentials (cookies are never used). Preflight max age: 600 s.

## 12. Storage (single DynamoDB table)

Key schema: partition key `pk` (S), sort key `sk` (S); TTL attribute `ttl` (N).
Long identifiers are hashed in keys because a sort key is limited to 1024 bytes.
`H(x)` is base64url(SHA-256(x)).

| `pk` | `sk` | Attributes |
|---|---|---|
| `ACCT#<account id>` | `META` | `created_at`, `epoch`, `passkey_count`, `recovery_key` |
| `ACCT#<account id>` | `CRED#<H(credential id)>` | `credential_id` (B), `registration_id` (S), `public_key` (B, COSE), `alg`, `sign_count`, `backup_eligible`, `backup_state`, `aaguid` (B), `transports` (L), `created_at`, `last_used_at` |
| `CREDID#<H(credential id)>` | `CREDID` | `account_id` — enforces global uniqueness of credential IDs |
| `RECOVERY#<recovery hash>` | `RECOVERY` | `account_id` |
| `CHAL#<b64url challenge>` | `CHAL` | `kind` (`register`, `login`, `recover`, `add_passkey`), `jkt` (bound device key), `account_id`?, `recovery_key`?, `expires_at`, `ttl` |
| `JTI#<H(jkt ‖ 0x00 ‖ jti)>` | `JTI` | `expires_at`, `ttl` |

Reads that decide revocation (`META`, `CRED#…`) are strongly consistent. Because
DynamoDB deletes TTL-expired items lazily, every read of a `CHAL` or `JTI` item
also checks `expires_at`.

## 13. Service configuration

| Variable | Example | Meaning |
|---|---|---|
| `AUTH_ISSUER` | `https://auth.example.com` | Public origin (scheme, host, optional non-default port; no path); `iss`; prefix for every `htu` |
| `AUTH_RP_ID` | `example.com` | WebAuthn RP ID |
| `AUTH_RP_NAME` | `Example` | Shown in the passkey sheet |
| `AUTH_ALLOWED_ORIGINS` | `https://app.example.com,android:apk-key-hash:…` | WebAuthn origins |
| `AUTH_CORS_ORIGINS` | `https://app.example.com` | Browser origins allowed by CORS |
| `AUTH_AUDIENCES` | `https://api.example.com` | Allowed `aud` values (first is the default); the issuer is always allowed |
| `AUTH_CLIENT_IDS` | `web,ios,android,cli` | Allowed `client_id` values |
| `AUTH_TABLE_NAME` | `auth` | DynamoDB table |
| `AUTH_ACCESS_TOKEN_KEY_ID` | KMS key ID/ARN | Active access-token signing key |
| `AUTH_ACCESS_TOKEN_PREVIOUS_KEY_IDS` | comma-separated | Still published in JWKS during rotation |
| `AUTH_REFRESH_TOKEN_KEY_ID` | KMS key ID/ARN | Active refresh-token signing key |
| `AUTH_REFRESH_TOKEN_PREVIOUS_KEY_IDS` | comma-separated | Still accepted during rotation |
| `AUTH_DPOP_NONCE_KEY_ID` | KMS key ID/ARN | HMAC key for nonces |
| `AUTH_LISTEN_ADDR` | `127.0.0.1:8080` | Local mode only (ignored on Lambda) |

The service runs on Lambda when `AWS_LAMBDA_RUNTIME_API` is set, and as a plain
HTTP server otherwise. Only in local mode are `http://localhost` and
`http://127.0.0.1` URLs accepted for the issuer, origins and audiences.

Validation at startup (the service refuses to start otherwise): every web
origin in `AUTH_ALLOWED_ORIGINS` must be `https` and its host must equal the RP
ID or be a subdomain of it (WebAuthn §5.1.4.1); Android origins must carry a
32-byte base64url hash; client IDs are short lowercase identifiers; every KMS
key must have the expected key spec and usage.
