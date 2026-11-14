# @eric-minassian/auth-web

Browser SDK for the passkey-only, anonymous, PII-free auth service. It implements the client
side of [`docs/protocol.md`](../../docs/protocol.md):

- **Passkeys only** (WebAuthn Level 3) for sign-up, sign-in, step-up and recovery.
- **Device-bound sessions**: a non-extractable P-256 key, generated per session and stored in
  IndexedDB, signs a [DPoP](https://www.rfc-editor.org/rfc/rfc9449) proof for every request.
  Tokens are useless without that key.
- **Silent renewal**: after the first passkey ceremony, `restore()` keeps the user signed in
  without any prompt until the session expires (30 days idle, one year absolute), is revoked,
  or a sensitive action needs a fresh passkey (step-up).

Zero runtime dependencies, ESM only, ES2022, TypeScript types included.

## Install

```sh
npm install @eric-minassian/auth-web
```

## Usage

```ts
import { createAuthClient, AuthError, StepUpRequiredError } from '@eric-minassian/auth-web';

const auth = createAuthClient({
  issuer: 'https://auth.example.com', // AUTH_ISSUER, canonical, no trailing slash
  defaultResource: 'https://api.example.com', // RFC 8707 audience of your API
  // clientId: 'web',                  // default
  // storageName: 'auth-web',          // IndexedDB database name
  // fetch: customFetch,               // defaults to globalThis.fetch
});

auth.onChange((session) => render(session)); // fires on sign-in / sign-out, also from other tabs

// On page load: silent, never shows UI.
try {
  await auth.restore(); // Session | null
} catch (error) {
  // Network trouble or rate limiting: the stored session is kept, try again later.
}
```

### Sign up, sign in

Call these from a click handler: browsers require a user gesture for passkey prompts.

```ts
// New anonymous account. Show the recovery code exactly once.
const { accountId, recoveryCode } = await auth.signUp();

// Sign in with a passkey (account picker / passkey sheet).
const session = await auth.signIn();
```

**Immediate UI.** `signIn({ immediate: true })` uses Chrome's Immediate UI mode (Chrome 149+):
if this device has a passkey for the site, the browser shows a lightweight sign-in sheet;
otherwise the promise resolves to `null` right away, without the modal "use a phone or
security key" dialog. Use the `null` result to show your sign-up / other-device options.

```ts
button.onclick = async () => {
  const session = await auth.signIn({ immediate: true });
  if (session === null) showSignUpOrOtherDeviceOptions(); // includes a plain `auth.signIn()`
};
```

The SDK only passes `uiMode: 'immediate'` after `PublicKeyCredential.getClientCapabilities()`
reports `immediateGet: true`; browsers silently ignore unknown members and would otherwise show
the normal modal. Where Immediate UI is unavailable, `signIn({ immediate: true })` resolves to
`null` without prompting. `auth.isImmediateSignInAvailable()` exposes the detection.

### Calling your API

```ts
const response = await auth.fetch('https://api.example.com/v1/things', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'x' }),
  // resource: 'https://other-api.example.com', // when not the default
});
```

`auth.fetch` obtains (and silently refreshes) an access token for the resource, adds
`Authorization: DPoP <token>` and a fresh `DPoP` proof bound to the method, URL and token, and:

- retries once when the server asks for a DPoP nonce (`use_dpop_nonce`, both the 400 JSON and
  the 401 `WWW-Authenticate` form);
- on `invalid_token`, refreshes once and retries;
- on a resource server's `invalid_dpop_proof` caused by a stale clock estimate, re-syncs the
  clock with the auth service and retries once;
- on `insufficient_user_authentication` (RFC 9470) throws `StepUpRequiredError`: call
  `auth.signIn()` and retry.

For safety it refuses (`TypeError`) to send a token to a URL whose origin differs from the
resource's, or over plain `http` (except loopback hosts). Redirects are not followed unless you
pass `redirect` explicitly, since a proof is valid for one URL only.

### Account management

```ts
const account = await auth.getAccount(); // { accountId, createdAt, passkeys: [...] }
await auth.addPasskey(); // e.g. a security key or another platform
await auth.removePasskey(credentialId);
const newCode = await auth.rotateRecoveryCode();
await auth.signOutEverywhere(); // revokes every session of the account, then signs out here
await auth.deleteAccount();
await auth.signOut(); // this device only: destroys the key and every token

// Lost every passkey: recover with the code (input is normalized: case, spaces, I/L/O).
const { accountId, recoveryCode } = await auth.recover('XXXX-XXXX-…');
```

`addPasskey`, `removePasskey`, `rotateRecoveryCode` and `deleteAccount` need a passkey
ceremony from the last five minutes. When the server asks for step-up, these helpers run
`signIn()` and retry once. If the user picks a passkey of a _different_ account during step-up,
they fail with `account_mismatch` instead of acting on that other account.

### Errors

Every failure is an `AuthError` with a typed `code` (or a `TypeError` for invalid arguments):

| Code                                                                                                                                                | Meaning                                                   |
| --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| protocol codes (`invalid_grant`, `webauthn_rejected`, `unknown_credential`, `too_many_passkeys`, `last_passkey`, `rate_limited`, `server_error`, …) | returned by the server, see protocol §10.8                |
| `insufficient_user_authentication`                                                                                                                  | thrown as `StepUpRequiredError` (`maxAge` in seconds)     |
| `ceremony_cancelled`                                                                                                                                | the user dismissed the passkey prompt or it timed out     |
| `ceremony_failed`                                                                                                                                   | other WebAuthn failure (`cause` holds the `DOMException`) |
| `not_signed_in`                                                                                                                                     | no session on this device                                 |
| `account_mismatch`                                                                                                                                  | step-up with another account's passkey                    |
| `network_error`, `invalid_response`, `unexpected_status`                                                                                            | transport / server contract problems                      |
| `webauthn_unsupported`, `storage_unavailable`, `credential_invalid`, `invalid_recovery_code`                                                        | environment or input problems                             |

`error.status` and `error.description` carry the HTTP status and the server's
`error_description` when there is one.

## Security model

- **Keys.** Each session gets a fresh ECDSA P-256 key pair created with WebCrypto
  `extractable: false`. The `CryptoKey` objects are structured-cloned into IndexedDB; their
  private bytes are never reachable from JavaScript, so neither XSS nor a stolen storage dump
  can copy the key off the device. Keys loaded back from storage are checked (non-extractable,
  P-256, signing) and discarded otherwise. A new key per session keeps accounts unlinkable on a
  shared device.
- **Tokens.** Access tokens (5 minutes) live only in memory, keyed by resource. The refresh
  token is stored in IndexedDB next to the key; it is DPoP-bound (`cnf.jkt`) and therefore
  useless without the key. Nothing is ever written to `localStorage`, `sessionStorage` or
  cookies, nothing is logged, and requests to the auth service use `credentials: 'omit'`,
  `cache: 'no-store'` and `referrerPolicy: 'no-referrer'`.
- **Proofs.** ES256 over `typ: dpop+jwt` with the public JWK only (`kty`, `crv`, `x`, `y`),
  `htm`, `htu` (origin + path, no query or fragment), a random 128-bit `jti`, `iat` corrected
  for clock skew (estimated from the auth service's `Date` header), the latest server nonce and,
  with an access token, `ath`.
- **Sign-out** deletes the key and tokens (protocol §6.3): without the key no proof can ever be
  produced again for that session. Other tabs are told through `BroadcastChannel`.
- **Cross-tab safety.** Every write of the stored session (sign-in, refresh, sign-out) holds a
  Web Lock, and a refresh re-reads the record before using and before replacing it, so it can
  never resurrect a session another tab signed out or replaced. Refreshes are single-flight per
  resource within a tab.
- **Validation.** Every server response is shape-checked before use; base64url decoding is
  strict (no padding, no foreign characters, canonical trailing bits); tokens must be `token68`
  and `token_type` must be `DPoP`.
- **Passkey hygiene** (Signal API, feature-detected): unknown credentials are reported with
  `signalUnknownCredential`; `getAccount()`, recovery and account deletion report the accepted
  set with `signalAllAcceptedCredentials`; a passkey created for a registration that the server
  then rejects is reported as unknown so it does not linger in the user's password manager.
- **CSP.** No `eval` or dynamic code. `connect-src` must allow the issuer and your APIs.

### Server and CORS requirements

The auth service must expose `DPoP-Nonce`, `WWW-Authenticate` and `Date` (protocol §11).
Resource servers should accept the `Authorization` and `DPoP` request headers and expose
`DPoP-Nonce` and `WWW-Authenticate`.

## Browser support

Evergreen browsers with WebAuthn, WebCrypto ECDSA P-256, IndexedDB (with `CryptoKey`
storage) and `fetch`. Optional features are detected at runtime:

| Feature                                                                      | Used for                                 | Fallback                                      |
| ---------------------------------------------------------------------------- | ---------------------------------------- | --------------------------------------------- |
| Web Locks API                                                                | cross-tab refresh/sign-out serialization | in-tab mutex                                  |
| `BroadcastChannel`                                                           | instant sign-in/sign-out in other tabs   | other tabs notice on their next refresh       |
| `PublicKeyCredential.getClientCapabilities()` + `immediateGet` (Chrome 149+) | Immediate UI                             | `signIn({ immediate: true })` resolves `null` |
| WebAuthn Signal API                                                          | keeping password managers in sync        | skipped                                       |

Notes:

- Call `signUp`, `signIn`, `addPasskey` and `recover` directly from a user gesture. The SDK
  fetches the WebAuthn options first (one request); Safari in particular is strict about the
  user-activation window.
- Passkey options and responses are converted manually (Level 3 JSON forms), so the SDK does
  not depend on `PublicKeyCredential.parseCreationOptionsFromJSON` / `toJSON()`, and works with
  credential objects from password-manager extensions.
- In private browsing, IndexedDB is usually wiped when the window closes, so the session ends
  with it.

## Development

```sh
npm ci
npm run lint && npm run typecheck && npm run format:check && npm test && npm run build
```

Tests run in Node with `fake-indexeddb` and Node's WebCrypto. `test/support/` exports reusable
fixtures that produce and verify the real binary formats:

- `SoftwareAuthenticator`: `navigator.credentials.create/get` with CBOR attestation objects
  (fmt `none`), COSE ES256 keys, correct authenticator data and flags, `clientDataJSON` and DER
  assertion signatures; `install()` also provides `PublicKeyCredential` statics (capabilities,
  Signal API).
- `FakeAuthServer`: an in-memory auth service and resource API (`server.fetch`) that verifies
  DPoP proofs (signature, `typ`, `alg`, `jwk`, `htm`, `htu`, `iat`, nonce, `ath`, `jti` replay),
  WebAuthn ceremonies, refresh-token binding and epochs, audiences and step-up.

The authenticator is independent of the fake server and can drive end-to-end tests against the
real service: install it with an origin from `AUTH_ALLOWED_ORIGINS` and use the global `fetch`.
