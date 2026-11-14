/**
 * Reusable test support: a software WebAuthn authenticator (with browser glue)
 * and an in-memory fake of the auth service, plus the binary-format helpers
 * they are built on.
 *
 * Typical use against the fake server:
 *
 *   const server = await FakeAuthServer.create();
 *   const authenticator = new SoftwareAuthenticator({ origin: 'https://app.example.com' });
 *   const uninstall = authenticator.install();
 *   const client = createAuthClient({ issuer: server.issuer, fetch: server.fetch });
 *
 * Against the real service, install the authenticator with an origin listed in
 * `AUTH_ALLOWED_ORIGINS` (and an RP ID that is a suffix of its host) and use the
 * global `fetch`.
 */
export {
  SoftwareAuthenticator,
  type CeremonyCall,
  type PromptHandler,
  type SignalCall,
  type SoftwareAuthenticatorOptions,
  type StoredCredential,
} from './authenticator.js';
export {
  FakeAuthServer,
  type AccountRecord,
  type CredentialRecord,
  type Exchange,
  type FakeAuthServerOptions,
} from './fake-server.js';
export { CborError, decodeCbor, decodeCborPrefix, encodeCbor, type CborValue } from './cbor.js';
export {
  decodeJws,
  signJwt,
  thumbprint,
  verifyDpopProof,
  verifyJwt,
  type DecodedJws,
  type DpopVerdict,
  type VerifyDpopOptions,
} from './jose.js';
export * from './webauthn-format.js';
