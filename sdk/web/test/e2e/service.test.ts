/**
 * End-to-end tests of the SDK against the real Rust service (not the fake).
 *
 * Skipped unless AUTH_E2E_ISSUER is set. `scripts/e2e-sdk.sh` starts the service
 * against aws-emulator and runs this file with:
 *   AUTH_E2E_ISSUER  e.g. http://localhost:18080
 *   AUTH_E2E_ORIGIN  an origin in the service's AUTH_ALLOWED_ORIGINS
 */
import { afterEach, describe, expect, it } from 'vitest';
import { AuthError, createAuthClient, type AuthClient } from '../../src/index.js';
import { parseCreationOptionsJSON, toCreationOptions } from '../../src/webauthn.js';
import { SoftwareAuthenticator } from '../support/index.js';

const issuer = process.env['AUTH_E2E_ISSUER'] ?? '';
const origin = process.env['AUTH_E2E_ORIGIN'] ?? 'http://localhost:5173';

const clients: AuthClient[] = [];
const installed: (() => void)[] = [];

afterEach(() => {
  for (const c of clients.splice(0)) c.close();
  for (const u of installed.splice(0).reverse()) u();
});

/** One browser profile: its own storage and device key. */
function device(storageName = `e2e-${crypto.randomUUID()}`): AuthClient {
  const client = createAuthClient({ issuer, storageName });
  clients.push(client);
  return client;
}

/** A passkey provider installed as navigator.credentials (synced by default). */
function provider(synced = true): { authenticator: SoftwareAuthenticator; uninstall: () => void } {
  const authenticator = new SoftwareAuthenticator({
    origin,
    signCount: synced ? 'zero' : 'increment',
    backupEligible: synced,
    backupState: synced,
  });
  const uninstall = authenticator.install();
  installed.push(uninstall);
  return { authenticator, uninstall };
}

async function errorCode(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (error) {
    if (error instanceof AuthError) return error.code;
    throw error;
  }
  throw new Error('expected an AuthError');
}

describe.skipIf(issuer === '')('SDK against the real service', () => {
  it('signs up and signs in on a second device with the same synced passkey', async () => {
    const { authenticator } = provider();
    const phone = device();
    const { accountId, recoveryCode } = await phone.signUp();
    expect(accountId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(recoveryCode).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(phone.session?.accountId).toBe(accountId);

    const account = await phone.getAccount();
    expect(account.accountId).toBe(accountId);
    expect(account.passkeys).toHaveLength(1);
    expect(account.passkeys[0]?.backupEligible).toBe(true);

    const laptop = device();
    expect((await laptop.signIn()).accountId).toBe(accountId);
    expect((await laptop.getAccount()).accountId).toBe(accountId);
    expect(authenticator.credentials).toHaveLength(1);
  });

  it('restores a session after a reload without any passkey prompt', async () => {
    const { authenticator } = provider();
    const storageName = `e2e-reload-${crypto.randomUUID()}`;
    const first = device(storageName);
    const { accountId } = await first.signUp();
    first.close();
    const ceremonies = authenticator.calls.length;

    const reloaded = device(storageName);
    expect((await reloaded.restore())?.accountId).toBe(accountId);
    expect((await reloaded.getAccount()).accountId).toBe(accountId);
    expect(authenticator.calls.length).toBe(ceremonies);
  });

  it('adds a security key, removes it and rotates the recovery code', async () => {
    const synced = provider();
    const phone = device();
    await phone.signUp();

    // A second authenticator (a security key) for the same account.
    synced.uninstall();
    provider(false);
    const added = await phone.addPasskey();
    expect(added.backupEligible).toBe(false);
    expect((await phone.getAccount()).passkeys).toHaveLength(2);
    await phone.removePasskey(added.credentialId);
    expect((await phone.getAccount()).passkeys).toHaveLength(1);

    const code = await phone.rotateRecoveryCode();
    expect(code).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/);
  });

  it('signs out everywhere: other devices lose their sessions immediately', async () => {
    provider();
    const phone = device();
    await phone.signUp();
    const storageName = `e2e-laptop-${crypto.randomUUID()}`;
    const laptop = device(storageName);
    await laptop.signIn();
    await laptop.getAccount();

    await phone.signOutEverywhere();
    expect(phone.session).toBeNull();
    // The laptop still holds an unexpired access token, but the account API
    // checks the session on every request.
    expect(await errorCode(laptop.getAccount())).toMatch(
      /^(invalid_token|invalid_grant|not_signed_in)$/,
    );
    // After a reload there is nothing to restore.
    expect(await device(storageName).restore()).toBeNull();
  });

  it('recovers an account with a new passkey and the recovery code', async () => {
    const lost = provider();
    const phone = device();
    const { accountId, recoveryCode } = await phone.signUp();
    lost.uninstall();

    provider();
    const fresh = device();
    const typed = recoveryCode.toLowerCase().replaceAll('-', ' ');
    const { recoveryCode: next } = await fresh.recover(typed);
    expect(next).not.toBe(recoveryCode);
    expect(fresh.session?.accountId).toBe(accountId);
    expect((await fresh.getAccount()).passkeys).toHaveLength(1);

    // The old device's session is revoked at once, and the old code is spent.
    expect(await errorCode(phone.getAccount())).toMatch(
      /^(invalid_token|invalid_grant|not_signed_in)$/,
    );
    expect(await errorCode(device().recover(recoveryCode))).toBe('invalid_grant');
  });

  it('deletes the account and makes the passkey provider forget it', async () => {
    const { authenticator } = provider();
    const phone = device();
    await phone.signUp();
    await phone.deleteAccount();
    expect(phone.session).toBeNull();
    expect(authenticator.credentials).toHaveLength(0);
    expect(authenticator.signals.some((s) => s.kind === 'allAccepted')).toBe(true);
  });

  it('signals an unknown passkey so the provider stops offering it', async () => {
    const { authenticator } = provider();
    // A passkey the server never stored (for example from an abandoned sign-up).
    const res = await fetch(`${issuer}/v1/register/options`, { method: 'POST' });
    const { publicKey } = (await res.json()) as { publicKey: unknown };
    await navigator.credentials.create({
      publicKey: toCreationOptions(parseCreationOptionsJSON(publicKey)),
    });
    expect(authenticator.credentials).toHaveLength(1);

    expect(await errorCode(device().signIn())).toBe('unknown_credential');
    expect(authenticator.signals.some((s) => s.kind === 'unknown')).toBe(true);
    expect(authenticator.credentials).toHaveLength(0);
  });
});
