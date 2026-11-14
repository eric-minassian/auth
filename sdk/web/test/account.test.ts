import { describe, expect, test } from 'vitest';
import { normalizeRecoveryCode, type Session } from '../src/index.js';
import { APP_ORIGIN, peekJwt, setup } from './harness.js';
import { SoftwareAuthenticator } from './support/index.js';

/** Routes `create` to a second authenticator (e.g. a security key) and `get` to the first. */
function useSecondAuthenticatorForCreate(first: SoftwareAuthenticator): SoftwareAuthenticator {
  const second = new SoftwareAuthenticator({ origin: APP_ORIGIN, attachment: 'cross-platform' });
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: {
      create: (o?: CredentialCreationOptions) => second.create(o),
      get: (o?: CredentialRequestOptions) => first.get(o),
    },
  });
  return second;
}

describe('account API (protocol §10.7)', () => {
  test('getAccount returns the passkeys and signals them as accepted', async () => {
    const { client, server, authenticator } = await setup({
      authenticator: { backupEligible: true, backupState: true },
    });
    const { accountId } = await client.signUp();
    const account = await client.getAccount();
    expect(account.accountId).toBe(accountId);
    expect(account.passkeys).toHaveLength(1);
    const passkey = account.passkeys[0];
    expect(passkey).toMatchObject({ backupEligible: true, backupState: true, lastUsedAt: null });
    expect(passkey?.credentialId).toBe(
      authenticator.credentials[0] &&
        Buffer.from(authenticator.credentials[0].id).toString('base64url'),
    );
    expect(authenticator.signals).toEqual([
      {
        kind: 'allAccepted',
        rpId: 'example.com',
        userId: accountId,
        allAcceptedCredentialIds: [passkey?.credentialId],
      },
    ]);
    // Account API calls use an access token whose audience is the issuer.
    const exchange = server.requestsTo('/v1/account', 'GET')[0];
    const token = peekJwt((exchange?.requestHeaders.get('authorization') ?? '').slice(5));
    expect(token.payload['aud']).toBe(server.issuer);
    const proof = peekJwt(exchange?.requestHeaders.get('dpop') ?? '').payload;
    expect(proof).toMatchObject({ htm: 'GET', htu: `${server.issuer}/v1/account` });
    expect(proof['nonce']).toBeTypeOf('string');
    expect(proof['ath']).toBeTypeOf('string');
  });

  test('getAccount without the Signal API still works', async () => {
    const { client, authenticator } = await setup({ authenticator: { signalApi: false } });
    await client.signUp();
    expect((await client.getAccount()).passkeys).toHaveLength(1);
    expect(authenticator.signals).toEqual([]);
  });

  test('addPasskey performs step-up automatically when the session is old', async () => {
    const { client, server, authenticator } = await setup();
    await client.signUp();
    const second = useSecondAuthenticatorForCreate(authenticator);
    server.advance(400); // auth_time is now older than STEP_UP_MAX_AGE
    const changes: (Session | null)[] = [];
    client.onChange((s) => changes.push(s));

    const passkey = await client.addPasskey();

    expect(authenticator.calls.filter((c) => c.kind === 'get')).toHaveLength(1); // the step-up
    expect(second.credentials).toHaveLength(1);
    expect(passkey.credentialId).toBe(
      Buffer.from(second.credentials[0]?.id ?? []).toString('base64url'),
    );
    expect((await client.getAccount()).passkeys).toHaveLength(2);
    expect(changes).toEqual([]); // same account: no sign-in/sign-out transition
    const options = second.calls[0]?.options as CredentialCreationOptions;
    expect(options.publicKey?.excludeCredentials).toHaveLength(1);
    // The options call was retried exactly once after step-up.
    expect(server.requestsTo('/v1/account/passkeys/options').map((e) => e.status)).toContain(401);
  });

  test('addPasskey on an authenticator that already holds a passkey fails (excludeCredentials)', async () => {
    const { client } = await setup();
    await client.signUp();
    await expect(client.addPasskey()).rejects.toMatchObject({ code: 'ceremony_failed' });
  });

  test('a rejected addPasskey verification signals the orphaned passkey', async () => {
    const { client, server, authenticator } = await setup();
    await client.signUp();
    const second = useSecondAuthenticatorForCreate(authenticator);
    server.intercept = (_req, path) =>
      path === '/v1/account/passkeys/verify'
        ? new Response(JSON.stringify({ error: 'too_many_passkeys' }), {
            status: 409,
            headers: { 'Content-Type': 'application/json' },
          })
        : undefined;
    await expect(client.addPasskey()).rejects.toMatchObject({
      code: 'too_many_passkeys',
      status: 409,
    });
    expect(authenticator.signals).toContainEqual(
      expect.objectContaining({ kind: 'unknown', rpId: 'example.com' }),
    );
    expect(second.credentials).toHaveLength(1); // the signal went to the installed PublicKeyCredential
  });

  test('step-up never switches accounts', async () => {
    const { client, server, authenticator } = await setup();
    const first = await client.signUp();
    await client.signOut();
    const other = await client.signUp(); // a second account on the same authenticator
    await client.signOut();
    // Sign back into the first account.
    authenticator.selectCredential = (c) =>
      c.find((x) => Buffer.from(x.userHandle).toString('base64url') === first.accountId);
    await client.signIn();
    server.advance(400);
    // During step-up the user picks the other account's passkey.
    authenticator.selectCredential = (c) =>
      c.find((x) => Buffer.from(x.userHandle).toString('base64url') === other.accountId);
    const before = server.requestsTo('/v1/login/verify').length;
    await expect(client.rotateRecoveryCode()).rejects.toMatchObject({ code: 'account_mismatch' });
    expect(server.requestsTo('/v1/login/verify')).toHaveLength(before); // never sent
    expect(client.session).toEqual({ accountId: first.accountId });
  });

  test('a second step-up demand is surfaced instead of looping', async () => {
    const { client, server } = await setup();
    await client.signUp();
    server.stepUpMaxAge = -1; // nothing is ever recent enough
    await expect(client.rotateRecoveryCode()).rejects.toMatchObject({
      code: 'insufficient_user_authentication',
    });
    expect(server.stats.logins).toBe(1);
  });

  test('removePasskey deletes the passkey and tells the credential manager', async () => {
    const { client, authenticator } = await setup();
    await client.signUp();
    const second = useSecondAuthenticatorForCreate(authenticator);
    const added = await client.addPasskey();
    await client.removePasskey(added.credentialId);
    expect((await client.getAccount()).passkeys.map((p) => p.credentialId)).not.toContain(
      added.credentialId,
    );
    expect(authenticator.signals).toContainEqual({
      kind: 'unknown',
      rpId: 'example.com',
      credentialId: added.credentialId,
    });
    expect(second.credentials).toHaveLength(1); // it lives on the second authenticator; signals reach the first's registry
  });

  test('removing the last passkey is refused with last_passkey', async () => {
    const { client } = await setup();
    await client.signUp();
    const [only] = (await client.getAccount()).passkeys;
    await expect(client.removePasskey(only?.credentialId ?? '')).rejects.toMatchObject({
      code: 'last_passkey',
      status: 409,
    });
  });

  test('removePasskey validates the credential ID before building the URL', async () => {
    const { client, server } = await setup();
    await client.signUp();
    const before = server.exchanges.length;
    await expect(client.removePasskey('../account')).rejects.toThrow(TypeError);
    await expect(client.removePasskey('a/b')).rejects.toThrow(TypeError);
    expect(server.exchanges).toHaveLength(before);
  });

  test('rotateRecoveryCode returns a new code; the old one stops working', async () => {
    const { client } = await setup();
    const { recoveryCode: oldCode } = await client.signUp();
    const newCode = await client.rotateRecoveryCode();
    expect(newCode).not.toBe(oldCode);
    expect(newCode).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
    await client.signOut();
    await expect(client.recover(oldCode)).rejects.toMatchObject({ code: 'invalid_grant' });
  });

  test('signOutEverywhere revokes other devices and signs out here', async () => {
    const { client, newTab, server } = await setup();
    await client.signUp();
    const otherDevice = newTab({ storageName: 'other-device' });
    // Simulate a second device: copy nothing, sign in there with the same passkey.
    await otherDevice.signIn();
    await client.signOutEverywhere();
    expect(client.session).toBeNull();
    expect(server.requestsTo('/v1/account/logout-all')[0]?.status).toBe(204);
    // The other device's refresh token now fails (epoch changed).
    const fresh = newTab({ storageName: 'other-device' });
    expect(await fresh.restore()).toBeNull();
  });

  test('deleteAccount removes the account, clears the passkey and signs out', async () => {
    const { client, server, authenticator } = await setup();
    const { accountId } = await client.signUp();
    await client.deleteAccount();
    expect(server.accounts.has(accountId)).toBe(false);
    expect(client.session).toBeNull();
    expect(authenticator.signals.at(-1)).toEqual({
      kind: 'allAccepted',
      rpId: 'example.com',
      userId: accountId,
      allAcceptedCredentialIds: [],
    });
    expect(authenticator.credentials).toHaveLength(0);
  });

  test('account calls without a session fail with not_signed_in', async () => {
    const { client } = await setup();
    await expect(client.getAccount()).rejects.toMatchObject({ code: 'not_signed_in' });
    await expect(client.signOutEverywhere()).rejects.toMatchObject({ code: 'not_signed_in' });
    await expect(client.deleteAccount()).rejects.toMatchObject({ code: 'not_signed_in' });
  });
});

describe('recovery (protocol §9, §10.6)', () => {
  test('recovers on a new device, replaces every passkey and revokes old sessions', async () => {
    const { client, newTab, server, authenticator } = await setup();
    const { accountId, recoveryCode } = await client.signUp();
    const oldCredential = Buffer.from(authenticator.credentials[0]?.id ?? []).toString('base64url');

    // New device: new authenticator, new storage. The code is typed sloppily.
    const device = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    const uninstall = device.install();
    try {
      const sloppy = ` ${recoveryCode.toLowerCase().replaceAll('-', ' ').replaceAll('1', 'l').replaceAll('0', 'o')} `;
      const tab = newTab({ storageName: 'new-device' });
      const result = await tab.recover(sloppy);
      expect(result.accountId).toBe(accountId);
      expect(result.recoveryCode).not.toBe(recoveryCode);
      expect(tab.session).toEqual({ accountId });
      const sent = JSON.parse(
        server.requestsTo('/v1/recover/options')[0]?.requestBody ?? '{}',
      ) as Record<string, string>;
      expect(sent['recovery_code']).toBe(recoveryCode);
      const account = server.accounts.get(accountId);
      expect([...(account?.credentials.keys() ?? [])]).not.toContain(oldCredential);
      expect(account?.credentials.size).toBe(1);
      expect(device.signals.at(-1)).toEqual({
        kind: 'allAccepted',
        rpId: 'example.com',
        userId: accountId,
        allAcceptedCredentialIds: [
          Buffer.from(device.credentials[0]?.id ?? []).toString('base64url'),
        ],
      });
      expect((await tab.fetch('https://api.example.com/hello')).status).toBe(200);
    } finally {
      uninstall();
    }
    // The original device's session is dead.
    expect(await newTab().restore()).toBeNull();
  });

  test('malformed codes are rejected locally; unknown codes by the server', async () => {
    const { client, server } = await setup();
    await expect(client.recover('not a code')).rejects.toMatchObject({
      code: 'invalid_recovery_code',
    });
    await expect(client.recover('UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU')).rejects.toMatchObject({
      code: 'invalid_recovery_code',
    });
    expect(server.exchanges).toHaveLength(0);
    await expect(client.recover('0000-0000-0000-0000-0000-0000-0000-0000')).rejects.toMatchObject({
      code: 'invalid_grant',
      status: 400,
    });
  });

  test('normalizeRecoveryCode follows §9', () => {
    expect(normalizeRecoveryCode('abcd efgh-ijkl mnop qrst vwxy z012 3456')).toBe(
      'ABCD-EFGH-1JK1-MN0P-QRST-VWXY-Z012-3456',
    );
    expect(normalizeRecoveryCode('ABCD')).toBeUndefined();
    expect(normalizeRecoveryCode('ABCD-EFGH-IJKL-MNOP-QRST-VWXY-Z012-345U')).toBeUndefined();
    expect(normalizeRecoveryCode('ABCD-EFGH-IJKL-MNOP-QRST-VWXY-Z012-3456-7')).toBeUndefined();
  });
});
