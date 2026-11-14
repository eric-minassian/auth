import { expect, test } from 'vitest';
import { setup } from './harness.js';

test('smoke: sign up, fetch, sign in, account', async () => {
  const { client, server } = await setup();
  const { accountId, recoveryCode } = await client.signUp();
  expect(accountId).toHaveLength(22);
  expect(recoveryCode).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
  const res = await client.fetch('https://api.example.com/hello');
  expect(res.status).toBe(200);
  expect(await res.json()).toMatchObject({ sub: accountId });
  const account = await client.getAccount();
  expect(account.passkeys).toHaveLength(1);
  await client.signOut();
  const session = await client.signIn();
  expect(session.accountId).toBe(accountId);
  expect(server.stats.logins).toBe(1);
});
