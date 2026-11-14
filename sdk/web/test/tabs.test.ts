import { describe, expect, test, vi } from 'vitest';
import type { Session } from '../src/index.js';
import { setup } from './harness.js';

const API = 'https://api.example.com/hello';

describe('cross-tab coordination', () => {
  test('a sign-in in one tab is picked up by another (BroadcastChannel)', async () => {
    const { client: tabA, newTab } = await setup();
    const tabB = newTab();
    const changes: (Session | null)[] = [];
    tabB.onChange((s) => changes.push(s));
    const { accountId } = await tabA.signUp();
    await vi.waitFor(() => {
      expect(changes).toEqual([{ accountId }]);
    });
    expect(tabB.session).toEqual({ accountId });
    expect((await tabB.fetch(API)).status).toBe(200);
  });

  test('a sign-out in one tab signs out the others', async () => {
    const { client: tabA, newTab } = await setup();
    await tabA.signUp();
    const tabB = newTab();
    await tabB.restore();
    expect((await tabB.fetch(API)).status).toBe(200);
    const changes: (Session | null)[] = [];
    tabB.onChange((s) => changes.push(s));
    await tabA.signOut();
    await vi.waitFor(() => {
      expect(changes).toEqual([null]);
    });
    await expect(tabB.fetch(API)).rejects.toMatchObject({ code: 'not_signed_in' });
  });

  test('a refresh never resurrects a session that another tab signed out', async () => {
    const { client: tabA, newTab, server } = await setup();
    await tabA.signUp();
    const tabB = newTab();
    // Hold tab B's refresh at the server until tab A has signed out.
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let sawRefresh: () => void = () => undefined;
    const refreshStarted = new Promise<void>((resolve) => {
      sawRefresh = resolve;
    });
    server.intercept = async (_req, path) => {
      if (path === '/v1/token') {
        sawRefresh();
        await gate;
      }
      return undefined;
    };
    const restoring = tabB.restore();
    await refreshStarted;
    const signingOut = tabA.signOut(); // waits for the lock held by B's refresh
    release();
    await restoring;
    await signingOut;
    expect(tabA.session).toBeNull();
    await vi.waitFor(() => {
      expect(tabB.session).toBeNull();
    });
    expect(await newTab().restore()).toBeNull();
  });

  test('concurrent refreshes in two tabs both succeed and leave a usable stored session', async () => {
    const { client, newTab, server } = await setup();
    await client.signUp();
    const tabA = newTab();
    const tabB = newTab();
    const [a, b] = await Promise.all([tabA.fetch(API), tabB.fetch(API)]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(server.stats.refreshes).toBe(2); // access tokens are per tab (memory only)
    expect(await newTab().restore()).not.toBeNull();
  });

  test('works without the Web Locks API (in-tab fallback)', async () => {
    const { client, newTab, server } = await setup();
    await client.signUp();
    // Shadow the prototype getter with an own property.
    Object.defineProperty(navigator, 'locks', { value: undefined, configurable: true });
    try {
      const tab = newTab();
      const responses = await Promise.all([tab.fetch(API), tab.fetch(API), tab.fetch(API)]);
      expect(responses.map((r) => r.status)).toEqual([200, 200, 200]);
      expect(server.stats.refreshes).toBe(1);
    } finally {
      Reflect.deleteProperty(navigator, 'locks');
    }
  });
});
