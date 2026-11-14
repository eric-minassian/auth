import { onTestFinished } from 'vitest';
import { createAuthClient, type AuthClient, type AuthClientOptions } from '../src/index.js';
import {
  FakeAuthServer,
  SoftwareAuthenticator,
  type FakeAuthServerOptions,
  type SoftwareAuthenticatorOptions,
} from './support/index.js';

export const APP_ORIGIN = 'https://app.example.com';

export interface Harness {
  server: FakeAuthServer;
  authenticator: SoftwareAuthenticator;
  client: AuthClient;
  /** Creates another client sharing storage (another tab of the same origin). */
  newTab: (overrides?: Partial<AuthClientOptions>) => AuthClient;
}

export async function setup(
  options: {
    server?: FakeAuthServerOptions;
    authenticator?: Partial<SoftwareAuthenticatorOptions>;
    client?: Partial<AuthClientOptions>;
  } = {},
): Promise<Harness> {
  const server = await FakeAuthServer.create(options.server);
  const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN, ...options.authenticator });
  const uninstall = authenticator.install();
  const clients: AuthClient[] = [];
  const newTab = (overrides: Partial<AuthClientOptions> = {}): AuthClient => {
    const client = createAuthClient({
      issuer: server.issuer,
      defaultResource: server.audiences[0] ?? server.issuer,
      fetch: server.fetch,
      ...options.client,
      ...overrides,
    });
    clients.push(client);
    return client;
  };
  const client = newTab();
  onTestFinished(() => {
    for (const c of clients) c.close();
    uninstall();
  });
  return { server, authenticator, client, newTab };
}

/** Decodes the header and payload of a compact JWS without verifying it. */
export function peekJwt(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const [h, p] = token.split('.');
  const json = (part: string | undefined): Record<string, unknown> =>
    JSON.parse(Buffer.from(part ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
  return { header: json(h), payload: json(p) };
}
