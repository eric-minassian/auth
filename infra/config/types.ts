export interface AuthConfig {
  env: { account: string; region: string };
  /** Registrable domain, e.g. `ericminassian.com`. */
  domain: string;
  /** Auth subdomain label, e.g. `auth`. */
  subdomain: string;
  /** Filesystem path (relative to infra/) of the built Lambda bootstrap dir. */
  lambdaAssetPath: string;
  /** Filesystem path (relative to infra/) of the built SPA dist dir. */
  spaAssetPath: string;
}

/**
 * The auth host (`auth.ericminassian.com`). This is also the name of the
 * delegated public hosted zone: the parent `ericminassian.com` zone (managed
 * elsewhere) delegates this subdomain to us via NS records, so the zone apex
 * is the auth host itself.
 */
export function authHost(config: AuthConfig): string {
  return `${config.subdomain}.${config.domain}`;
}

export function issuerUrl(config: AuthConfig): string {
  return `https://${authHost(config)}`;
}

/** `mail.auth.<domain>` — the SES custom MAIL FROM subdomain (inside our zone). */
export function mailFromDomain(config: AuthConfig): string {
  return `mail.${authHost(config)}`;
}

/** No-reply sender on the auth host. */
export function emailFrom(config: AuthConfig): string {
  return `no-reply@${authHost(config)}`;
}
