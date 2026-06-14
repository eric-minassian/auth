/** The deployment environments, each its own AWS account. */
export type EnvName = "local" | "prod";

/**
 * Cross-account DNS delegation: the parent zone lives in the org-management
 * account, which exposes one scoped IAM role per delegated subdomain that lets
 * the member account self-register its `NS` record. See `~/projects/aws`
 * (`DnsStack`) and `docs/deploy.md`.
 */
export interface DelegationConfig {
  /** Account that owns the parent (`ericminassian.com`) hosted zone. */
  managementAccountId: string;
  /** Parent zone name; resolved by name by the delegation custom resource. */
  parentZoneName: string;
}

export interface AuthConfig {
  /** Which environment this config is for. */
  name: EnvName;
  /**
   * Target account/region. `account` is omitted for `local`, making the stacks
   * environment-agnostic so they resolve to whatever `CDK_DEFAULT_ACCOUNT` the
   * developer's credentials provide.
   */
  env: { account?: string; region: string };
  /** Registrable domain, e.g. `ericminassian.com`. */
  domain: string;
  /** Auth subdomain label, e.g. `auth` (prod) or `beta.auth` (beta). */
  subdomain: string;
  /** Cross-account delegation for this env's subdomain. */
  delegation: DelegationConfig;
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

/**
 * ARN of the org-management role this env assumes to register its `NS`
 * delegation in the parent zone.
 *
 * LOAD-BEARING: the role name derives from the *full host* (`authHost`), not
 * the bare `subdomain` — it must match `delegationRoleName()` in the org repo
 * (`~/projects/aws/cdk/lib/dns-stack.ts`), which is fed the full subdomain
 * (e.g. `beta.auth.ericminassian.com`). Do not "simplify" to `config.subdomain`.
 */
export function delegationRoleArn(config: AuthConfig): string {
  const roleName = `route53-delegation-${authHost(config).replace(/\./g, "-")}`;
  return `arn:aws:iam::${config.delegation.managementAccountId}:role/${roleName}`;
}
