/** Shared types for the /account tabbed layout, imported by the route and panels. */

export type AccountTab = "overview" | "passkeys" | "recovery" | "sessions" | "profile";

export const ACCOUNT_TABS: readonly AccountTab[] = [
  "overview",
  "passkeys",
  "recovery",
  "sessions",
  "profile",
] as const;

export interface AccountSearch {
  /** Active tab; `undefined` means the default ("overview"). */
  tab?: AccountTab;
  /** Recovery hand-off: auto-open code generation off a fresh assertion. */
  generate?: boolean;
}

function isTab(value: unknown): value is AccountTab {
  return typeof value === "string" && (ACCOUNT_TABS as readonly string[]).includes(value);
}

/**
 * Validate raw search params into a typed {@link AccountSearch}. Falsy values
 * are omitted (not set to `false`/`undefined` keys) so they never serialize into
 * the URL — a bare `/account` stays clean, with no `?generate=false` noise.
 */
export function parseAccountSearch(search: Record<string, unknown>): AccountSearch {
  const generate =
    search.generate === true || search.generate === "1" || search.generate === "true";
  return {
    ...(isTab(search.tab) ? { tab: search.tab } : {}),
    ...(generate ? { generate: true } : {}),
  };
}
