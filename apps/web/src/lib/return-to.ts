/**
 * Open-redirect guard for the post-login `return_to`. Only same-origin URLs
 * whose path is exactly `/oauth/authorize` are allowed — that is the only
 * place the sign-in flow ever needs to resume. Anything else falls back to
 * the account page.
 */
export function safeReturnTo(returnTo: string | undefined): string {
  if (!returnTo) return "/account";
  try {
    const url = new URL(returnTo, location.origin);
    if (url.origin === location.origin && url.pathname === "/oauth/authorize") {
      return url.pathname + url.search;
    }
  } catch {
    // fall through
  }
  return "/account";
}

export function resumeAfterLogin(returnTo: string | undefined): void {
  location.assign(safeReturnTo(returnTo));
}
