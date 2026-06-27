import { expect, test, type CDPSession, type Page } from "@playwright/test";

const VIRTUAL_AUTH_OPTIONS = {
  protocol: "ctap2",
  transport: "internal",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
} as const;

/**
 * Installs a CDP virtual WebAuthn authenticator with resident-key + user
 * verification support, so passkey ceremonies (including usernameless
 * discoverable login) complete without real hardware. Returns the CDP session
 * and the authenticator id (so a test can swap in a "new device").
 */
async function addVirtualAuthenticator(
  page: Page,
): Promise<{ client: CDPSession; authenticatorId: string }> {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send("WebAuthn.addVirtualAuthenticator", {
    options: VIRTUAL_AUTH_OPTIONS,
  });
  return { client, authenticatorId };
}

function uniqueNickname(): string {
  return `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
}

/** Drives the passkey sign-up flow (proof-of-work + passkey) to the account page. */
async function signUp(page: Page, nickname: string): Promise<void> {
  await page.goto("/sign-up");
  await page.getByLabel("Display name").fill(nickname);
  await page.getByRole("button", { name: /Create account/ }).click();
  // Allow time for the proof-of-work solve plus two passkey ceremonies.
  await expect(page).toHaveURL(/\/account$/, { timeout: 30_000 });
}

test("sign up with a passkey, then sign out and back in", async ({ page }) => {
  await addVirtualAuthenticator(page);
  const nickname = uniqueNickname();

  await signUp(page, nickname);
  await expect(page.getByText(nickname)).toBeVisible();

  // --- Sign out ---
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/sign-in$/);

  // --- Sign back in with the discoverable passkey (no identifier). The
  // conditional-UI autofill can auto-complete with the virtual authenticator;
  // otherwise the explicit button drives it. Either way we reach /account. ---
  await page
    .getByRole("button", { name: /Sign in with a passkey/ })
    .click({ timeout: 5000 })
    .catch(() => {
      /* conditional UI already signed us in — the button is gone */
    });
  await expect(page).toHaveURL(/\/account$/, { timeout: 30_000 });
  await expect(page.getByText(nickname)).toBeVisible();
});

test("generate recovery codes, then recover the account with one", async ({ page }) => {
  const { client, authenticatorId } = await addVirtualAuthenticator(page);
  const nickname = uniqueNickname();
  await signUp(page, nickname);

  // Generate recovery codes — the fresh login satisfies the step-up. Generation
  // lives under the Recovery tab (deep-linkable via the ?tab search param).
  await page.goto("/account?tab=recovery");
  await page.getByRole("button", { name: /^Generate$/ }).click();
  const codesBlock = page.locator("pre");
  await expect(codesBlock).toBeVisible();
  const codes = (await codesBlock.innerText())
    .trim()
    .split("\n")
    .map((c) => c.trim())
    .filter(Boolean);
  expect(codes.length).toBe(10);
  // Dismiss the one-time codes: acknowledge via the checkbox, then confirm.
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: /^Done$/ }).click();

  // Sign out, then simulate recovering on a NEW device: drop the authenticator
  // holding the original passkey and attach a fresh one (otherwise registering
  // the recovery passkey hits excludeCredentials → InvalidStateError).
  await page.getByRole("button", { name: "Sign out" }).click();
  // Immediately drop the authenticator (this also disarms any conditional-UI
  // auto-login) and attach a fresh one, simulating recovery on a new device.
  await client.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await client.send("WebAuthn.addVirtualAuthenticator", { options: VIRTUAL_AUTH_OPTIONS });

  await page.goto("/recover");
  const [firstCode = ""] = codes;
  await page.getByLabel("Recovery code").fill(firstCode);
  await page.getByRole("button", { name: /Recover/ }).click();
  // Recovery hands off to /account?tab=recovery&generate=1 to mint fresh codes.
  await expect(page).toHaveURL(/\/account/, { timeout: 30_000 });
});

test("OIDC authorize returns a code to the RP when signed in", async ({ page }) => {
  await addVirtualAuthenticator(page);
  await signUp(page, uniqueNickname());

  // Hitting authorize while signed in returns a code to the dev RP callback.
  const params = new URLSearchParams({
    response_type: "code",
    client_id: "dev",
    redirect_uri: "http://localhost:5174/callback",
    scope: "openid profile",
    // S256 challenge of a fixed verifier (its value is irrelevant here).
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256",
    state: "xyz",
  });
  const response = await page.request.get(`/oauth/authorize?${params.toString()}`, {
    maxRedirects: 0,
  });
  expect(response.status()).toBe(303);
  const location = response.headers()["location"] ?? "";
  expect(location).toContain("http://localhost:5174/callback");
  expect(location).toContain("code=");
  expect(location).toContain("state=xyz");
});
