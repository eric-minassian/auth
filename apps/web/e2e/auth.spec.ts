import { expect, test, type CDPSession, type Page } from "@playwright/test";

/**
 * Installs a CDP virtual WebAuthn authenticator with resident-key + user
 * verification support, so passkey ceremonies complete without real hardware.
 */
async function addVirtualAuthenticator(page: Page): Promise<CDPSession> {
  const client = await page.context().newCDPSession(page);
  await client.send("WebAuthn.enable");
  await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return client;
}

/** Reads the OTP the dev API "emailed", retrying until it lands. */
async function fetchOtp(page: Page, email: string): Promise<string> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const response = await page.request.get(
      `/api/dev/last-otp?email=${encodeURIComponent(email)}`,
    );
    if (response.ok()) {
      return ((await response.json()) as { code: string }).code;
    }
    await page.waitForTimeout(250);
  }
  throw new Error(`no OTP delivered for ${email}`);
}

function uniqueEmail(): string {
  return `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
}

/** Drives the sign-up flow to the account page. */
async function signUp(page: Page, email: string): Promise<void> {
  await page.goto("/sign-up");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Send code" }).click();

  // The OTP step only renders once the start request resolves.
  await expect(page.getByText(/Enter the 6-digit code/)).toBeVisible();
  const code = await fetchOtp(page, email);
  await page.locator('input[autocomplete="one-time-code"]').first().fill(code);
  await page.getByRole("button", { name: "Verify" }).click();

  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page).toHaveURL(/\/account$/);
}

test("sign up with email OTP + passkey, then sign out and back in", async ({ page }) => {
  await addVirtualAuthenticator(page);
  const email = uniqueEmail();

  await signUp(page, email);
  await expect(page.getByText(email)).toBeVisible();
  await expect(page.getByText("Passkey", { exact: true })).toBeVisible();

  // --- Sign out ---
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/sign-in$/);

  // --- Sign back in with the passkey ---
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Sign in with passkey" }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByText(email)).toBeVisible();
});

test("OIDC authorize returns a code to the RP when signed in", async ({ page }) => {
  await addVirtualAuthenticator(page);
  const email = uniqueEmail();
  await signUp(page, email);

  // Hitting authorize while signed in returns a code to the dev RP callback.
  const params = new URLSearchParams({
    response_type: "code",
    client_id: "dev",
    redirect_uri: "http://localhost:5174/callback",
    scope: "openid email",
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
