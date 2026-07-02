import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Field, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { Link, createRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";

import { AuthCard } from "../components/AuthCard.js";
import { useTitle } from "../hooks/useTitle.js";
import { ApiError, api, type SessionInfo } from "../lib/api.js";
import {
  describePasskeyError,
  loginWithPasskey,
  redeemRecoveryCode,
  registerPasskey,
  WebAuthnError,
} from "../lib/webauthn.js";
import { centeredLayoutRoute } from "./_centered.js";

interface RecoverSearch {
  return_to?: string;
}

/**
 * Recovery is two irreversible steps with very different retry semantics:
 * redeeming the one-time code (burns it, signs out everywhere, leaves an
 * enroll session), then registering a replacement passkey (retryable for the
 * ~30-minute life of that enroll session). Splitting them means a cancelled
 * passkey prompt never sends the user back to burn a second code.
 */
type Step = "code" | "register";

function Recover() {
  useTitle("Recover account");
  const navigate = useNavigate();
  const { return_to } = recoverRoute.useSearch();
  const [step, setStep] = useState<Step>("code");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  // A live enroll session (403 from the whoami endpoint) means a code was
  // already redeemed — e.g. the passkey prompt was cancelled and the page
  // reloaded. Resume at the register step instead of asking for another code.
  useEffect(() => {
    let cancelled = false;
    void api.get<SessionInfo>("/api/session").catch((e: unknown) => {
      if (!cancelled && e instanceof ApiError && e.status === 403) {
        setStep("register");
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  async function redeem() {
    setBusy(true);
    setError(undefined);
    try {
      await redeemRecoveryCode(code.trim());
      setStep("register");
    } catch (e) {
      setError(describePasskeyError(e, "Recovery failed. Check the code and try again."));
    } finally {
      setBusy(false);
    }
  }

  async function register() {
    setBusy(true);
    setError(undefined);
    try {
      // The code is already redeemed: this step only creates the replacement
      // passkey and signs in with it. Fully retryable.
      const { discoverable } = await registerPasskey();
      if (discoverable === false) throw new WebAuthnError("not_discoverable");
      await loginWithPasskey();
      // If older passkeys survived the recovery, the server requires a
      // review before this account can authorize again — the code that
      // recovered the account may have been racing a stolen passkey.
      let session: SessionInfo | undefined;
      try {
        session = await api.get<SessionInfo>("/api/session");
      } catch {
        // Fall through; the server re-gates at /oauth/authorize regardless.
      }
      if (session?.user.pending_credential_review) {
        void navigate({ to: "/review-passkeys", search: { return_to, from: "recovery" } });
        return;
      }
      // The user just completed a user-verifying assertion, so drop them
      // straight into generating replacement codes via a typed search param.
      void navigate({ to: "/account", search: { tab: "recovery", generate: true } });
    } catch (e) {
      setError(
        describePasskeyError(e, "Couldn't create the replacement passkey. Please try again."),
      );
      setBusy(false);
    }
  }

  if (step === "register") {
    return (
      <AuthCard
        title="Code accepted"
        description="Now create a replacement passkey for this device."
      >
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        <p className="text-muted-foreground text-xs/relaxed">
          Your recovery code was accepted and every other session was signed
          out. This step can be retried — it won&apos;t use another code.
        </p>
        <Button onClick={() => void register()} disabled={busy} size="lg" className="w-full">
          {busy ? <Spinner /> : null}
          Create a passkey &amp; sign in
        </Button>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title="Recover your account"
      description="Enter a recovery code to register a new passkey."
      footer={
        // Carry return_to so a mid-OAuth user still lands back at the RP.
        <Link to="/sign-in" search={{ return_to }} className="text-primary underline">
          Back to sign in
        </Link>
      }
    >
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <Field>
        <FieldLabel htmlFor="code">Recovery code</FieldLabel>
        <Input
          id="code"
          autoComplete="off"
          autoCapitalize="characters"
          placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onKeyDown={(e) => {
            // busy gate: a double Enter must not redeem a second one-time code.
            if (e.key === "Enter" && !busy && code.trim()) void redeem();
          }}
        />
      </Field>
      <p className="text-muted-foreground text-xs/relaxed">
        Each code works once and signs you out everywhere. After recovering, save
        a fresh set of codes from your account.
      </p>
      <Button
        onClick={() => void redeem()}
        disabled={busy || !code.trim()}
        size="lg"
        className="w-full"
      >
        {busy ? <Spinner /> : null}
        Redeem recovery code
      </Button>
    </AuthCard>
  );
}

export const recoverRoute = createRoute({
  getParentRoute: () => centeredLayoutRoute,
  path: "/recover",
  validateSearch: (search: Record<string, unknown>): RecoverSearch => ({
    return_to: typeof search.return_to === "string" ? search.return_to : undefined,
  }),
  component: Recover,
});
