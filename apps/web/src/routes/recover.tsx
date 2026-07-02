import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Field, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { Link, createRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { AuthCard } from "../components/AuthCard.js";
import { useTitle } from "../hooks/useTitle.js";
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

function Recover() {
  useTitle("Recover account");
  const navigate = useNavigate();
  const { return_to } = recoverRoute.useSearch();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function recover() {
    setBusy(true);
    setError(undefined);
    try {
      await redeemRecoveryCode(code.trim());
      // Recovery grants an enroll session: register a fresh passkey, then log in.
      const { discoverable } = await registerPasskey();
      if (discoverable === false) throw new WebAuthnError("not_discoverable");
      await loginWithPasskey();
      // The user just completed a user-verifying assertion, so drop them
      // straight into generating replacement codes via a typed search param.
      void navigate({ to: "/account", search: { tab: "recovery", generate: true } });
    } catch (e) {
      setError(describePasskeyError(e, "Recovery failed. Check the code and try again."));
      setBusy(false);
    }
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
            if (e.key === "Enter" && !busy && code.trim()) void recover();
          }}
        />
      </Field>
      <p className="text-muted-foreground text-xs/relaxed">
        Each code works once and signs you out everywhere. After recovering, save
        a fresh set of codes from your account.
      </p>
      <Button
        onClick={() => void recover()}
        disabled={busy || !code.trim()}
        size="lg"
        className="w-full"
      >
        {busy ? <Spinner /> : null}
        Recover &amp; add a passkey
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
