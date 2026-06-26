import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Field, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { Link, createRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { AuthCard } from "../components/AuthCard.js";
import { ApiError } from "../lib/api.js";
import { loginWithPasskey, redeemRecoveryCode, registerPasskey } from "../lib/webauthn.js";
import { rootRoute } from "./root.js";

function Recover() {
  const navigate = useNavigate();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function recover() {
    setBusy(true);
    setError(undefined);
    try {
      await redeemRecoveryCode(code.trim());
      // Recovery grants an enroll session: register a fresh passkey, then log in.
      await registerPasskey();
      await loginWithPasskey();
      void navigate({ to: "/account" });
    } catch (e) {
      setError(
        e instanceof ApiError ? e.message : "Recovery failed. Check the code and try again.",
      );
      setBusy(false);
    }
  }

  return (
    <AuthCard
      title="Recover your account"
      description="Enter a recovery code to register a new passkey."
      footer={
        <Link to="/sign-in" className="text-primary underline">
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
            if (e.key === "Enter" && code.trim()) void recover();
          }}
        />
      </Field>
      <p className="text-muted-foreground text-sm">
        Each code works once and signs you out everywhere. After recovering, save
        a fresh set of codes from your account.
      </p>
      <Button onClick={() => void recover()} disabled={busy || !code.trim()}>
        {busy ? <Spinner /> : null}
        Recover &amp; add a passkey
      </Button>
    </AuthCard>
  );
}

export const recoverRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/recover",
  component: Recover,
});
