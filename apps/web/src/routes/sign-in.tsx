import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { Link, createRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { AuthCard } from "../components/AuthCard.js";
import { resumeAfterLogin } from "../lib/return-to.js";
import { loginWithPasskey, supportsConditionalUi } from "../lib/webauthn.js";
import { rootRoute } from "./root.js";

interface SignInSearch {
  return_to?: string;
}

function SignIn() {
  const { return_to } = signInRoute.useSearch();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  // Holds the in-flight conditional-UI ceremony so the explicit button can
  // abort it — only one WebAuthn get() may be outstanding at a time.
  const conditional = useRef<AbortController | undefined>(undefined);

  // Conditional UI: arm the autofill-driven passkey prompt on mount.
  useEffect(() => {
    const controller = new AbortController();
    conditional.current = controller;
    let cancelled = false;
    void (async () => {
      if (!(await supportsConditionalUi())) return;
      try {
        await loginWithPasskey({ conditional: true, signal: controller.signal });
        if (!cancelled) resumeAfterLogin(return_to);
      } catch {
        // Aborted or no autofill selection — the explicit button still works.
      }
    })();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [return_to]);

  async function signIn() {
    setBusy(true);
    setError(undefined);
    // Cancel the pending conditional ceremony before starting an explicit one.
    conditional.current?.abort();
    try {
      await loginWithPasskey();
      resumeAfterLogin(return_to);
    } catch {
      setError("Sign-in failed. Try again, or recover your account.");
      setBusy(false);
    }
  }

  return (
    <AuthCard
      title="Sign in"
      description="Use your passkey to continue — no email, no password."
      footer={
        <>
          No account?{" "}
          <Link to="/sign-up" className="text-primary underline">
            Create one
          </Link>
        </>
      }
    >
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <Button onClick={signIn} disabled={busy}>
        {busy ? <Spinner /> : null}
        Sign in with a passkey
      </Button>
      <Link to="/recover" className="text-muted-foreground text-center text-sm underline">
        Lost access to your passkey?
      </Link>
    </AuthCard>
  );
}

export const signInRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sign-in",
  validateSearch: (search: Record<string, unknown>): SignInSearch => ({
    return_to: typeof search.return_to === "string" ? search.return_to : undefined,
  }),
  component: SignIn,
});
