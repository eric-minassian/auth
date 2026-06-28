import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Field, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { Link, createRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";

import { AuthCard } from "../components/AuthCard.js";
import { useTitle } from "../hooks/useTitle.js";
import { resumeAfterLogin } from "../lib/return-to.js";
import {
  describePasskeyError,
  isUserCancellation,
  loginWithPasskey,
  supportsConditionalUi,
} from "../lib/webauthn.js";
import { centeredLayoutRoute } from "./_centered.js";

interface SignInSearch {
  return_to?: string;
}

interface SignInError {
  text: string;
  /** A non-failure (the user dismissed the prompt) — shown as a gentle hint, not an alarm. */
  soft?: boolean;
}

function SignIn() {
  useTitle("Sign in");
  const { return_to } = signInRoute.useSearch();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<SignInError | undefined>();
  // Whether the browser offers passkey autofill — gates the anchor input that
  // the conditional ceremony fills in (without it, the dropdown has nowhere to
  // attach and silently never appears).
  const [autofillReady, setAutofillReady] = useState(false);
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
      if (!cancelled) setAutofillReady(true);
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
    } catch (e) {
      setError({
        text: describePasskeyError(e, "Sign-in failed. Try again, or recover your account."),
        soft: isUserCancellation(e),
      });
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
        <Alert variant={error.soft ? "default" : "destructive"}>
          <AlertDescription>{error.text}</AlertDescription>
        </Alert>
      ) : null}
      {autofillReady ? (
        <Field>
          <FieldLabel htmlFor="passkey">Passkey</FieldLabel>
          {/* The autofill anchor: `autocomplete="webauthn"` is what surfaces the
              browser's saved-passkey dropdown for the armed conditional ceremony.
              Usernameless, so its value is never read. */}
          <Input
            id="passkey"
            autoComplete="webauthn"
            placeholder="Tap to use a saved passkey"
            aria-label="Sign in with a saved passkey"
          />
        </Field>
      ) : null}
      <Button onClick={signIn} disabled={busy} size="lg" className="w-full">
        {busy ? <Spinner /> : null}
        Sign in with a passkey
      </Button>
      <Link to="/recover" className="text-muted-foreground text-center text-xs underline">
        Lost access to your passkey?
      </Link>
    </AuthCard>
  );
}

export const signInRoute = createRoute({
  getParentRoute: () => centeredLayoutRoute,
  path: "/sign-in",
  validateSearch: (search: Record<string, unknown>): SignInSearch => ({
    return_to: typeof search.return_to === "string" ? search.return_to : undefined,
  }),
  component: SignIn,
});
