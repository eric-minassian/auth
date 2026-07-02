import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Field, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { Link, createRoute } from "@tanstack/react-router";
import { useState } from "react";

import { AuthCard } from "../components/AuthCard.js";
import { useTitle } from "../hooks/useTitle.js";
import { resumeAfterLogin } from "../lib/return-to.js";
import {
  describePasskeyError,
  loginWithPasskey,
  signUp,
  WebAuthnError,
} from "../lib/webauthn.js";
import { centeredLayoutRoute } from "./_centered.js";

interface SignUpSearch {
  return_to?: string;
}

function SignUp() {
  useTitle("Create account");
  const { return_to } = signUpRoute.useSearch();
  const [nickname, setNickname] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function createAccount() {
    setBusy(true);
    setError(undefined);
    try {
      // Solve the proof-of-work, register the first passkey, and activate.
      const { discoverable } = await signUp(nickname.trim());
      if (discoverable === false) throw new WebAuthnError("not_discoverable");
      // Signup leaves an enroll session; a passkey login mints the full session.
      await loginWithPasskey();
      // Resume an in-progress OAuth flow (prompt=create) or land on the account.
      resumeAfterLogin(return_to);
    } catch (e) {
      setError(describePasskeyError(e, "Couldn't finish signing up. Please try again."));
      setBusy(false);
    }
  }

  return (
    <AuthCard
      title="Create your account"
      description="Pick a display name and set up a passkey — no email, no password."
      footer={
        <>
          Already have an account?{" "}
          {/* Carry return_to so a mid-OAuth user still lands back at the RP. */}
          <Link to="/sign-in" search={{ return_to }} className="text-primary underline">
            Sign in
          </Link>
        </>
      }
    >
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      <Field>
        <FieldLabel htmlFor="nickname">Display name</FieldLabel>
        <Input
          id="nickname"
          autoComplete="off"
          placeholder="e.g. Ada"
          value={nickname}
          onChange={(e) => setNickname(e.target.value)}
          onKeyDown={(e) => {
            // busy gate: a second Enter must not start a parallel ceremony.
            if (e.key === "Enter" && !busy && nickname.trim()) void createAccount();
          }}
        />
      </Field>
      <Button
        onClick={() => void createAccount()}
        disabled={busy || !nickname.trim()}
        size="lg"
        className="w-full"
      >
        {busy ? <Spinner /> : null}
        Create account &amp; passkey
      </Button>
    </AuthCard>
  );
}

export const signUpRoute = createRoute({
  getParentRoute: () => centeredLayoutRoute,
  path: "/sign-up",
  validateSearch: (search: Record<string, unknown>): SignUpSearch => ({
    return_to: typeof search.return_to === "string" ? search.return_to : undefined,
  }),
  component: SignUp,
});
