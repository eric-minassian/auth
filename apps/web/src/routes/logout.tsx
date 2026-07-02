import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { createRoute } from "@tanstack/react-router";
import { useState } from "react";

import { AuthCard } from "../components/AuthCard.js";
import { useTitle } from "../hooks/useTitle.js";
import { api } from "../lib/api.js";
import { centeredLayoutRoute } from "./_centered.js";

/**
 * Confirmation page reached when `/oauth/logout` could not verify an
 * `id_token_hint`. The destructive logout happens via this Origin-checked
 * POST, never on the bare GET.
 */
function Logout() {
  useTitle("Sign out");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [failed, setFailed] = useState(false);

  async function signOutEverywhere() {
    setBusy(true);
    setFailed(false);
    try {
      // A failure must stay visible: claiming "signed out" while the session
      // cookie is still live would be a lie with security consequences.
      await api.post("/api/session/logout");
      setDone(true);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard
      title="Sign out"
      description={done ? "You've been signed out." : "Sign out of this account everywhere?"}
    >
      {failed ? (
        <Alert variant="destructive">
          <AlertDescription>
            Couldn&apos;t sign you out — you may still be signed in. Check your connection and
            try again.
          </AlertDescription>
        </Alert>
      ) : null}
      {done ? (
        <Button size="lg" className="w-full" onClick={() => location.assign("/sign-in")}>
          Back to sign in
        </Button>
      ) : (
        <Button
          variant="destructive"
          size="lg"
          className="w-full"
          onClick={signOutEverywhere}
          disabled={busy}
        >
          {busy ? <Spinner /> : null}
          {failed ? "Try again" : "Sign out"}
        </Button>
      )}
    </AuthCard>
  );
}

export const logoutRoute = createRoute({
  getParentRoute: () => centeredLayoutRoute,
  path: "/logout",
  component: Logout,
});
