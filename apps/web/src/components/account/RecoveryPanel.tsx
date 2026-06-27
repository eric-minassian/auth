import { Button } from "@eric-minassian/design/components/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@eric-minassian/design/components/card";
import { useRouter } from "@tanstack/react-router";
import { useCallback, useEffect, useRef, useState } from "react";

import { useAccountMutation } from "../../hooks/useAccountMutation.js";
import type { RecoveryReadiness } from "../../lib/api.js";
import { generateRecoveryCodes } from "../../lib/webauthn.js";
import { ConfirmDelete } from "../ConfirmDelete.js";
import { ShowOnceCodes } from "../ShowOnceCodes.js";

const LOW_RECOVERY_CODES = 3;

export function RecoveryPanel(props: {
  readiness: RecoveryReadiness;
  /** Set by the recovery hand-off (?generate=1): auto-run generation on mount. */
  autoGenerate: boolean;
  /** Clear the ?generate search param once consumed. */
  onConsumeGenerate: () => void;
}) {
  const router = useRouter();
  const { run, busy } = useAccountMutation();
  const [newCodes, setNewCodes] = useState<string[]>();
  // Non-secret screen-reader announcement (the codes themselves are never read).
  const [announce, setAnnounce] = useState("");

  const remaining = props.readiness.recovery_codes_remaining;
  const hasCodes = remaining > 0;
  const low = remaining > 0 && remaining < LOW_RECOVERY_CODES;

  const generate = useCallback(async () => {
    // Show the once-only codes WITHOUT a post-mutation route invalidate: an
    // errored re-validation would render the route's errorComponent and unmount
    // this panel before the freshly-rotated codes are ever displayed — losing
    // the account's only break-glass factor. The readiness count is refreshed
    // later, on dismiss, when no secret is on screen.
    const codes = await run("generate", () => generateRecoveryCodes(), {
      error: "Could not generate recovery codes",
      skipInvalidate: true,
    });
    if (codes) {
      setNewCodes(codes);
      setAnnounce("Recovery codes generated. Save them now — they're shown only once.");
    }
  }, [run]);

  function dismiss() {
    setNewCodes(undefined);
    setAnnounce("");
    // Safe to refresh now: no secret is rendered, so an errored refetch that
    // swaps in the error view can't drop the codes.
    void router.invalidate();
  }

  // Recovery hand-off: the session is freshly user-verified, so generate at once.
  const fired = useRef(false);
  const { autoGenerate, onConsumeGenerate } = props;
  useEffect(() => {
    if (autoGenerate && !fired.current) {
      fired.current = true;
      onConsumeGenerate();
      void generate();
    }
  }, [autoGenerate, onConsumeGenerate, generate]);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Recovery codes</h2>
        </CardTitle>
        <CardDescription>
          Your only way back in if you lose every passkey. There is no email reset.
        </CardDescription>
        {newCodes ? null : (
          <CardAction>
            {hasCodes ? (
              <ConfirmDelete
                title="Regenerate recovery codes?"
                description={`This immediately invalidates your ${remaining} existing code${remaining === 1 ? "" : "s"}. You'll see a fresh set to save.`}
                confirmLabel="Regenerate"
                onConfirm={generate}
                trigger={
                  <Button size="sm" variant="outline" disabled={busy}>
                    Regenerate
                  </Button>
                }
              />
            ) : (
              <Button size="sm" onClick={() => void generate()} disabled={busy}>
                Generate
              </Button>
            )}
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        {/* Always-mounted, non-secret live region so generation is announced. */}
        <div className="sr-only" role="status" aria-live="polite">
          {announce}
        </div>
        {newCodes ? (
          <ShowOnceCodes codes={newCodes} onDone={dismiss} />
        ) : (
          <p className={hasCodes && !low ? "text-muted-foreground text-xs" : "text-destructive text-xs"}>
            {remaining === 0
              ? "You have no recovery codes. Generate a set and store them somewhere safe."
              : low
                ? `Only ${remaining} recovery code${remaining === 1 ? "" : "s"} left — regenerate a fresh set soon.`
                : `${remaining} unused recovery codes remaining.`}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
