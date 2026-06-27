import { Button } from "@eric-minassian/design/components/button";
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from "@eric-minassian/design/components/item";
import { Link } from "@tanstack/react-router";
import { CircleCheckIcon, TriangleAlertIcon } from "lucide-react";

import type { AccountTab } from "../lib/account-nav.js";

const LOW_RECOVERY_CODES = 3;

interface Row {
  tone: "ok" | "alert";
  title: string;
  description?: string;
  action?: { label: string; tab: AccountTab; generate?: boolean };
}

/**
 * A Google-Security-Checkup-style health panel: neutral rows for healthy facts,
 * destructive rows for the real lockout levers — each linking to its fix.
 */
export function SecurityCheckup(props: {
  passkeyCount: number;
  recoveryRemaining: number;
  sessionCount: number;
}) {
  const { passkeyCount, recoveryRemaining, sessionCount } = props;
  const rows: Row[] = [];

  // Passkeys — a single passkey is one lost device away from lockout.
  if (passkeyCount >= 2) {
    rows.push({ tone: "ok", title: `${passkeyCount} passkeys registered` });
  } else {
    rows.push({
      tone: "alert",
      title: "Add a second passkey",
      description: "With only one passkey, losing that device locks you out.",
      action: { label: "Add passkey", tab: "passkeys" },
    });
  }

  // Recovery codes — the only break-glass once every passkey is gone.
  if (recoveryRemaining === 0) {
    rows.push({
      tone: "alert",
      title: "No recovery codes",
      description: "Generate a set so you can get back in if you lose every passkey.",
      action: { label: "Generate", tab: "recovery", generate: true },
    });
  } else if (recoveryRemaining < LOW_RECOVERY_CODES) {
    rows.push({
      tone: "alert",
      title: `Only ${recoveryRemaining} recovery code${recoveryRemaining === 1 ? "" : "s"} left`,
      description: "Regenerate a fresh set soon.",
      // No `generate` here: regenerating destroys the remaining codes, so send
      // the user to the panel's confirmation rather than auto-invalidating.
      action: { label: "Regenerate", tab: "recovery" },
    });
  } else {
    rows.push({ tone: "ok", title: `${recoveryRemaining} unused recovery codes` });
  }

  rows.push({
    tone: "ok",
    title: `${sessionCount} active ${sessionCount === 1 ? "session" : "sessions"}`,
  });

  return (
    <ItemGroup>
      {rows.map((row) => (
        <Item key={row.title} variant="muted" size="sm">
          <ItemMedia
            variant="icon"
            className={row.tone === "alert" ? "text-destructive" : "text-muted-foreground"}
          >
            {row.tone === "alert" ? <TriangleAlertIcon /> : <CircleCheckIcon />}
          </ItemMedia>
          <ItemContent>
            <ItemTitle>{row.title}</ItemTitle>
            {row.description ? <ItemDescription>{row.description}</ItemDescription> : null}
          </ItemContent>
          {row.action ? (
            <ItemActions>
              <Button size="sm" variant={row.tone === "alert" ? "default" : "outline"} asChild>
                <Link
                  to="/account"
                  search={(prev) => ({
                    ...prev,
                    tab: row.action?.tab,
                    generate: row.action?.generate,
                  })}
                >
                  {row.action.label}
                </Link>
              </Button>
            </ItemActions>
          ) : null}
        </Item>
      ))}
    </ItemGroup>
  );
}
