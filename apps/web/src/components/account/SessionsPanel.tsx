import { Badge } from "@eric-minassian/design/components/badge";
import { Button } from "@eric-minassian/design/components/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@eric-minassian/design/components/card";
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from "@eric-minassian/design/components/item";
import { MonitorSmartphoneIcon } from "lucide-react";
import { toast } from "sonner";

import { useAccountMutation } from "../../hooks/useAccountMutation.js";
import { api, type SessionListItem } from "../../lib/api.js";
import { Time } from "../Time.js";

/** A session touched within the last ~5 minutes is "active now". */
function isActiveNow(lastSeenSeconds: number): boolean {
  return Date.now() / 1000 - lastSeenSeconds < 5 * 60;
}

/** A non-current session created in the last 24h is flagged as a new device. */
function isNewDevice(s: SessionListItem): boolean {
  return !s.current && Date.now() / 1000 - s.created_at < 24 * 60 * 60;
}

/** Human label for a session's origin: "Chrome on macOS · US". */
function sessionOrigin(s: SessionListItem): string {
  return [s.device, s.region].filter(Boolean).join(" · ") || "Unknown device";
}

export function SessionsPanel(props: { sessions: SessionListItem[] }) {
  const { run, busy, isPending } = useAccountMutation();
  // Current session first, then most-recently-seen.
  const sessions = [...props.sessions].sort(
    (a, b) => Number(b.current) - Number(a.current) || b.last_seen_at - a.last_seen_at,
  );
  const others = sessions.filter((s) => !s.current);

  function revoke(id: string) {
    void run(`revoke:${id}`, () => api.del(`/api/account/sessions/${encodeURIComponent(id)}`), {
      success: "Session revoked",
      error: "Could not revoke session",
    });
  }

  function revokeOthers() {
    void run(
      "revoke-others",
      async () => {
        // One server-side sweep: a single rate token and a single audit
        // event, instead of a per-session loop that could rate-limit itself.
        const { revoked } = await api.post<{ ok: boolean; revoked: number }>(
          "/api/account/sessions/revoke-others",
        );
        toast.success(
          revoked === 1 ? "Signed out 1 other session" : `Signed out ${revoked} other sessions`,
        );
      },
      { error: "Could not sign out other sessions" },
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Active sessions</h2>
        </CardTitle>
        <CardDescription>Where you&apos;re currently signed in.</CardDescription>
        {others.length > 0 ? (
          <CardAction>
            <Button
              size="sm"
              variant="outline"
              onClick={revokeOthers}
              disabled={busy}
            >
              Sign out everywhere else
            </Button>
          </CardAction>
        ) : null}
      </CardHeader>
      <CardContent>
        <ItemGroup>
          {sessions.map((s) => (
            <Item key={s.session_id} variant="outline">
              <ItemMedia variant="icon">
                <MonitorSmartphoneIcon />
              </ItemMedia>
              <ItemContent>
                <ItemTitle>
                  {sessionOrigin(s)}
                  {s.current ? (
                    <Badge variant="secondary">This device</Badge>
                  ) : isActiveNow(s.last_seen_at) ? (
                    <Badge variant="secondary">Active now</Badge>
                  ) : null}
                  {isNewDevice(s) ? <Badge variant="outline">New device</Badge> : null}
                  {s.amr.includes("recovery") ? <Badge variant="outline">Recovery</Badge> : null}
                </ItemTitle>
                <ItemDescription>
                  Started <Time at={s.created_at} /> · last seen <Time at={s.last_seen_at} />
                </ItemDescription>
              </ItemContent>
              {!s.current ? (
                <ItemActions>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => revoke(s.session_id)}
                    disabled={isPending(`revoke:${s.session_id}`)}
                  >
                    Revoke
                  </Button>
                </ItemActions>
              ) : null}
            </Item>
          ))}
        </ItemGroup>
      </CardContent>
    </Card>
  );
}
