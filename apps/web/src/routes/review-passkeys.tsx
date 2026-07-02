import { Badge } from "@eric-minassian/design/components/badge";
import { Button } from "@eric-minassian/design/components/button";
import {
  Card,
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
import { createRoute, redirect, useNavigate, useRouter } from "@tanstack/react-router";
import { CheckIcon, KeyRoundIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDelete } from "../components/ConfirmDelete.js";
import { Time } from "../components/Time.js";
import { useTitle } from "../hooks/useTitle.js";
import { ApiError, api, type PasskeyInfo, type SessionInfo } from "../lib/api.js";
import { resumeAfterLogin } from "../lib/return-to.js";
import { describePasskeyError, signalAcceptedCredentials, withStepUp } from "../lib/webauthn.js";
import { centeredLayoutRoute } from "./_centered.js";

interface ReviewSearch {
  return_to?: string;
  /** Set when arriving from the recovery flow, to resume its code hand-off. */
  from?: "recovery";
}

/**
 * Post-recovery credential review. A redeemed recovery code proves the owner
 * is present, but every passkey that predates the recovery is suspect — the
 * lost or stolen device it lives on could still sign in. The server refuses
 * to authorize RPs until each surviving passkey has been explicitly kept or
 * removed here.
 */
function ReviewPasskeys() {
  useTitle("Review your passkeys");
  const navigate = useNavigate();
  const router = useRouter();
  const { return_to, from } = reviewPasskeysRoute.useSearch();
  const { session } = reviewPasskeysRoute.useRouteContext();
  const { passkeys } = reviewPasskeysRoute.useLoaderData();
  const [kept, setKept] = useState<ReadonlySet<string>>(new Set());
  const [pendingKey, setPendingKey] = useState<string | undefined>();
  const [finishing, setFinishing] = useState(false);

  const others = passkeys.filter((p) => !p.current);
  const allReviewed = others.every((p) => kept.has(p.credential_id));

  function keep(id: string) {
    setKept((prev) => new Set(prev).add(id));
  }

  async function remove(id: string) {
    setPendingKey(`remove:${id}`);
    try {
      await withStepUp(() =>
        api.del<{ ok: boolean; current_session_revoked: boolean }>(
          `/api/account/passkeys/${encodeURIComponent(id)}`,
        ),
      );
      toast.success("Passkey removed");
      // Reload the list; the removed entry disappears from `others`.
      await router.invalidate();
    } catch (e) {
      toast.error(describePasskeyError(e, "Could not remove passkey"));
    } finally {
      setPendingKey(undefined);
    }
  }

  async function done() {
    setFinishing(true);
    try {
      await api.post("/api/account/credential-review/complete");
      // Sync this device's passkey manager with the final accepted set.
      await signalAcceptedCredentials(
        session.user.user_id,
        passkeys.map((p) => p.credential_id),
      );
      if (return_to) {
        resumeAfterLogin(return_to);
        return;
      }
      if (from === "recovery") {
        // Resume the recovery hand-off: generate replacement codes now.
        void navigate({ to: "/account", search: { tab: "recovery", generate: true } });
        return;
      }
      void navigate({ to: "/account", search: {} });
    } catch (e) {
      toast.error(describePasskeyError(e, "Could not finish the review"));
      setFinishing(false);
    }
  }

  return (
    <Card className="w-full max-w-lg">
      <CardHeader>
        <CardTitle>
          <h1>Review your passkeys</h1>
        </CardTitle>
        <CardDescription>
          You recovered this account. Review each passkey that existed before —
          remove any you don&apos;t recognize; a lost or stolen device&apos;s passkey
          could still sign in.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <ItemGroup>
          {passkeys.map((passkey) => (
            <Item key={passkey.credential_id} variant="outline">
              <ItemMedia variant="icon">
                <KeyRoundIcon />
              </ItemMedia>
              <ItemContent>
                <ItemTitle>
                  {passkey.name}
                  {passkey.current ? (
                    <Badge variant="secondary">This device (new)</Badge>
                  ) : kept.has(passkey.credential_id) ? (
                    <Badge variant="outline">Kept</Badge>
                  ) : null}
                </ItemTitle>
                <ItemDescription>
                  Added <Time at={passkey.created_at} />
                  {passkey.last_used_at ? (
                    <>
                      {" · last used "}
                      <Time at={passkey.last_used_at} />
                    </>
                  ) : (
                    " · never used"
                  )}
                </ItemDescription>
              </ItemContent>
              {!passkey.current ? (
                <ItemActions>
                  {!kept.has(passkey.credential_id) ? (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => keep(passkey.credential_id)}
                      disabled={pendingKey !== undefined}
                    >
                      <CheckIcon /> Keep
                    </Button>
                  ) : null}
                  <ConfirmDelete
                    title="Remove this passkey?"
                    description="Anyone holding the device it lives on will no longer be able to sign in, and its sessions will be signed out."
                    confirmLabel="Remove"
                    onConfirm={() => void remove(passkey.credential_id)}
                    trigger={
                      <Button
                        size="icon-sm"
                        variant="ghost"
                        aria-label="Remove passkey"
                        disabled={pendingKey === `remove:${passkey.credential_id}`}
                      >
                        <Trash2Icon />
                      </Button>
                    }
                  />
                </ItemActions>
              ) : null}
            </Item>
          ))}
        </ItemGroup>
        {others.length === 0 ? (
          <p className="text-muted-foreground text-xs">
            No older passkeys remain — you&apos;re all set.
          </p>
        ) : null}
        <Button
          size="lg"
          className="w-full"
          onClick={() => void done()}
          disabled={!allReviewed || finishing || pendingKey !== undefined}
        >
          Done — continue
        </Button>
      </CardContent>
    </Card>
  );
}

export const reviewPasskeysRoute = createRoute({
  getParentRoute: () => centeredLayoutRoute,
  path: "/review-passkeys",
  validateSearch: (search: Record<string, unknown>): ReviewSearch => ({
    return_to: typeof search.return_to === "string" ? search.return_to : undefined,
    ...(search.from === "recovery" ? { from: "recovery" as const } : {}),
  }),
  beforeLoad: async ({ search }) => {
    try {
      const session = await api.get<SessionInfo>("/api/session");
      return { session };
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
        throw redirect({ to: "/sign-in", search: { return_to: search.return_to } });
      }
      throw e;
    }
  },
  loader: async () => {
    const { passkeys } = await api.get<{ passkeys: PasskeyInfo[] }>("/api/account/passkeys");
    return { passkeys };
  },
  component: ReviewPasskeys,
});
