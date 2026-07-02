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
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@eric-minassian/design/components/empty";
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from "@eric-minassian/design/components/item";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@eric-minassian/design/components/tooltip";
import { KeyRoundIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useEffect } from "react";
import { toast } from "sonner";

import { useAccountMutation } from "../../hooks/useAccountMutation.js";
import { api, type PasskeyInfo, type SessionInfo } from "../../lib/api.js";
import { registerPasskey, signalAcceptedCredentials, withStepUp } from "../../lib/webauthn.js";
import { ConfirmDelete } from "../ConfirmDelete.js";
import { RenamePasskeyDialog } from "../RenamePasskeyDialog.js";
import { Time } from "../Time.js";

export function PasskeysPanel(props: { passkeys: PasskeyInfo[]; session: SessionInfo }) {
  const { passkeys, session } = props;
  const m = useAccountMutation();
  const onlyOne = passkeys.length < 2;

  // Keep this device's passkey manager in sync with the server's full list
  // (prunes ghost entries for passkeys removed elsewhere). Best-effort.
  const idsKey = passkeys.map((k) => k.credential_id).join(",");
  useEffect(() => {
    void signalAcceptedCredentials(session.user.user_id, idsKey ? idsKey.split(",") : []);
  }, [idsKey, session.user.user_id]);

  function add() {
    void m.run(
      "add",
      async () => {
        const result = await withStepUp(() => registerPasskey());
        if (result.discoverable === false) {
          toast.warning(
            "This device couldn't store a sign-in-ready passkey. Try a platform authenticator (Touch ID, Windows Hello, or a passkey manager).",
          );
        } else {
          toast.success("Passkey added");
        }
      },
      { error: "Could not add a passkey" },
    );
  }

  function rename(id: string, name: string) {
    void m.run(
      `rename:${id}`,
      () => api.patch(`/api/account/passkeys/${encodeURIComponent(id)}`, { name }),
      { success: "Passkey renamed", error: "Could not rename passkey" },
    );
  }

  function remove(id: string) {
    void m.run(
      `delete:${id}`,
      async () => {
        const result = await withStepUp(() =>
          api.del<{ ok: boolean; current_session_revoked: boolean }>(
            `/api/account/passkeys/${encodeURIComponent(id)}`,
          ),
        );
        // Deleting the passkey that signed this session in revokes the
        // session too — land on sign-in instead of a wall of 401s.
        if (result.current_session_revoked) {
          window.location.assign("/sign-in");
        }
      },
      { success: "Passkey removed", error: "Could not remove passkey" },
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Passkeys</h2>
        </CardTitle>
        <CardDescription>The devices you can sign in with.</CardDescription>
        <CardAction>
          <Button size="sm" onClick={add} disabled={m.busy}>
            <PlusIcon /> Add passkey
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {onlyOne ? (
          <p className="text-muted-foreground text-xs">
            Add a second passkey (e.g. on another device) so losing one never locks you out.
          </p>
        ) : null}
        {passkeys.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>No passkeys</EmptyTitle>
              <EmptyDescription>Add one to keep access to your account.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <ItemGroup>
            {passkeys.map((passkey) => (
              <Item key={passkey.credential_id} variant="outline">
                <ItemMedia variant="icon">
                  <KeyRoundIcon />
                </ItemMedia>
                <ItemContent>
                  <ItemTitle>
                    {passkey.name}
                    {passkey.backup_eligible === true ? (
                      <Badge variant="secondary">Synced</Badge>
                    ) : passkey.backup_eligible === false ? (
                      <Badge variant="outline">Device-bound</Badge>
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
                <ItemActions>
                  <RenamePasskeyDialog
                    currentName={passkey.name}
                    onSave={(name) => rename(passkey.credential_id, name)}
                    trigger={
                      <Button
                        size="icon-sm"
                        variant="ghost"
                        aria-label="Rename passkey"
                        disabled={m.isPending(`rename:${passkey.credential_id}`)}
                      >
                        <PencilIcon />
                      </Button>
                    }
                  />
                  {onlyOne ? (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="inline-flex">
                          <Button size="icon-sm" variant="ghost" disabled aria-label="Remove passkey">
                            <Trash2Icon />
                          </Button>
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>Add another passkey first</TooltipContent>
                    </Tooltip>
                  ) : (
                    <ConfirmDelete
                      title="Remove this passkey?"
                      description="You won't be able to sign in with this device anymore, and any sessions it signed in will be signed out."
                      confirmLabel="Remove"
                      onConfirm={() => remove(passkey.credential_id)}
                      trigger={
                        <Button
                          size="icon-sm"
                          variant="ghost"
                          aria-label="Remove passkey"
                          disabled={m.isPending(`delete:${passkey.credential_id}`)}
                        >
                          <Trash2Icon />
                        </Button>
                      }
                    />
                  )}
                </ItemActions>
              </Item>
            ))}
          </ItemGroup>
        )}
      </CardContent>
    </Card>
  );
}
