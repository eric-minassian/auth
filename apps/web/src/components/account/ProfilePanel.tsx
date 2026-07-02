import { Avatar, AvatarFallback } from "@eric-minassian/design/components/avatar";
import { Button } from "@eric-minassian/design/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@eric-minassian/design/components/card";
import { Field, FieldDescription, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";

import { useAccountMutation } from "../../hooks/useAccountMutation.js";
import { api, type SessionInfo } from "../../lib/api.js";
import {
  signalAcceptedCredentials,
  signalCurrentUserDetails,
  withStepUp,
} from "../../lib/webauthn.js";
import { ConfirmDelete } from "../ConfirmDelete.js";
import { CopyField } from "../CopyField.js";
import { initials } from "../../lib/initials.js";

export function ProfilePanel(props: { session: SessionInfo }) {
  const { user } = props.session;
  const { run, busy, isPending } = useAccountMutation();
  const navigate = useNavigate();
  const [nickname, setNickname] = useState(user.nickname);
  const trimmed = nickname.trim();
  const nicknameDirty = trimmed !== user.nickname && trimmed.length > 0 && trimmed.length <= 64;

  function saveNickname() {
    void run(
      "nickname",
      async () => {
        await api.patch("/api/account", { nickname: trimmed });
        // Keep the passkey entries in this device's manager labeled with the
        // new name (best-effort WebAuthn Signal API).
        await signalCurrentUserDetails(user.user_id, trimmed);
      },
      { success: "Name updated", error: "Could not update your name" },
    );
  }

  function deleteAccount() {
    void run(
      "delete-account",
      async () => {
        // Irreversible, so the server requires a fresh WebAuthn assertion.
        await withStepUp(() => api.del("/api/account"));
        // Prune this account's passkeys from the local manager on the way out.
        await signalAcceptedCredentials(user.user_id, []);
        void navigate({ to: "/sign-in" });
      },
      { error: "Could not delete account", skipInvalidate: true },
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Profile</h2>
          </CardTitle>
          <CardDescription>Your identity. There is no email on this account.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <Avatar size="lg">
              <AvatarFallback>{initials(user.nickname)}</AvatarFallback>
            </Avatar>
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{user.nickname}</p>
              <p className="text-muted-foreground text-xs">
                Display name — shown to apps, never an identifier
              </p>
            </div>
          </div>
          <Field>
            <FieldLabel htmlFor="nickname">Display name</FieldLabel>
            <div className="flex gap-2">
              <Input
                id="nickname"
                value={nickname}
                maxLength={64}
                autoComplete="off"
                onChange={(e) => setNickname(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && nicknameDirty && !busy) saveNickname();
                }}
              />
              <Button
                size="sm"
                className="self-center"
                onClick={saveNickname}
                disabled={!nicknameDirty || busy}
              >
                {isPending("nickname") ? "Saving…" : "Save"}
              </Button>
            </div>
            <FieldDescription>
              Apps see the new name the next time they refresh your profile.
            </FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="sub">User ID (sub)</FieldLabel>
            <CopyField id="sub" value={user.user_id} label="User ID (sub)" />
            <FieldDescription>
              The stable identifier apps key your account on.
            </FieldDescription>
          </Field>
        </CardContent>
      </Card>

      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle>
            <h2>Danger zone</h2>
          </CardTitle>
          <CardDescription>
            Permanently delete your account, passkeys, and sessions. This cannot be undone.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ConfirmDelete
            title="Delete your account?"
            description="This permanently removes your account, passkeys, and sessions. This cannot be undone."
            confirmLabel="Delete account"
            onConfirm={deleteAccount}
            trigger={
              <Button variant="destructive" size="sm" disabled={busy}>
                Delete account
              </Button>
            }
          />
        </CardContent>
      </Card>
    </div>
  );
}
