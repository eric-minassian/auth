import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@eric-minassian/design/components/alert-dialog";
import { Badge } from "@eric-minassian/design/components/badge";
import { Button } from "@eric-minassian/design/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@eric-minassian/design/components/card";
import { Empty, EmptyDescription, EmptyTitle } from "@eric-minassian/design/components/empty";
import {
  Item,
  ItemActions,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemTitle,
} from "@eric-minassian/design/components/item";
import { Skeleton } from "@eric-minassian/design/components/skeleton";
import { createRoute, redirect, useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { useCallback, useEffect, useState } from "react";

import {
  api,
  ApiError,
  type PasskeyInfo,
  type RecoveryReadiness,
  type SessionInfo,
  type SessionListItem,
} from "../lib/api.js";
import {
  generateRecoveryCodes,
  getRecoveryReadiness,
  registerPasskey,
  withStepUp,
} from "../lib/webauthn.js";
import { rootRoute } from "./root.js";

function formatDate(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString();
}

function Account() {
  const navigate = useNavigate();
  const [session, setSession] = useState<SessionInfo>();
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>();
  const [sessions, setSessions] = useState<SessionListItem[]>();
  const [readiness, setReadiness] = useState<RecoveryReadiness>();
  // Newly generated recovery codes, shown exactly once.
  const [newCodes, setNewCodes] = useState<string[]>();
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [s, p, sess, r] = await Promise.all([
      api.get<SessionInfo>("/api/session"),
      api.get<{ passkeys: PasskeyInfo[] }>("/api/account/passkeys"),
      api.get<{ sessions: SessionListItem[] }>("/api/account/sessions"),
      getRecoveryReadiness(),
    ]);
    setSession(s);
    setPasskeys(p.passkeys);
    setSessions(sess.sessions);
    setReadiness(r);
  }, []);

  useEffect(() => {
    void load().catch(() => navigate({ to: "/sign-in" }));
  }, [load, navigate]);

  async function addPasskey() {
    setBusy(true);
    try {
      // Adding a passkey from a non-fresh session requires a step-up assertion.
      await withStepUp(() => registerPasskey());
      toast.success("Passkey added");
      await load();
    } catch {
      toast.error("Could not add a passkey");
    } finally {
      setBusy(false);
    }
  }

  async function generateCodes() {
    setBusy(true);
    try {
      const codes = await generateRecoveryCodes();
      setNewCodes(codes);
      await load();
    } catch {
      toast.error("Could not generate recovery codes");
    } finally {
      setBusy(false);
    }
  }

  async function deletePasskey(id: string) {
    try {
      await api.del(`/api/account/passkeys/${encodeURIComponent(id)}`);
      toast.success("Passkey removed");
      await load();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not remove passkey");
    }
  }

  async function revokeSession(id: string) {
    await api.del(`/api/account/sessions/${encodeURIComponent(id)}`);
    toast.success("Session revoked");
    await load();
  }

  async function signOut() {
    await api.post("/api/session/logout");
    navigate({ to: "/sign-in" });
  }

  async function deleteAccount() {
    await api.del("/api/account");
    navigate({ to: "/sign-in" });
  }

  const onlyOnePasskey = (readiness?.passkey_count ?? 0) < 2;
  const noRecoveryCodes = (readiness?.recovery_codes_remaining ?? 0) === 0;

  return (
    <div className="flex w-full max-w-xl flex-col gap-6 py-8">
      <header>
        <h1 className="text-2xl font-semibold">Account</h1>
        {session ? (
          <p className="text-muted-foreground text-sm">{session.user.nickname}</p>
        ) : (
          <Skeleton className="mt-1 h-4 w-40" />
        )}
      </header>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Passkeys</CardTitle>
            <CardDescription>The devices you can sign in with.</CardDescription>
          </div>
          <Button size="sm" onClick={addPasskey} disabled={busy}>
            Add passkey
          </Button>
        </CardHeader>
        <CardContent>
          {onlyOnePasskey && passkeys !== undefined ? (
            <p className="text-muted-foreground mb-3 text-sm">
              Add a second passkey (e.g. on another device) so losing one never locks you out.
            </p>
          ) : null}
          {passkeys === undefined ? (
            <Skeleton className="h-16 w-full" />
          ) : passkeys.length === 0 ? (
            <Empty>
              <EmptyTitle>No passkeys</EmptyTitle>
              <EmptyDescription>Add one to keep access to your account.</EmptyDescription>
            </Empty>
          ) : (
            <ItemGroup>
              {passkeys.map((passkey) => (
                <Item key={passkey.credential_id} variant="outline">
                  <ItemContent>
                    <ItemTitle>{passkey.name}</ItemTitle>
                    <ItemDescription>
                      Added {formatDate(passkey.created_at)}
                      {passkey.last_used_at
                        ? ` · last used ${formatDate(passkey.last_used_at)}`
                        : " · never used"}
                    </ItemDescription>
                  </ItemContent>
                  <ItemActions>
                    <ConfirmDelete
                      title="Remove this passkey?"
                      description="You won't be able to sign in with this device anymore."
                      disabled={passkeys.length <= 1}
                      onConfirm={() => deletePasskey(passkey.credential_id)}
                    />
                  </ItemActions>
                </Item>
              ))}
            </ItemGroup>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Recovery codes</CardTitle>
            <CardDescription>
              Your only way back in if you lose every passkey. There is no email reset.
            </CardDescription>
          </div>
          <Button size="sm" variant={noRecoveryCodes ? "default" : "outline"} onClick={generateCodes} disabled={busy}>
            {readiness && readiness.recovery_codes_remaining > 0 ? "Regenerate" : "Generate"}
          </Button>
        </CardHeader>
        <CardContent>
          {newCodes ? (
            <div className="flex flex-col gap-3">
              <p className="text-sm font-medium">
                Save these now — they're shown only once and replace any previous codes.
              </p>
              <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-sm leading-6">
                {newCodes.join("\n")}
              </pre>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    void navigator.clipboard
                      .writeText(newCodes.join("\n"))
                      .then(() => toast.success("Copied"));
                  }}
                >
                  Copy
                </Button>
                <Button size="sm" onClick={() => setNewCodes(undefined)}>
                  I've saved them
                </Button>
              </div>
            </div>
          ) : readiness === undefined ? (
            <Skeleton className="h-6 w-48" />
          ) : (
            <p className="text-muted-foreground text-sm">
              {readiness.recovery_codes_remaining > 0
                ? `${readiness.recovery_codes_remaining} unused recovery code${readiness.recovery_codes_remaining === 1 ? "" : "s"} remaining.`
                : "You have no recovery codes. Generate a set and store them somewhere safe."}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Active sessions</CardTitle>
          <CardDescription>Where you're currently signed in.</CardDescription>
        </CardHeader>
        <CardContent>
          {sessions === undefined ? (
            <Skeleton className="h-16 w-full" />
          ) : (
            <ItemGroup>
              {sessions.map((s) => (
                <Item key={s.session_id} variant="outline">
                  <ItemContent>
                    <ItemTitle className="flex items-center gap-2">
                      Session
                      {s.current ? <Badge variant="secondary">This device</Badge> : null}
                    </ItemTitle>
                    <ItemDescription>
                      Started {formatDate(s.created_at)} · last seen {formatDate(s.last_seen_at)}
                    </ItemDescription>
                  </ItemContent>
                  {!s.current ? (
                    <ItemActions>
                      <Button size="sm" variant="outline" onClick={() => void revokeSession(s.session_id)}>
                        Revoke
                      </Button>
                    </ItemActions>
                  ) : null}
                </Item>
              ))}
            </ItemGroup>
          )}
        </CardContent>
      </Card>

      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle>Danger zone</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Button variant="outline" onClick={() => void signOut()}>
            Sign out
          </Button>
          <ConfirmDelete
            trigger={<Button variant="destructive">Delete account</Button>}
            title="Delete your account?"
            description="This permanently removes your account, passkeys, and sessions. This cannot be undone."
            onConfirm={deleteAccount}
          />
        </CardContent>
      </Card>
    </div>
  );
}

function ConfirmDelete(props: {
  title: string;
  description: string;
  onConfirm: () => Promise<void>;
  disabled?: boolean;
  trigger?: React.ReactNode;
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        {props.trigger ?? (
          <Button size="sm" variant="ghost" disabled={props.disabled}>
            Remove
          </Button>
        )}
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{props.title}</AlertDialogTitle>
          <AlertDialogDescription>{props.description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={() => void props.onConfirm()}>Confirm</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export const accountRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account",
  beforeLoad: async () => {
    const signedIn = await api
      .get("/api/session")
      .then(() => true)
      .catch(() => false);
    if (!signedIn) throw redirect({ to: "/sign-in" });
  },
  component: Account,
});
