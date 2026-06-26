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
  signalAcceptedCredentials,
  withStepUp,
} from "../lib/webauthn.js";
import { rootRoute } from "./root.js";

// Below this many remaining codes, nudge the user to regenerate.
const LOW_RECOVERY_CODES = 3;
// Flag set by the recovery flow so the account page drops the user straight
// into generating a fresh set of codes (they just completed a UV assertion).
const POST_RECOVERY_FLAG = "ema_post_recovery";

function formatDate(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString();
}

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

const RECOVERY_FILE_HEADER =
  "auth.ericminassian.com recovery codes\nKeep these private. Each works once; they replace any previous set.\n\n";

/** Download the one-time codes as a local text file (no out-of-band channel). */
function downloadCodes(codes: string[]): void {
  const blob = new Blob([RECOVERY_FILE_HEADER + codes.join("\n") + "\n"], {
    type: "text/plain",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "recovery-codes.txt";
  link.click();
  URL.revokeObjectURL(url);
}

/** Open the browser print dialog with just the codes. */
function printCodes(codes: string[]): void {
  const frame = document.createElement("iframe");
  frame.style.position = "fixed";
  frame.style.right = "0";
  frame.style.bottom = "0";
  frame.style.width = "0";
  frame.style.height = "0";
  frame.style.border = "0";
  document.body.appendChild(frame);
  const doc = frame.contentDocument;
  if (doc) {
    const pre = doc.createElement("pre");
    pre.style.fontFamily = "monospace";
    pre.style.fontSize = "14px";
    pre.textContent = RECOVERY_FILE_HEADER + codes.join("\n");
    doc.body.appendChild(pre);
    frame.contentWindow?.focus();
    frame.contentWindow?.print();
  }
  setTimeout(() => frame.remove(), 1000);
}

function Account() {
  const navigate = useNavigate();
  const [session, setSession] = useState<SessionInfo>();
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>();
  const [sessions, setSessions] = useState<SessionListItem[]>();
  const [readiness, setReadiness] = useState<RecoveryReadiness>();
  // Newly generated recovery codes, shown exactly once.
  const [newCodes, setNewCodes] = useState<string[]>();
  // Gate dismissing the one-time codes behind an explicit acknowledgement.
  const [codesSaved, setCodesSaved] = useState(false);
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
    // Keep this device's passkey manager in sync with the server's full list.
    void signalAcceptedCredentials(
      s.user.user_id,
      p.passkeys.map((k) => k.credential_id),
    );
  }, []);

  const generateCodes = useCallback(async () => {
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
  }, [load]);

  useEffect(() => {
    void load()
      .then(() => {
        // Coming from a recovery: the session is freshly user-verified, so go
        // straight into generating replacement codes.
        if (sessionStorage.getItem(POST_RECOVERY_FLAG)) {
          sessionStorage.removeItem(POST_RECOVERY_FLAG);
          void generateCodes();
        }
      })
      .catch(() => navigate({ to: "/sign-in" }));
  }, [load, generateCodes, navigate]);

  async function addPasskey() {
    setBusy(true);
    try {
      // Adding a passkey from a non-fresh session requires a step-up assertion.
      const result = await withStepUp(() => registerPasskey());
      if (result.discoverable === false) {
        toast.warning(
          "This device couldn't store a sign-in-ready passkey. Try a platform authenticator (Touch ID, Windows Hello, or a passkey manager).",
        );
      } else {
        toast.success("Passkey added");
      }
      await load();
    } catch {
      toast.error("Could not add a passkey");
    } finally {
      setBusy(false);
    }
  }

  async function renamePasskey(id: string, current: string) {
    const name = window.prompt("Rename passkey", current)?.trim();
    if (!name || name === current) return;
    try {
      await api.patch(`/api/account/passkeys/${encodeURIComponent(id)}`, { name });
      await load();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not rename passkey");
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
    try {
      // Deletion is irreversible, so the server requires a fresh assertion.
      await withStepUp(() => api.del("/api/account"));
      // Prune this account's passkeys from the local manager on the way out.
      if (session) await signalAcceptedCredentials(session.user.user_id, []);
      navigate({ to: "/sign-in" });
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not delete account");
    }
  }

  const onlyOnePasskey = (readiness?.passkey_count ?? 0) < 2;
  const remainingCodes = readiness?.recovery_codes_remaining ?? 0;
  const noRecoveryCodes = remainingCodes === 0;
  const lowRecoveryCodes = remainingCodes > 0 && remainingCodes < LOW_RECOVERY_CODES;

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
                    <ItemTitle className="flex items-center gap-2">
                      {passkey.name}
                      {passkey.backup_eligible === true ? (
                        <Badge variant="secondary">Synced</Badge>
                      ) : passkey.backup_eligible === false ? (
                        <Badge variant="outline">Device-bound</Badge>
                      ) : null}
                    </ItemTitle>
                    <ItemDescription>
                      Added {formatDate(passkey.created_at)}
                      {passkey.last_used_at
                        ? ` · last used ${formatDate(passkey.last_used_at)}`
                        : " · never used"}
                    </ItemDescription>
                  </ItemContent>
                  <ItemActions>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => void renamePasskey(passkey.credential_id, passkey.name)}
                    >
                      Rename
                    </Button>
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
          <Button
            size="sm"
            variant={noRecoveryCodes || lowRecoveryCodes ? "default" : "outline"}
            onClick={() => void generateCodes()}
            disabled={busy}
          >
            {remainingCodes > 0 ? "Regenerate" : "Generate"}
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
              <div className="flex flex-wrap gap-2">
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
                <Button size="sm" variant="outline" onClick={() => downloadCodes(newCodes)}>
                  Download
                </Button>
                <Button size="sm" variant="outline" onClick={() => printCodes(newCodes)}>
                  Print
                </Button>
              </div>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={codesSaved}
                  onChange={(e) => setCodesSaved(e.target.checked)}
                />
                I've saved these codes somewhere safe
              </label>
              <Button
                size="sm"
                disabled={!codesSaved}
                onClick={() => {
                  setNewCodes(undefined);
                  setCodesSaved(false);
                }}
              >
                Done
              </Button>
            </div>
          ) : readiness === undefined ? (
            <Skeleton className="h-6 w-48" />
          ) : (
            <p
              className={
                lowRecoveryCodes || noRecoveryCodes
                  ? "text-destructive text-sm"
                  : "text-muted-foreground text-sm"
              }
            >
              {noRecoveryCodes
                ? "You have no recovery codes. Generate a set and store them somewhere safe."
                : lowRecoveryCodes
                  ? `Only ${remainingCodes} recovery code${remainingCodes === 1 ? "" : "s"} left — regenerate a fresh set soon.`
                  : `${remainingCodes} unused recovery codes remaining.`}
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
                    <ItemTitle className="flex flex-wrap items-center gap-2">
                      {sessionOrigin(s)}
                      {s.current ? (
                        <Badge variant="secondary">This device</Badge>
                      ) : isActiveNow(s.last_seen_at) ? (
                        <Badge variant="secondary">Active now</Badge>
                      ) : null}
                      {isNewDevice(s) ? <Badge variant="destructive">New device</Badge> : null}
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
