import { Avatar, AvatarFallback } from "@eric-minassian/design/components/avatar";
import { Button } from "@eric-minassian/design/components/button";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@eric-minassian/design/components/empty";
import { Skeleton } from "@eric-minassian/design/components/skeleton";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@eric-minassian/design/components/tabs";
import { createRoute, redirect, useNavigate } from "@tanstack/react-router";
import {
  KeyRoundIcon,
  LifeBuoyIcon,
  LogOutIcon,
  type LucideIcon,
  MonitorSmartphoneIcon,
  ShieldCheckIcon,
  UserIcon,
} from "lucide-react";
import { useCallback } from "react";

import { OverviewPanel } from "../components/account/OverviewPanel.js";
import { PasskeysPanel } from "../components/account/PasskeysPanel.js";
import { ProfilePanel } from "../components/account/ProfilePanel.js";
import { RecoveryPanel } from "../components/account/RecoveryPanel.js";
import { SessionsPanel } from "../components/account/SessionsPanel.js";
import { useIsMobile } from "../hooks/useIsMobile.js";
import { useTitle } from "../hooks/useTitle.js";
import {
  api,
  ApiError,
  type PasskeyInfo,
  type RecoveryReadiness,
  type SessionInfo,
  type SessionListItem,
} from "../lib/api.js";
import { type AccountTab, parseAccountSearch } from "../lib/account-nav.js";
import { initials } from "../lib/initials.js";
import { getRecoveryReadiness } from "../lib/webauthn.js";
import { rootRoute } from "./root.js";

const NAV: { value: AccountTab; label: string; icon: LucideIcon }[] = [
  { value: "overview", label: "Overview", icon: ShieldCheckIcon },
  { value: "passkeys", label: "Passkeys", icon: KeyRoundIcon },
  { value: "recovery", label: "Recovery codes", icon: LifeBuoyIcon },
  { value: "sessions", label: "Sessions", icon: MonitorSmartphoneIcon },
  { value: "profile", label: "Profile", icon: UserIcon },
];

interface AccountLoaderData {
  passkeys: PasskeyInfo[];
  sessions: SessionListItem[];
  readiness: RecoveryReadiness;
}

function AccountPage() {
  useTitle("Account");
  const { session } = accountRoute.useRouteContext();
  const { passkeys, sessions, readiness } = accountRoute.useLoaderData();
  const { tab, generate } = accountRoute.useSearch();
  const navigate = useNavigate();
  const isMobile = useIsMobile();

  const activeTab: AccountTab = tab ?? "overview";

  const onTabChange = useCallback(
    (value: string) => {
      void navigate({
        to: "/account",
        search: (prev) => ({
          ...prev,
          tab: value === "overview" ? undefined : (value as AccountTab),
          generate: undefined,
        }),
        replace: true,
      });
    },
    [navigate],
  );

  const consumeGenerate = useCallback(() => {
    void navigate({
      to: "/account",
      search: (prev) => ({ ...prev, generate: undefined }),
      replace: true,
    });
  }, [navigate]);

  async function signOut() {
    await api.post("/api/session/logout").catch(() => undefined);
    void navigate({ to: "/sign-in" });
  }

  return (
    <main className="mx-auto w-full max-w-4xl px-4 py-8 sm:py-10">
      <header className="mb-6 flex items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <Avatar>
            <AvatarFallback>{initials(session.user.nickname)}</AvatarFallback>
          </Avatar>
          <div className="min-w-0">
            <h1 className="font-heading text-base font-medium">Account</h1>
            <p className="text-muted-foreground truncate text-xs">{session.user.nickname}</p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => void signOut()}>
          <LogOutIcon /> Sign out
        </Button>
      </header>

      <Tabs
        value={activeTab}
        onValueChange={onTabChange}
        orientation={isMobile ? "horizontal" : "vertical"}
      >
        <TabsList
          variant="line"
          className={isMobile ? "w-full justify-start overflow-x-auto" : "w-44 shrink-0"}
        >
          {NAV.map(({ value, label, icon: Icon }) => (
            <TabsTrigger key={value} value={value} className={isMobile ? "flex-none" : undefined}>
              <Icon />
              {label}
            </TabsTrigger>
          ))}
        </TabsList>

        <div className="min-w-0 flex-1 md:max-w-2xl">
          <TabsContent value="overview">
            <OverviewPanel readiness={readiness} sessionCount={sessions.length} />
          </TabsContent>
          <TabsContent value="passkeys">
            <PasskeysPanel passkeys={passkeys} session={session} />
          </TabsContent>
          <TabsContent value="recovery">
            <RecoveryPanel
              readiness={readiness}
              autoGenerate={activeTab === "recovery" && generate === true}
              onConsumeGenerate={consumeGenerate}
            />
          </TabsContent>
          <TabsContent value="sessions">
            <SessionsPanel sessions={sessions} />
          </TabsContent>
          <TabsContent value="profile">
            <ProfilePanel session={session} />
          </TabsContent>
        </div>
      </Tabs>
    </main>
  );
}

function AccountPending() {
  return (
    <main className="mx-auto w-full max-w-4xl px-4 py-8 sm:py-10">
      <div className="mb-6 flex items-center gap-3">
        <Skeleton className="size-8 rounded-full" />
        <div className="flex flex-col gap-1.5">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-3 w-32" />
        </div>
      </div>
      <div className="flex flex-col gap-4 md:flex-row">
        <Skeleton className="h-40 w-full md:w-44 md:shrink-0" />
        <Skeleton className="h-64 w-full md:max-w-2xl" />
      </div>
    </main>
  );
}

function AccountError({ reset }: { error: Error; reset: () => void }) {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center p-4">
      <Empty className="max-w-sm">
        <EmptyHeader>
          <EmptyTitle>
            <h1>Couldn&apos;t load your account</h1>
          </EmptyTitle>
          <EmptyDescription>Something went wrong. Please try again.</EmptyDescription>
        </EmptyHeader>
        <EmptyContent>
          <Button size="sm" onClick={reset}>
            Retry
          </Button>
        </EmptyContent>
      </Empty>
    </main>
  );
}

export const accountRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/account",
  validateSearch: parseAccountSearch,
  beforeLoad: async () => {
    try {
      const session = await api.get<SessionInfo>("/api/session");
      return { session };
    } catch (e) {
      // Only an auth failure means "not signed in" — bounce to sign-in. Any
      // other failure (500, network) should surface, not masquerade as logout.
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
        throw redirect({ to: "/sign-in" });
      }
      throw e;
    }
  },
  loader: async (): Promise<AccountLoaderData> => {
    const [passkeys, sessions, readiness] = await Promise.all([
      api.get<{ passkeys: PasskeyInfo[] }>("/api/account/passkeys"),
      api.get<{ sessions: SessionListItem[] }>("/api/account/sessions"),
      getRecoveryReadiness(),
    ]);
    return { passkeys: passkeys.passkeys, sessions: sessions.sessions, readiness };
  },
  component: AccountPage,
  pendingComponent: AccountPending,
  errorComponent: AccountError,
});
