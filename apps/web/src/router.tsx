import { Button } from "@eric-minassian/design/components/button";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@eric-minassian/design/components/empty";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { createRouter, Link } from "@tanstack/react-router";

import { accountRoute } from "./routes/account.js";
import { centeredLayoutRoute } from "./routes/_centered.js";
import { errorRoute } from "./routes/error.js";
import { indexRoute } from "./routes/index.js";
import { logoutRoute } from "./routes/logout.js";
import { recoverRoute } from "./routes/recover.js";
import { rootRoute } from "./routes/root.js";
import { signInRoute } from "./routes/sign-in.js";
import { signUpRoute } from "./routes/sign-up.js";

const routeTree = rootRoute.addChildren([
  indexRoute,
  centeredLayoutRoute.addChildren([
    signInRoute,
    signUpRoute,
    recoverRoute,
    logoutRoute,
    errorRoute,
  ]),
  accountRoute,
]);

function RouterPending() {
  return (
    <div className="flex min-h-svh items-center justify-center">
      <Spinner className="text-muted-foreground" />
    </div>
  );
}

function RouterError({ reset }: { error: Error; reset: () => void }) {
  return (
    <div className="flex min-h-svh flex-col items-center justify-center p-4">
      <Empty className="max-w-sm">
        <EmptyHeader>
          <EmptyTitle>Something went wrong</EmptyTitle>
          <EmptyDescription>An unexpected error occurred. Please try again.</EmptyDescription>
        </EmptyHeader>
        <EmptyContent className="flex-row justify-center gap-2">
          <Button size="sm" onClick={reset}>
            Retry
          </Button>
          <Button size="sm" variant="outline" asChild>
            <Link to="/sign-in">Sign in</Link>
          </Button>
        </EmptyContent>
      </Empty>
    </div>
  );
}

export const router = createRouter({
  routeTree,
  defaultPendingComponent: RouterPending,
  defaultErrorComponent: RouterError,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
