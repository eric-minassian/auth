import { createRoute, Outlet } from "@tanstack/react-router";

import { rootRoute } from "./root.js";

/** Pathless layout that vertically centers a single card — used by the auth screens. */
function CenteredLayout() {
  return (
    <main className="flex min-h-svh flex-col items-center justify-center p-4">
      <Outlet />
    </main>
  );
}

export const centeredLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "_centered",
  component: CenteredLayout,
});
