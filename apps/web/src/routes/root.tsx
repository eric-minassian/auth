import { Toaster } from "@eric-minassian/design/components/sonner";
import { TooltipProvider } from "@eric-minassian/design/components/tooltip";
import { createRootRoute, Outlet } from "@tanstack/react-router";

/**
 * App shell. Centering is intentionally NOT here — auth screens center via the
 * `_centered` layout while the account shell is top-aligned and full-width. The
 * page background comes from the base layer (`body { bg-background }`).
 */
function RootLayout() {
  return (
    <TooltipProvider>
      <Outlet />
      <Toaster position="top-center" />
    </TooltipProvider>
  );
}

export const rootRoute = createRootRoute({ component: RootLayout });
