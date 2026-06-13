import { Toaster } from "@eric-minassian/design/components/sonner";
import { createRootRoute, Outlet } from "@tanstack/react-router";

function RootLayout() {
  return (
    <div className="bg-background text-foreground flex min-h-full flex-col items-center justify-center p-4">
      <Outlet />
      <Toaster position="top-center" />
    </div>
  );
}

export const rootRoute = createRootRoute({ component: RootLayout });
