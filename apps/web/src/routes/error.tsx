import { Empty, EmptyDescription, EmptyTitle } from "@eric-minassian/design/components/empty";
import { createRoute } from "@tanstack/react-router";

import { rootRoute } from "./root.js";

interface ErrorSearch {
  error?: string;
}

const MESSAGES: Record<string, string> = {
  invalid_client: "This application isn't recognized.",
  invalid_redirect_uri: "This application's redirect URL isn't allowed.",
  server_error: "Something went wrong on our end. Please try again.",
};

function ErrorPage() {
  const { error } = errorRoute.useSearch();
  const message = (error && MESSAGES[error]) ?? "This sign-in request can't be completed.";
  return (
    <Empty className="max-w-sm">
      <EmptyTitle>Can't sign you in</EmptyTitle>
      <EmptyDescription>{message}</EmptyDescription>
    </Empty>
  );
}

export const errorRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/error",
  validateSearch: (search: Record<string, unknown>): ErrorSearch => ({
    error: typeof search.error === "string" ? search.error : undefined,
  }),
  component: ErrorPage,
});
