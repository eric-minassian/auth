import { Button } from "@eric-minassian/design/components/button";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@eric-minassian/design/components/empty";
import { createRoute, Link } from "@tanstack/react-router";

import { useTitle } from "../hooks/useTitle.js";
import { centeredLayoutRoute } from "./_centered.js";

interface ErrorSearch {
  error?: string;
}

const MESSAGES: Record<string, string> = {
  invalid_client: "This application isn't recognized.",
  invalid_redirect_uri: "This application's redirect URL isn't allowed.",
  server_error: "Something went wrong on our end. Please try again.",
};

function ErrorPage() {
  useTitle("Can't sign you in");
  const { error } = errorRoute.useSearch();
  const message = (error && MESSAGES[error]) ?? "This sign-in request can't be completed.";
  return (
    <Empty className="max-w-sm">
      <EmptyHeader>
        <EmptyTitle>
          <h1>Can&apos;t sign you in</h1>
        </EmptyTitle>
        <EmptyDescription>{message}</EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Button size="sm" variant="outline" asChild>
          <Link to="/sign-in">Back to sign in</Link>
        </Button>
      </EmptyContent>
    </Empty>
  );
}

export const errorRoute = createRoute({
  getParentRoute: () => centeredLayoutRoute,
  path: "/error",
  validateSearch: (search: Record<string, unknown>): ErrorSearch => ({
    error: typeof search.error === "string" ? search.error : undefined,
  }),
  component: ErrorPage,
});
