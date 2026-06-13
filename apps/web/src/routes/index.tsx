import { createRoute, redirect } from "@tanstack/react-router";

import { api } from "../lib/api.js";
import { rootRoute } from "./root.js";

/** Bare `/` decides where to send the visitor based on session state. */
export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: async () => {
    const signedIn = await api
      .get("/api/session")
      .then(() => true)
      .catch(() => false);
    throw redirect({ to: signedIn ? "/account" : "/sign-in" });
  },
});
