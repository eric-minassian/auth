import { createRoute, redirect } from "@tanstack/react-router";

import { api, ApiError } from "../lib/api.js";
import { rootRoute } from "./root.js";

/** Bare `/` decides where to send the visitor based on session state. */
export const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: async () => {
    try {
      await api.get("/api/session");
    } catch (e) {
      // Only a real auth failure means "signed out". A transient 5xx/network
      // error should surface (router error UI), not masquerade as a logout.
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
        throw redirect({ to: "/sign-in" });
      }
      throw e;
    }
    throw redirect({ to: "/account" });
  },
});
