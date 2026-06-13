import { createRouter } from "@tanstack/react-router";

import { accountRoute } from "./routes/account.js";
import { errorRoute } from "./routes/error.js";
import { indexRoute } from "./routes/index.js";
import { logoutRoute } from "./routes/logout.js";
import { recoverRoute } from "./routes/recover.js";
import { rootRoute } from "./routes/root.js";
import { signInRoute } from "./routes/sign-in.js";
import { signUpRoute } from "./routes/sign-up.js";

const routeTree = rootRoute.addChildren([
  indexRoute,
  signInRoute,
  signUpRoute,
  recoverRoute,
  accountRoute,
  logoutRoute,
  errorRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
