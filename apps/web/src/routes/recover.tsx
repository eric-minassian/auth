import { Link, createRoute, useNavigate } from "@tanstack/react-router";

import { AuthCard } from "../components/AuthCard.js";
import { OtpEnrollFlow } from "../components/OtpEnrollFlow.js";
import { rootRoute } from "./root.js";

function Recover() {
  const navigate = useNavigate();
  return (
    <AuthCard
      title="Recover your account"
      description="Verify your email to register a new passkey."
      footer={
        <Link to="/sign-in" className="text-primary underline">
          Back to sign in
        </Link>
      }
    >
      <OtpEnrollFlow
        startPath="/api/recovery/start"
        verifyPath="/api/recovery/verify"
        passkeyLabel="Register a new passkey on this device to regain access."
        onComplete={() => void navigate({ to: "/account" })}
      />
    </AuthCard>
  );
}

export const recoverRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/recover",
  component: Recover,
});
