import { Link, createRoute, useNavigate } from "@tanstack/react-router";

import { AuthCard } from "../components/AuthCard.js";
import { OtpEnrollFlow } from "../components/OtpEnrollFlow.js";
import { rootRoute } from "./root.js";

function SignUp() {
  const navigate = useNavigate();
  return (
    <AuthCard
      title="Create your account"
      description="Verify your email, then set up a passkey."
      footer={
        <>
          Already have an account?{" "}
          <Link to="/sign-in" className="text-primary underline">
            Sign in
          </Link>
        </>
      }
    >
      <OtpEnrollFlow
        startPath="/api/signup/start"
        verifyPath="/api/signup/verify"
        passkeyLabel="Create a passkey on this device to finish signing up."
        onComplete={() => void navigate({ to: "/account" })}
      />
    </AuthCard>
  );
}

export const signUpRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sign-up",
  component: SignUp,
});
