import { Alert, AlertDescription } from "@eric-minassian/design/components/alert";
import { Button } from "@eric-minassian/design/components/button";
import { Field, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@eric-minassian/design/components/input-otp";
import { Spinner } from "@eric-minassian/design/components/spinner";
import { useState } from "react";

import { api, ApiError } from "../lib/api.js";
import { registerPasskey } from "../lib/webauthn.js";

type Step = "email" | "otp" | "passkey";

export interface OtpEnrollFlowProps {
  startPath: string;
  verifyPath: string;
  /** Whether this is the very first passkey (sign-up) or a recovery. */
  passkeyLabel: string;
  onComplete: () => void;
}

export function OtpEnrollFlow(props: OtpEnrollFlowProps) {
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(undefined);
    try {
      await fn();
    } catch (e) {
      setError(
        e instanceof ApiError ? e.message : "Something went wrong. Please try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  const sendCode = () =>
    run(async () => {
      await api.post(props.startPath, { email });
      setStep("otp");
    });

  const verifyCode = () =>
    run(async () => {
      await api.post(props.verifyPath, { email, code });
      setStep("passkey");
    });

  const createPasskey = () =>
    run(async () => {
      await registerPasskey();
      props.onComplete();
    });

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {step === "email" ? (
        <>
          <Field>
            <FieldLabel htmlFor="email">Email</FieldLabel>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && email) sendCode();
              }}
            />
          </Field>
          <Button onClick={sendCode} disabled={busy || !email}>
            {busy ? <Spinner /> : null}
            Send code
          </Button>
        </>
      ) : null}

      {step === "otp" ? (
        <>
          <Field>
            <FieldLabel htmlFor="otp">Enter the 6-digit code sent to {email}</FieldLabel>
            <InputOTP id="otp" maxLength={6} value={code} onChange={setCode}>
              <InputOTPGroup>
                {[0, 1, 2, 3, 4, 5].map((i) => (
                  <InputOTPSlot key={i} index={i} />
                ))}
              </InputOTPGroup>
            </InputOTP>
          </Field>
          <Button onClick={verifyCode} disabled={busy || code.length !== 6}>
            {busy ? <Spinner /> : null}
            Verify
          </Button>
          <Button variant="ghost" onClick={() => setStep("email")} disabled={busy}>
            Use a different email
          </Button>
        </>
      ) : null}

      {step === "passkey" ? (
        <>
          <p className="text-muted-foreground text-sm">{props.passkeyLabel}</p>
          <Button onClick={createPasskey} disabled={busy}>
            {busy ? <Spinner /> : null}
            Create passkey
          </Button>
        </>
      ) : null}
    </div>
  );
}
