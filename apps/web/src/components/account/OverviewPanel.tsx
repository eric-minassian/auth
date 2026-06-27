import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@eric-minassian/design/components/card";

import type { RecoveryReadiness } from "../../lib/api.js";
import { SecurityCheckup } from "../SecurityCheckup.js";

/** The default /account tab: an at-a-glance account-security checkup. */
export function OverviewPanel(props: { readiness: RecoveryReadiness; sessionCount: number }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <h2>Account health</h2>
        </CardTitle>
        <CardDescription>
          A quick check of what keeps your account secure and recoverable.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <SecurityCheckup
          passkeyCount={props.readiness.passkey_count}
          recoveryRemaining={props.readiness.recovery_codes_remaining}
          sessionCount={props.sessionCount}
        />
      </CardContent>
    </Card>
  );
}
