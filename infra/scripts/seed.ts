/**
 * Seeds the OIDC client registry (config/clients.json) into the DynamoDB
 * single table, in the item shape the Rust store reads
 * (PK=CLIENT#<id>, SK=CLIENT, flattened OidcClient fields).
 *
 * Resolves the table name from TABLE_NAME, or by describing the
 * `auth-stateful` CloudFormation stack's `TableName` output.
 *
 * Run: `pnpm --filter infra exec tsx scripts/seed.ts`
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CloudFormationClient, DescribeStacksCommand } from "@aws-sdk/client-cloudformation";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";

interface OidcClient {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  backchannel_logout_uri?: string;
  allowed_origins?: string[];
  scopes: string[];
}

const region = process.env.AWS_REGION ?? "us-east-1";

async function resolveTableName(): Promise<string> {
  if (process.env.TABLE_NAME) return process.env.TABLE_NAME;
  const cfn = new CloudFormationClient({ region });
  const { Stacks } = await cfn.send(new DescribeStacksCommand({ StackName: "auth-stateful" }));
  const output = Stacks?.[0]?.Outputs?.find((o) => o.OutputKey === "TableName");
  if (!output?.OutputValue) {
    throw new Error("could not resolve TableName from the auth-stateful stack");
  }
  return output.OutputValue;
}

async function main(): Promise<void> {
  // infra/scripts → repo root is two levels up.
  const here = dirname(fileURLToPath(import.meta.url));
  const raw = readFileSync(join(here, "..", "..", "config", "clients.json"), "utf8");
  const { clients } = JSON.parse(raw) as { clients: OidcClient[] };

  const tableName = await resolveTableName();
  const doc = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

  for (const client of clients) {
    await doc.send(
      new PutCommand({
        TableName: tableName,
        Item: {
          PK: `CLIENT#${client.client_id}`,
          SK: "CLIENT",
          client_id: client.client_id,
          client_name: client.client_name,
          redirect_uris: client.redirect_uris,
          post_logout_redirect_uris: client.post_logout_redirect_uris ?? [],
          // Optional: SPAs without a server (e.g. the static website client)
          // have no back-channel receiver. Omit rather than write `undefined`,
          // which the DynamoDB document client rejects.
          ...(client.backchannel_logout_uri
            ? { backchannel_logout_uri: client.backchannel_logout_uri }
            : {}),
          allowed_origins: client.allowed_origins ?? [],
          scopes: client.scopes,
        },
      }),
    );
    console.log(`seeded client ${client.client_id}`);
  }
  console.log(`done: ${clients.length} client(s) → ${tableName}`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
