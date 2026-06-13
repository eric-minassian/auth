#!/usr/bin/env bash
# Boots DynamoDB Local (docker) then the Rust dev API in the foreground so
# Playwright's webServer can manage its lifecycle. Run from the repo root.
set -euo pipefail
cd "$(dirname "$0")/../../.."

docker compose up -d

# Wait for DynamoDB Local to accept connections.
for _ in $(seq 1 30); do
  if curl -s -o /dev/null http://127.0.0.1:8000; then break; fi
  sleep 1
done

exec cargo run --quiet --bin local
