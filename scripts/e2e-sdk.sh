#!/usr/bin/env bash
# End-to-end test of the web SDK against the real service: provisions
# aws-emulator, starts the service on a free local port and runs
# sdk/web/test/e2e against it.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${AUTH_E2E_PORT:-18080}"
export AUTH_ISSUER="http://localhost:${PORT}"
export AUTH_LISTEN_ADDR="127.0.0.1:${PORT}"
export AUTH_ALLOWED_ORIGINS="http://localhost:5173"
export AUTH_CORS_ORIGINS="http://localhost:5173"
# shellcheck source=lib/provision-local.sh
source scripts/lib/provision-local.sh

cargo build -p auth-service
LOG="$(mktemp)"
target/debug/auth-service >"${LOG}" 2>&1 &
PID=$!
trap 'kill "${PID}" 2>/dev/null || true; rm -f "${LOG}"' EXIT

for _ in $(seq 1 60); do
  curl -fsS "${AUTH_ISSUER}/.well-known/oauth-authorization-server" >/dev/null 2>&1 && break
  kill -0 "${PID}" 2>/dev/null || { cat "${LOG}" >&2; exit 1; }
  sleep 1
done

cd sdk/web
AUTH_E2E_ISSUER="${AUTH_ISSUER}" AUTH_E2E_ORIGIN="http://localhost:5173" npx vitest run test/e2e
