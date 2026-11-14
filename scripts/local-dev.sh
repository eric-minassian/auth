#!/usr/bin/env bash
# Runs the auth service locally against aws-emulator: creates the DynamoDB
# table and the three KMS keys, then starts the service on
# http://localhost:8080 for a web app served from http://localhost:5173.
#
# The emulator keeps state in memory only, so every run starts clean.
set -euo pipefail
cd "$(dirname "$0")/.."
AUTH_TABLE_NAME="${AUTH_TABLE_NAME:-auth-local}"
# shellcheck source=lib/provision-local.sh
source scripts/lib/provision-local.sh
exec cargo run -p auth-service
