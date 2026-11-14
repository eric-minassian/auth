#!/usr/bin/env bash
# Runs the auth service locally against aws-emulator: creates the DynamoDB
# table and the three KMS keys, then starts the service on
# http://localhost:8080 for a web app served from http://localhost:5173.
#
# The emulator keeps state in memory only, so every run starts clean.
set -euo pipefail
cd "$(dirname "$0")/.."

eval "$(scripts/emulator.sh)"

TABLE="auth-local"
if ! aws dynamodb describe-table --table-name "${TABLE}" >/dev/null 2>&1; then
  aws dynamodb create-table --table-name "${TABLE}" \
    --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
    --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST >/dev/null
  aws dynamodb wait table-exists --table-name "${TABLE}"
  aws dynamodb update-time-to-live --table-name "${TABLE}" \
    --time-to-live-specification Enabled=true,AttributeName=ttl >/dev/null
fi

key() { aws kms create-key --key-spec "$1" --key-usage "$2" --description "auth local $3" --query KeyMetadata.KeyId --output text; }

export AUTH_ISSUER="${AUTH_ISSUER:-http://localhost:8080}"
export AUTH_RP_ID="${AUTH_RP_ID:-localhost}"
export AUTH_RP_NAME="${AUTH_RP_NAME:-Local Dev}"
export AUTH_ALLOWED_ORIGINS="${AUTH_ALLOWED_ORIGINS:-http://localhost:5173}"
export AUTH_CORS_ORIGINS="${AUTH_CORS_ORIGINS:-http://localhost:5173}"
export AUTH_AUDIENCES="${AUTH_AUDIENCES:-http://localhost:9000}"
export AUTH_CLIENT_IDS="${AUTH_CLIENT_IDS:-web,ios,android,cli}"
export AUTH_TABLE_NAME="${TABLE}"
export AUTH_ACCESS_TOKEN_KEY_ID="$(key ECC_NIST_P256 SIGN_VERIFY access-token)"
export AUTH_REFRESH_TOKEN_KEY_ID="$(key ECC_NIST_P256 SIGN_VERIFY refresh-token)"
export AUTH_DPOP_NONCE_KEY_ID="$(key HMAC_256 GENERATE_VERIFY_MAC dpop-nonce)"
export AUTH_LISTEN_ADDR="${AUTH_LISTEN_ADDR:-127.0.0.1:8080}"
export RUST_LOG="${RUST_LOG:-info}"

exec cargo run -p auth-service
