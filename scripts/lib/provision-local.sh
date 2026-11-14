# Sourced by local scripts: points the AWS SDK/CLI at aws-emulator, creates the
# DynamoDB table and the three KMS keys, and exports the service configuration.
# Override any AUTH_* variable before sourcing.

eval "$("$(dirname "${BASH_SOURCE[0]}")/../emulator.sh")"

AUTH_TABLE_NAME="${AUTH_TABLE_NAME:-auth-local-$(date +%s)-$$}"
if ! aws dynamodb describe-table --table-name "${AUTH_TABLE_NAME}" >/dev/null 2>&1; then
  aws dynamodb create-table --table-name "${AUTH_TABLE_NAME}" \
    --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
    --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST >/dev/null
  aws dynamodb wait table-exists --table-name "${AUTH_TABLE_NAME}"
  aws dynamodb update-time-to-live --table-name "${AUTH_TABLE_NAME}" \
    --time-to-live-specification Enabled=true,AttributeName=ttl >/dev/null
fi

_auth_key() {
  aws kms create-key --key-spec "$1" --key-usage "$2" --description "auth local $3" \
    --query KeyMetadata.KeyId --output text
}

export AUTH_TABLE_NAME
export AUTH_ISSUER="${AUTH_ISSUER:-http://localhost:8080}"
export AUTH_RP_ID="${AUTH_RP_ID:-localhost}"
export AUTH_RP_NAME="${AUTH_RP_NAME:-Local Dev}"
export AUTH_ALLOWED_ORIGINS="${AUTH_ALLOWED_ORIGINS:-http://localhost:5173}"
export AUTH_CORS_ORIGINS="${AUTH_CORS_ORIGINS:-http://localhost:5173}"
export AUTH_AUDIENCES="${AUTH_AUDIENCES:-http://localhost:9000}"
export AUTH_CLIENT_IDS="${AUTH_CLIENT_IDS:-web,ios,android,cli}"
export AUTH_ACCESS_TOKEN_KEY_ID="${AUTH_ACCESS_TOKEN_KEY_ID:-$(_auth_key ECC_NIST_P256 SIGN_VERIFY access-token)}"
export AUTH_REFRESH_TOKEN_KEY_ID="${AUTH_REFRESH_TOKEN_KEY_ID:-$(_auth_key ECC_NIST_P256 SIGN_VERIFY refresh-token)}"
export AUTH_DPOP_NONCE_KEY_ID="${AUTH_DPOP_NONCE_KEY_ID:-$(_auth_key HMAC_256 GENERATE_VERIFY_MAC dpop-nonce)}"
export AUTH_LISTEN_ADDR="${AUTH_LISTEN_ADDR:-127.0.0.1:8080}"
export RUST_LOG="${RUST_LOG:-info}"
