#!/usr/bin/env bash
# Starts aws-emulator (https://github.com/aws/aws-emulator) in the background if
# it is not already running, waits until it is healthy, and prints the
# environment variables that point the AWS SDK and CLI at it.
#
#   eval "$(scripts/emulator.sh)"          # shell
#   scripts/emulator.sh --github-env        # GitHub Actions ($GITHUB_ENV)
#
# Install the emulator first: https://docs.aws.amazon.com/ (package
# "aws-emulator", e.g. the .deb from downloads.aws.com/aws-emulator).
set -euo pipefail

PORT="${EMULATOR_PORT:-9297}"
HOME_DIR="${HOME}/.aws/emulator/${PORT}"
LOG="${TMPDIR:-/tmp}/aws-emulator-${PORT}.log"

if ! command -v aws-emulator >/dev/null 2>&1; then
  echo "aws-emulator is not installed" >&2
  exit 1
fi

healthy() {
  [[ -f "${HOME_DIR}/ca.pem" ]] &&
    curl -fsS --cacert "${HOME_DIR}/ca.pem" "https://127.0.0.1:${PORT}/__admin/health" >/dev/null 2>&1
}

if ! healthy; then
  nohup aws-emulator --telemetry off --port "${PORT}" --idle-timeout "${EMULATOR_IDLE_TIMEOUT:-3600}" >"${LOG}" 2>&1 &
  for _ in $(seq 1 60); do
    healthy && break
    sleep 1
  done
  healthy || { echo "aws-emulator did not become healthy; see ${LOG}" >&2; exit 1; }
fi

VARS=(
  "AWS_ENDPOINT_URL=https://127.0.0.1:${PORT}"
  "AWS_CONFIG_FILE=${HOME_DIR}/config"
  "AWS_SHARED_CREDENTIALS_FILE=${HOME_DIR}/emulator_credentials"
  "AWS_REGION=us-east-1"
  "SSL_CERT_FILE=${HOME_DIR}/ca.pem"
)
if [[ "${1:-}" == "--github-env" ]]; then
  printf '%s\n' "${VARS[@]}" >>"${GITHUB_ENV:?GITHUB_ENV is not set}"
else
  printf 'export %s\n' "${VARS[@]}"
  echo "unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN"
fi
