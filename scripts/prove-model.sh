#!/usr/bin/env bash
# Machine-check the Tamarin model of the protocol (model/auth.spthy).
#
# Runs two configurations and fails (non-zero exit) unless every lemma is
# verified:
#   1. default   -- security lemmas (all-traces) and executability lemmas
#                   (exists-trace) must all be "verified";
#   2. ATTACKS   -- attack / weakness witnesses (exists-trace) must all be
#                   "verified", i.e. Tamarin must find each attack trace.
# Any "falsified", "analysis incomplete" or wellformedness warning fails.
#
# Usage: scripts/prove-model.sh [--default-only | --attacks-only]
# Env:   TAMARIN (default: tamarin-prover), LOG_DIR (default: target/tamarin)

set -euo pipefail

cd "$(dirname "$0")/.."
MODEL=model/auth.spthy
TAMARIN=${TAMARIN:-tamarin-prover}
LOG_DIR=${LOG_DIR:-target/tamarin}
mkdir -p "$LOG_DIR"

if [[ -d "$HOME/.local/bin" ]]; then
  PATH="$HOME/.local/bin:$PATH"
fi

if ! command -v "$TAMARIN" >/dev/null 2>&1; then
  echo "error: $TAMARIN not found (install tamarin-prover >= 1.10 and maude)" >&2
  exit 2
fi

# Maude looks for prelude.maude next to its binary or in MAUDE_LIB; a
# symlinked maude binary needs MAUDE_LIB pointing at the real directory.
if [[ -z "${MAUDE_LIB:-}" ]] && command -v maude >/dev/null 2>&1; then
  maude_dir=$(dirname "$(readlink -f "$(command -v maude)")")
  if [[ -f "$maude_dir/prelude.maude" ]]; then
    export MAUDE_LIB="$maude_dir"
  fi
fi

mode=${1:-all}

# run NAME [extra tamarin args...]
run() {
  local name=$1; shift
  local log="$LOG_DIR/$name.log"
  local start end
  start=$(date +%s)
  echo "==> tamarin-prover --prove ${*:+$* }$MODEL   (log: $log)"
  local attempt rc
  for attempt in 1 2 3; do
    rc=0
    "$TAMARIN" --prove --derivcheck-timeout=120 "$@" "$MODEL" >"$log" 2>&1 || rc=$?
    # Tamarin 1.12 occasionally aborts right after loading the theory with
    # the GHC runtime error "<<loop>>" (no lemma has been analysed at that
    # point).  That is a crash, not a proof result: retry (at most twice).
    if [[ $rc -ne 0 ]] && grep -q '<<loop>>' "$log" && [[ $attempt -lt 3 ]]; then
      echo "    tamarin-prover crashed with <<loop>> before analysing any lemma; retrying"
      start=$(date +%s)
      continue
    fi
    break
  done
  if [[ $rc -ne 0 ]]; then
    echo "error: tamarin-prover exited with an error; see $log" >&2
    tail -n 40 "$log" >&2
    return 1
  fi
  end=$(date +%s)
  # Print the summary block.
  sed -n '/^summary of summaries:/,/^=\{10,\}/p' "$log"
  echo "    wall time: $((end - start)) s"

  local summary
  summary=$(sed -n '/^summary of summaries:/,/^=\{10,\}/p' "$log")
  if [[ -z "$summary" ]]; then
    echo "error: no summary in $log" >&2
    return 1
  fi
  local failed=0
  if grep -q "WARNING" <<<"$summary"; then
    echo "error: wellformedness warnings in $name run" >&2
    failed=1
  fi
  if grep -Eq "falsified|analysis incomplete" <<<"$summary"; then
    echo "error: some lemmas are not verified in $name run:" >&2
    grep -E "falsified|analysis incomplete" <<<"$summary" >&2
    failed=1
  fi
  local total verified
  total=$(grep -Ec '\((all-traces|exists-trace)\):' <<<"$summary" || true)
  verified=$(grep -Ec '\((all-traces|exists-trace)\): verified' <<<"$summary" || true)
  echo "    $verified/$total lemmas verified"
  if [[ "$total" -eq 0 || "$verified" -ne "$total" ]]; then
    failed=1
  fi
  return $failed
}

status=0
if [[ "$mode" != "--attacks-only" ]]; then
  run default || status=1
fi
if [[ "$mode" != "--default-only" ]]; then
  run attacks -D=ATTACKS || status=1
fi

if [[ $status -eq 0 ]]; then
  echo "OK: all lemmas verified"
else
  echo "FAILED: see logs in $LOG_DIR" >&2
fi
exit $status
