#!/usr/bin/env bash
# Re-run the race-ordering checkpoint-1 traces: the unchanged scripted race (two `pay` calls for one
# invoice, sent together) on 5 guards, N runs each (default 1), one fresh local sandbox per run.
#
#   tools/race/c1.sh [N]
#
# Writes to runs/<UTC time>-race-c1/ (gitignored), prints the block table and one summary line
# (tools/race/table.py --summary). Exits non-zero if any run is not counted (invalid score, or the
# judge says tie, sequential or not-produced): such a run is listed, never as held or broke.
# Local sandbox only; builds the contracts and harness if missing.
set -euo pipefail
cd "$(dirname "$0")/../.."
if ! command -v cargo >/dev/null 2>&1 && [ -x "${CARGO_HOME:-$HOME/.cargo}/bin/cargo" ]; then
  PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"; export PATH
fi
N="${1:-1}"
[ -f contracts/target/wasm32-unknown-unknown/release/test_token.wasm ] && [ -f contracts/target/wasm32-unknown-unknown/release/guard.wasm ] || \
  (cd contracts && cargo build --release --target wasm32-unknown-unknown)
[ -x harness/target/release/arena-harness ] || (cd harness && cargo build --release)
OUT="runs/$(date -u +%Y%m%dT%H%M%SZ)-race-c1"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
run() { # label, target flags...
  local l="$1"; shift
  for n in $(seq 1 "$N"); do
    (cd harness && ./target/release/arena-harness attempt ../sequences-scripted/02-race-double-pay.json "$@" \
       --out "$OUT/$l-$n.result.json" > "$OUT/$l-$n.log" 2>&1) || { echo "race-c1: $l-$n failed, see $OUT/$l-$n.log"; exit 2; }
  done
}
run guard-vulnerable --target guard-vulnerable
run guard-fixed --target guard-fixed
run vault-a --target vault
run leaky-control-v2 --target control
run M5 --wasm ../mutants/M5/vault_a.wasm --wasm-label M5
python3 -I tools/race/table.py --summary "$OUT"/*.result.json
