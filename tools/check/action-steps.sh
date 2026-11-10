#!/usr/bin/env bash
# The script step of action.yml (the GitHub Action). Also run locally by action-local.sh, so the
# local test exercises exactly these lines.
#
# Reads only environment variables (set by action.yml from the inputs):
#   ARENA_WASM (required), ARENA_CONFIG, ARENA_MAPPING, ARENA_FAIL_ON, ARENA_JOBS, MUSE_API_KEY,
#   GITHUB_WORKSPACE, GITHUB_ACTION_PATH, GITHUB_STEP_SUMMARY, GITHUB_OUTPUT.
# Never fails on its own: it records the check's exit code in $GITHUB_OUTPUT (exit_code), so the
# report upload still runs; action.yml's last step turns that code into pass/fail.
set -uo pipefail

ARENA_HOME="${GITHUB_ACTION_PATH:?}"
WORK="${GITHUB_WORKSPACE:?}"
OUT="$WORK/arena-report"
: "${GITHUB_STEP_SUMMARY:=/dev/null}" "${GITHUB_OUTPUT:=/dev/null}"
source "$HOME/.cargo/env" 2>/dev/null || true

out() { printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; }

if ! command -v rustup >/dev/null 2>&1; then
  echo "::error::rustup not found. GitHub's ubuntu and macos runners include it; on a self-hosted runner install it from https://rustup.rs"
  out exit_code 2; exit 0
fi
# Install the exact toolchains Arena pins (rust-toolchain.toml in each folder): stable for the
# harness, 1.86.0 + wasm32-unknown-unknown for the contracts. Recent rustup no longer does this
# implicitly in every case, so it is asked for here.
for d in harness contracts; do
  (cd "$ARENA_HOME/$d" && rustup toolchain install >/dev/null 2>&1) || (cd "$ARENA_HOME/$d" && rustup show >/dev/null)
done

case "${ARENA_FAIL_ON:-beyond-policy}" in beyond-policy|against-intent|never) ;; *)
  echo "::error::fail-on must be beyond-policy, against-intent or never (got '${ARENA_FAIL_ON}')"; out exit_code 2; exit 0;;
esac
case "${ARENA_JOBS:-2}" in ''|*[!0-9]*) echo "::error::jobs must be a whole number"; out exit_code 2; exit 0;; esac

args=(check "$ARENA_WASM" --out "$OUT" --fail-on "${ARENA_FAIL_ON:-beyond-policy}" --jobs "${ARENA_JOBS:-2}")
[ -n "${ARENA_CONFIG:-}" ] && args+=(--config "$ARENA_CONFIG")
[ -n "${ARENA_MAPPING:-}" ] && args+=(--mapping "$ARENA_MAPPING")
[ -z "${MUSE_API_KEY:-}" ] && args+=(--no-muse)
export MUSE_API_KEY

cd "$WORK"
ARENA_SUMMARY_BADGE=shields "$ARENA_HOME/arena" "${args[@]}"
code=$?

if [ -f "$OUT/summary.md" ]; then
  cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
  echo "" >> "$GITHUB_STEP_SUMMARY"
  echo "The full report (report.html, report.json, badge.svg, shields.json, every attempt's log) is in this run's artifacts." >> "$GITHUB_STEP_SUMMARY"
  python3 -I - "$OUT/report.json" <<'PY' >> "$GITHUB_OUTPUT"
import json, sys
r = json.load(open(sys.argv[1]))
t = r.get("totals") or {}
print(f"status={r['status']}")
print(f"badge={r.get('badge', {}).get('message', '')}")
print(f"beyond_policy={t.get('beyond_policy', '')}")
print(f"against_intent={t.get('against_intent', '')}")
PY
else
  echo "arena check wrote no report (exit $code)." >> "$GITHUB_STEP_SUMMARY"
fi
out exit_code "$code"
exit 0
