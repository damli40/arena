#!/usr/bin/env bash
# The script step of action.yml (the GitHub Action). Also run locally by action-local.sh, so the
# local test exercises exactly these lines.
#
# Reads only environment variables (set by action.yml from the inputs):
#   ARENA_WASM (required), ARENA_CONFIG, ARENA_MAPPING, ARENA_FAIL_ON, ARENA_JOBS, MUSE_API_KEY,
#   ARENA_REPO_URL, ARENA_REPO_REF,
#   GITHUB_WORKSPACE, GITHUB_ACTION_PATH, GITHUB_STEP_SUMMARY, GITHUB_OUTPUT.
# Never fails on its own: it records the check's exit code in $GITHUB_OUTPUT (exit_code), so the
# report upload still runs; action.yml's last step turns that code into pass/fail.
#
# Exit codes of `arena check` (and so of exit_code):
#   0 = finished, nothing paid over the fail-on line
#   1 = finished, tokens were paid over the fail-on line
#   2 = could not finish (any other code is treated the same way)
set -uo pipefail

ARENA_HOME="${GITHUB_ACTION_PATH:?}"
WORK="${GITHUB_WORKSPACE:?}"
OUT="$WORK/arena-report"
: "${GITHUB_STEP_SUMMARY:=/dev/null}" "${GITHUB_OUTPUT:=/dev/null}"

out() { printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; }
meaning() {
  case "$1" in
    0) echo "0 = the check finished and nothing was paid over the fail-on line" ;;
    1) echo "1 = the check finished and tokens were paid over the fail-on line" ;;
    2) echo "2 = the check could not finish" ;;
    *) echo "$1 = unexpected; treated as 'the check could not finish'" ;;
  esac
}
give_up() {  # a problem before the check could start: record exit code 2 and stop
  echo "::error::$1"
  echo "arena check did not run: $1" >> "$GITHUB_STEP_SUMMARY"
  out exit_code 2; exit 0
}

# Find cargo/rustup without running any shell file from $HOME. rustup puts them in
# ${CARGO_HOME:-~/.cargo}/bin; we only add that folder to PATH, and only if they are not found
# already. (A job that ran untrusted code earlier could have changed anything in $HOME, PATH
# included; that is why the example workflow builds the guard in a separate job.)
if ! command -v rustup >/dev/null 2>&1 && [ -x "${CARGO_HOME:-$HOME/.cargo}/bin/rustup" ]; then
  PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"; export PATH
fi
command -v rustup >/dev/null 2>&1 || give_up "rustup not found. GitHub's ubuntu and macos runners include it; on a self-hosted runner install it from https://rustup.rs"

[ -n "${ARENA_WASM:-}" ] || give_up "the 'wasm' input is empty; pass the path to your guard's .wasm"
case "${ARENA_FAIL_ON:-beyond-policy}" in beyond-policy|against-intent|never) ;; *)
  give_up "fail-on must be beyond-policy, against-intent or never (got '${ARENA_FAIL_ON}')";;
esac
case "${ARENA_JOBS:-2}" in ''|*[!0-9]*|0) give_up "jobs must be a whole number of at least 1";; esac

# Install the exact toolchains Arena pins (rust-toolchain.toml in each folder): stable for the
# harness, 1.86.0 + wasm32-unknown-unknown for the contracts. Recent rustup no longer does this
# implicitly in every case, so it is asked for here.
for d in harness contracts; do
  (cd "$ARENA_HOME/$d" && rustup toolchain install >/dev/null 2>&1) || (cd "$ARENA_HOME/$d" && rustup show >/dev/null)
done

# The report links to Arena's docs at the exact Arena commit. GitHub is meant to pass the
# action's repo and ref (action.yml sets them), but a known runner issue
# (https://github.com/actions/runner/issues/2473) leaves them empty in composite actions. Then
# fall back to the folder GitHub unpacks the action into: .../_actions/<owner>/<repo>/<ref>.
# That layout is how the runner works today, not a documented promise, so only a 40-character
# commit SHA is accepted from it; otherwise the link stays a plain file path.
if [ -z "${ARENA_REPO_URL:-}" ] && [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  ref="$(basename "$ARENA_HOME")"; repo="$(basename "$(dirname "$ARENA_HOME")")"
  owner="$(basename "$(dirname "$(dirname "$ARENA_HOME")")")"
  parent="$(basename "$(dirname "$(dirname "$(dirname "$ARENA_HOME")")")")"
  if [ "$parent" = "_actions" ] && printf '%s' "$ref" | grep -Eq '^[0-9a-f]{40}$'; then
    ARENA_REPO_URL="https://github.com/$owner/$repo"; ARENA_REPO_REF="$ref"
  fi
fi
export ARENA_REPO_URL="${ARENA_REPO_URL:-}" ARENA_REPO_REF="${ARENA_REPO_REF:-}"

args=(check "$ARENA_WASM" --out "$OUT" --fail-on "${ARENA_FAIL_ON:-beyond-policy}" --jobs "${ARENA_JOBS:-2}")
[ -n "${ARENA_CONFIG:-}" ] && args+=(--config "$ARENA_CONFIG")
[ -n "${ARENA_MAPPING:-}" ] && args+=(--mapping "$ARENA_MAPPING")
[ -z "${MUSE_API_KEY:-}" ] && args+=(--no-muse)
export MUSE_API_KEY="${MUSE_API_KEY:-}"

# Only a report written by THIS run may reach the job summary and the step outputs. Delete any
# report files left from before, so "the file exists afterwards" means "this run wrote it".
rm -f "$OUT/summary.md" "$OUT/report.json" "$OUT/report.html" "$OUT/badge.svg" "$OUT/shields.json"

cd "$WORK"
ARENA_SUMMARY_BADGE=shields "$ARENA_HOME/arena" "${args[@]}"
code=$?
echo "arena check exit code: $(meaning "$code")"

if [ -f "$OUT/summary.md" ] && [ -f "$OUT/report.json" ]; then
  cat "$OUT/summary.md" >> "$GITHUB_STEP_SUMMARY"
  {
    echo ""
    echo "Exit code $(meaning "$code")."
    echo ""
    echo "The full report (report.html, report.json, badge.svg, shields.json, every attempt's log) is in this run's artifacts."
  } >> "$GITHUB_STEP_SUMMARY"
  # One line per value; newlines are removed so a value cannot add extra outputs.
  python3 -I - "$OUT/report.json" <<'PY' >> "$GITHUB_OUTPUT"
import json, sys
r = json.load(open(sys.argv[1]))
t = r.get("totals") or {}
one = lambda v: " ".join(str(v).split())
print(f"status={one(r.get('status', 'not-run'))}")
print(f"badge={one((r.get('badge') or {}).get('message', ''))}")
# full: true only for a green badge (held with nothing in the brackets but 0 not applicable and all 4 rules)
print(f"full={'true' if (r.get('badge') or {}).get('color') == 'brightgreen' else 'false'}")
print(f"beyond_policy={one(t.get('beyond_policy', ''))}")
print(f"against_intent={one(t.get('against_intent', ''))}")
PY
else
  echo "arena check wrote no report this run. Exit code $(meaning "$code")." >> "$GITHUB_STEP_SUMMARY"
  [ "$code" = 0 ] && code=2   # no report means we cannot say it passed
fi
out exit_code "$code"
exit 0
