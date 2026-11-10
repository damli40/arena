#!/usr/bin/env bash
# Local dry run of the GitHub Action's script steps (action.yml), on this machine.
#
#   tools/check/action-local.sh [wasm] [extra env, e.g. ARENA_FAIL_ON=never]
#
# Fakes the variables GitHub sets (GITHUB_ACTION_PATH, GITHUB_WORKSPACE, GITHUB_STEP_SUMMARY,
# GITHUB_OUTPUT), runs tools/check/action-steps.sh exactly as action.yml does, then applies the
# same fail-on rule as action.yml's last step. It does NOT run the Action on GitHub, the pinned
# third-party steps (setup-python, cache, upload-artifact), or Linux.
set -uo pipefail
ARENA_HOME="$(cd "$(dirname "$0")/../.." && pwd)"
WS="$(mktemp -d "${TMPDIR:-/tmp}/arena-action-ws.XXXXXX")"
mkdir -p "$WS/guard"
cp "${1:-$ARENA_HOME/targets/vault-a/vault_a.wasm}" "$WS/guard/guard.wasm"
export GITHUB_ACTION_PATH="$ARENA_HOME" GITHUB_WORKSPACE="$WS"
export GITHUB_STEP_SUMMARY="$WS/step-summary.md" GITHUB_OUTPUT="$WS/github-output.txt"
export ARENA_WASM="guard/guard.wasm" ARENA_FAIL_ON="${ARENA_FAIL_ON:-beyond-policy}" ARENA_JOBS="${ARENA_JOBS:-4}"
export ARENA_CONFIG="${ARENA_CONFIG:-}" ARENA_MAPPING="${ARENA_MAPPING:-}" MUSE_API_KEY=""
bash "$ARENA_HOME/tools/check/action-steps.sh"
echo "---- step returned $? (must be 0: it never fails on its own)"
echo "---- \$GITHUB_OUTPUT"; cat "$GITHUB_OUTPUT"
echo "---- \$GITHUB_STEP_SUMMARY"; cat "$GITHUB_STEP_SUMMARY"
echo "---- report files"; ls "$WS/arena-report"
code=$(sed -n 's/^exit_code=//p' "$GITHUB_OUTPUT" | tail -1)
case "${code:-2}" in 0) verdict="pass";; *) verdict="fail";; esac
echo "---- fail-on step would: $verdict (exit_code=$code, fail-on=$ARENA_FAIL_ON)"
echo "workspace: $WS"
