#!/usr/bin/env bash
# Local dry run of .github/workflows/hunt.yml: the same ci-steps.sh steps, in the same order.
#
#   tools/hunter/ci-local.sh          offline: canned paper + canned model reply (no key, no Muse call),
#                                     but REAL sandbox runs against every guard; writes to a temp dir only
#   tools/hunter/ci-local.sh --real   same, with a real arXiv search and real Muse calls (still a temp dir)
#
# It first checks that the workflow still calls exactly these steps, so the two cannot drift apart.
set -euo pipefail
cd "$(dirname "$0")/../.."
WF=.github/workflows/hunt.yml
TMP="$(mktemp -d "${TMPDIR:-/tmp}/arena-ci-local.XXXXXX")"

expected="build test hunt collect"
actual=$(grep -oE "tools/hunter/ci-steps\.sh [a-z]+" "$WF" | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')
if [ "$actual" != "$expected" ]; then
  echo "WORKFLOW DRIFT: $WF calls [$actual], ci-local runs [$expected]" >&2; exit 1
fi
echo "workflow steps match: $actual"

export HUNT_OUT_DIR="$TMP/evidence/hunts" HUNT_BOARD_OUT="$TMP/site" HUNT_ARTIFACT_DIR="$TMP/artifact" HUNT_NO_SAVE=1
export HUNT_DAYS=7 HUNT_MAX_PAPERS=5 HUNT_JOBS=4 HUNT_PAPER=""
if [ "${1:-}" != "--real" ]; then
  export HUNT_OFFLINE_REPLIES=tools/hunter/tests/fixtures/replies.json HUNT_PAPERS_FILE=tools/hunter/tests/fixtures/papers.json
fi
mkdir -p "$HUNT_OUT_DIR"

for s in $expected; do
  echo "== ci-steps.sh $s"
  bash tools/hunter/ci-steps.sh "$s"
done
echo "ci-local: ok. Artifact: $HUNT_ARTIFACT_DIR"
ls "$HUNT_ARTIFACT_DIR" "$HUNT_ARTIFACT_DIR/evidence/hunts" | head -20
