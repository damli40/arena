#!/usr/bin/env bash
# The paper hunt's CI steps. .github/workflows/hunt.yml calls exactly these, one per step, and
# tools/hunter/ci-local.sh runs the same ones locally. Keep the logic here, not in the YAML.
#
#   ci-steps.sh build      build the token, the guard and the harness (no-op when already built)
#   ci-steps.sh test       validator self-test, library validation, registry, unit tests
#   ci-steps.sh hunt       run one hunt (inputs from env, all validated here)
#   ci-steps.sh collect    copy the evidence + board into $HUNT_ARTIFACT_DIR for upload
#
# Inputs (env): HUNT_DAYS (1-365), HUNT_MAX_PAPERS (1-5), HUNT_PAPER (arXiv id or empty),
#   HUNT_JOBS (1-8), HUNT_OUT_DIR, HUNT_BOARD_OUT, HUNT_ARTIFACT_DIR, HUNT_OFFLINE_REPLIES,
#   HUNT_PAPERS_FILE, HUNT_NO_SAVE (1 = dry run). MUSE_API_KEY comes from the environment
#   (repo secret in CI) and is never echoed: `set -x` is never used in this file.
set -euo pipefail
cd "$(dirname "$0")/../.."
source "$HOME/.cargo/env" 2>/dev/null || true

step="${1:?usage: ci-steps.sh build|test|hunt|collect}"
OUT_DIR="${HUNT_OUT_DIR:-evidence/hunts}"
BOARD_OUT="${HUNT_BOARD_OUT:-site}"
ART="${HUNT_ARTIFACT_DIR:-hunt-artifact}"

int_in() { # $1 name, $2 value, $3 min, $4 max
  [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -ge "$3" ] && [ "$2" -le "$4" ] || { echo "bad $1: must be $3-$4" >&2; exit 2; }
}

case "$step" in
  build)
    [ -f contracts/target/wasm32-unknown-unknown/release/test_token.wasm ] && [ -f contracts/target/wasm32-unknown-unknown/release/guard.wasm ] || \
      (cd contracts && cargo build --release --target wasm32-unknown-unknown -p test-token -p guard)
    [ -x harness/target/release/arena-harness ] || (cd harness && cargo build --release)
    python3 -I tools/hunter/registry.py
    ;;
  test)
    python3 -I tools/hunter/validate.py --self-test
    python3 -I tools/hunter/validate.py
    python3 -I tools/hunter/registry.py
    python3 -I -m unittest discover -s tools/hunter/tests
    ;;
  hunt)
    DAYS="${HUNT_DAYS:-7}"; MAXP="${HUNT_MAX_PAPERS:-5}"; JOBS="${HUNT_JOBS:-4}"; PAPER="${HUNT_PAPER:-}"
    int_in HUNT_DAYS "$DAYS" 1 365; int_in HUNT_MAX_PAPERS "$MAXP" 1 5; int_in HUNT_JOBS "$JOBS" 1 8
    args=(--days "$DAYS" --max-papers "$MAXP" --jobs "$JOBS" --out-dir "$OUT_DIR" --board-out "$BOARD_OUT")
    if [ -n "$PAPER" ]; then
      [[ "$PAPER" =~ ^[0-9]{4}\.[0-9]{4,5}(v[0-9]+)?$ ]] || { echo "bad HUNT_PAPER: not an arXiv id" >&2; exit 2; }
      args+=(--paper "$PAPER")
    fi
    [ -n "${HUNT_OFFLINE_REPLIES:-}" ] && args+=(--offline-replies "$HUNT_OFFLINE_REPLIES")
    [ -n "${HUNT_PAPERS_FILE:-}" ] && args+=(--papers-file "$HUNT_PAPERS_FILE")
    [ "${HUNT_NO_SAVE:-0}" = "1" ] && args+=(--no-save)
    if [ -z "${HUNT_OFFLINE_REPLIES:-}" ] && [ -z "${MUSE_API_KEY:-}" ] && [ ! -f "$HOME/.config/arena/model.env" ]; then
      echo "MUSE_API_KEY is not set (add it as a repository secret); not hunting" >&2; exit 2
    fi
    mkdir -p "$OUT_DIR"
    # The same frozen-fingerprint checks every other mode gets, around the hunt.
    ./run-arena.sh hunt "${args[@]}"
    ;;
  collect)
    rm -rf "$ART"; mkdir -p "$ART/evidence" "$ART/site"
    cp -R "$OUT_DIR" "$ART/evidence/hunts"
    [ -f "$BOARD_OUT/board-data.json" ] && cp "$BOARD_OUT/board-data.json" "$BOARD_OUT/board.html" "$ART/site/" || true
    [ -d sequences-paper ] && cp -R sequences-paper "$ART/" || true
    # Never ship anything that looks like a key.
    if grep -rIl -E "MUSE_API_KEY=|Bearer [A-Za-z0-9._-]{12,}" "$ART" >/dev/null 2>&1; then
      echo "refusing to upload: something in the artifact looks like a secret" >&2; exit 1
    fi
    echo "artifact ready: $ART ($(find "$ART" -type f | wc -l | tr -d ' ') files)"
    ;;
  *) echo "unknown step $step" >&2; exit 2 ;;
esac
