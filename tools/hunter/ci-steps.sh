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
#   HUNT_PAPERS_FILE, HUNT_NO_SAVE (1 = dry run), HUNT_SOURCE (papers|news|all; default papers),
#   HUNT_NEWS_FILE (canned Elfa replies: the no-network stand-in for Elfa), ARENA_MODEL_PROVIDER
#   (papers job: nearai = NEAR AI Cloud, the default; muse) and ARENA_NEWS_MODEL_PROVIDER (news job:
#   muse, the default; nearai). The model keys (NEARAI_API_KEY, MUSE_API_KEY) and the optional
#   ELFA_API_KEY come from the environment (secrets of the GitHub Environment `hunt` in CI) and are never echoed: `set -x` is never
#   used in this file. No ELFA_API_KEY, or no key for the news model = the news source is skipped,
#   the hunt runs.
set -euo pipefail
cd "$(dirname "$0")/../.."
source "$HOME/.cargo/env" 2>/dev/null || true

step="${1:?usage: ci-steps.sh build|test|hunt|collect}"
OUT_DIR="${HUNT_OUT_DIR:-evidence/hunts}"
BOARD_OUT="${HUNT_BOARD_OUT:-site}"
ART="${HUNT_ARTIFACT_DIR:-hunt-artifact}"

# A missing model key: a scheduled run skips cleanly (exit 0, one notice line), so a workflow left
# enabled without secrets does not turn red every day; a manual or local run still fails (exit 2),
# so a watched run with a forgotten key is never mistaken for a hunt that found nothing.
no_key() { # $1 message
  if [ "${GITHUB_EVENT_NAME:-}" = "schedule" ]; then
    echo "::notice::$1; scheduled run skipped, nothing hunted"; mkdir -p "$OUT_DIR"; exit 0
  fi
  echo "$1; not hunting" >&2; exit 2
}

int_in() { # $1 name, $2 value, $3 min, $4 max
  [[ "$2" =~ ^[0-9]+$ ]] && [ "$2" -ge "$3" ] && [ "$2" -le "$4" ] || { echo "bad $1: must be $3-$4" >&2; exit 2; }
}

case "$step" in
  build)
    [ -f contracts/target/wasm32-unknown-unknown/release/test_token.wasm ] && [ -f contracts/target/wasm32-unknown-unknown/release/guard.wasm ] || \
      (cd contracts && cargo build --release --target wasm32-unknown-unknown -p test-token -p guard)
    [ -x harness/target/release/arena-harness ] || (cd harness && cargo build --release)
    # Optional Intel quote check for the NEAR AI attestation: pinned, hash-checked wheel, CI only
    # (a local machine may install it itself; without it the record says "quote not verified here").
    if [ "${CI:-}" = "true" ]; then
      python3 -m pip install --quiet --require-hashes --only-binary :all: --no-deps -r tools/hunter/requirements-attest.txt
    fi
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
    SOURCE="${HUNT_SOURCE:-papers}"
    int_in HUNT_DAYS "$DAYS" 1 365; int_in HUNT_MAX_PAPERS "$MAXP" 1 5; int_in HUNT_JOBS "$JOBS" 1 8
    case "$SOURCE" in papers|news|all) ;; *) echo "bad HUNT_SOURCE: papers, news or all" >&2; exit 2 ;; esac
    [ -n "$PAPER" ] && [ "$SOURCE" = "all" ] && SOURCE=papers   # one pinned paper is a papers-only hunt
    args=(--source "$SOURCE" --days "$DAYS" --max-papers "$MAXP" --jobs "$JOBS" --out-dir "$OUT_DIR" --board-out "$BOARD_OUT")
    if [ -n "$PAPER" ]; then
      [[ "$PAPER" =~ ^[0-9]{4}\.[0-9]{4,5}(v[0-9]+)?$ ]] || { echo "bad HUNT_PAPER: not an arXiv id" >&2; exit 2; }
      args+=(--paper "$PAPER")
    fi
    if [ "$SOURCE" != "papers" ]; then
      if [ -n "${HUNT_NEWS_FILE:-}" ]; then
        args+=(--news-file "$HUNT_NEWS_FILE")
      elif [ -z "${ELFA_API_KEY:-}" ] && [ ! -f "$HOME/.config/arena/news.env" ]; then
        echo "ELFA_API_KEY is not set (optional secret): the news source will be skipped; the rest of the hunt runs"
      fi
    fi
    [ -n "${HUNT_OFFLINE_REPLIES:-}" ] && args+=(--offline-replies "$HUNT_OFFLINE_REPLIES")
    [ -n "${HUNT_PAPERS_FILE:-}" ] && args+=(--papers-file "$HUNT_PAPERS_FILE")
    [ "${HUNT_NO_SAVE:-0}" = "1" ] && args+=(--no-save)
    PROVIDER="${ARENA_MODEL_PROVIDER:-nearai}"
    case "$PROVIDER" in nearai|muse) ;; *) echo "bad ARENA_MODEL_PROVIDER: nearai or muse" >&2; exit 2 ;; esac
    if [ -z "${HUNT_OFFLINE_REPLIES:-}" ]; then
      # The papers job needs its model key; the news job (Muse by default) is skipped by the hunt itself if its key is missing.
      if [ "$SOURCE" != news ] && [ "$PROVIDER" = nearai ] && [ -z "${NEARAI_API_KEY:-}" ] && [ ! -f "$HOME/.config/arena/nearai.env" ]; then
        no_key "NEARAI_API_KEY is not set (add it to the GitHub Environment named hunt)"
      fi
      if [ "$SOURCE" != news ] && [ "$PROVIDER" = muse ] && [ -z "${MUSE_API_KEY:-}" ] && [ ! -f "$HOME/.config/arena/model.env" ]; then
        no_key "MUSE_API_KEY is not set (needed because ARENA_MODEL_PROVIDER=muse)"
      fi
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
    if grep -rIl -i -E "MUSE_API_KEY=|NEARAI_API_KEY=|ELFA_API_KEY=|x-elfa-api-key|Bearer [A-Za-z0-9._-]{12,}" "$ART" >/dev/null 2>&1; then
      echo "refusing to upload: something in the artifact looks like a secret" >&2; exit 1
    fi
    echo "artifact ready: $ART ($(find "$ART" -type f | wc -l | tr -d ' ') files)"
    ;;
  *) echo "unknown step $step" >&2; exit 2 ;;
esac
