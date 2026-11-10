#!/usr/bin/env bash
# Arena harness entry point.
#
#   ./run-arena.sh scripted            scripted tester vs vault-a (10 sequences)
#   ./run-arena.sh ai                  AI tester sequences vs vault-a (budget 10)
#   ./run-arena.sh control             scripted tester vs leaky-control-v2 (positive control)
#   ./run-arena.sh bypass [vault|control]
#                                      agent tries to go around the guard (sequences-bypass/);
#                                      every bypass step should be refused by NEAR itself
#   ./run-arena.sh native-control      scripted tester vs targets/native-control, scored from
#                                      receivers' native NEAR balances (native positive control)
#   ./run-arena.sh native-fixed        same, vs targets/native-fixed (native negative control)
#   ./run-arena.sh any <guard.wasm> [label]
#                                      scripted tester vs ANY guard wasm that implements
#                                      targets/vault-a/INTERFACE.md (fingerprinted before/after)
#   ./run-arena.sh any-native <guard.wasm> [label]
#                                      same, for a guard that pays in native NEAR (native scoring)
#   ./run-arena.sh replay <file.json> [--target vault|control|native-control|native-fixed
#                                      | --wasm <path> [--wasm-label L] [--native]]
#                                      replay one sequence on a fresh sandbox
#
# Every mode checks the frozen targets' fingerprints against their FROZEN.txt
# before AND after the run, and refuses to run if they do not match.
set -euo pipefail
cd "$(dirname "$0")"
source "$HOME/.cargo/env" 2>/dev/null || true

HARNESS=harness/target/release/arena-harness
EVIDENCE=evidence

# Fresh-clone fix (plan 0.2): build what the harness needs if it is missing.
ensure_built() {
  [ -f contracts/target/wasm32-unknown-unknown/release/test_token.wasm ] || \
    (cd contracts && cargo build --release --target wasm32-unknown-unknown -p test-token)
  [ -x "$HARNESS" ] || (cd harness && cargo build --release)
}

check_frozen() {
  local label="$1"
  # leaky-control (v1) stays checked: it is frozen evidence of the interface bug.
  # native-control / native-fixed: the native-NEAR calibration pair (M3).
  for t in vault-a leaky-control leaky-control-v2 native-control native-fixed; do
    (
      cd "targets/$t"
      while read -r tag file hash rest; do
        [ "$tag" = "sha256" ] || continue
        actual=$(shasum -a 256 "$file" | cut -d' ' -f1)
        if [ "$actual" != "$hash" ]; then
          echo "FROZEN CHECK FAILED ($label): $t/$file" >&2
          echo "  expected $hash" >&2
          echo "  actual   $actual" >&2
          exit 1
        fi
        echo "frozen ok ($label): $t/$file $actual"
      done < FROZEN.txt
    )
  done
}

run_dir() { # $1 = sequences dir suffix, $2 = log label; harness flags after
  local dir="$1" label="$2"; shift 2
  ensure_built
  local log="$EVIDENCE/arena-${ARENA_DATE:-$(date +%Y-%m-%d)}-$label.log"
  check_frozen "before $label run"
  echo "running tester=$dir $* -> $log"
  "$HARNESS" run "sequences-$dir" --budget 10 "$@" 2>&1 | tee "$log"
  check_frozen "after $label run"
  echo "log saved: $log"
}

case "${1:-}" in
  scripted)
    run_dir scripted scripted --target vault
    ;;
  ai)
    run_dir ai ai --target vault
    ;;
  # Positive control (FIXES fix 1): the same scripted sequences against the
  # deliberately leaky fixture. The scorer MUST see a payout above 0 here,
  # or the scorer is blind.
  control)
    run_dir scripted positive-control --target control
    ;;
  # M3: native-NEAR calibration pair, scripted sequences, native scoring.
  # native-control MUST show unauthorised > 0 on race-double-pay;
  # native-fixed MUST show 0 everywhere.
  native-control)
    run_dir scripted native-control --target native-control
    ;;
  native-fixed)
    run_dir scripted native-fixed --target native-fixed
    ;;
  # W3: the agent signs with a function-call key; these sequences try to go
  # around the guard (direct token transfer, owner methods, adding a key).
  bypass)
    t="${2:-vault}"
    case "$t" in vault|control) ;; *) echo "bypass target must be vault or control" >&2; exit 1;; esac
    run_dir bypass "bypass-$t" --target "$t" --label bypass
    ;;
  # Any guard wasm implementing INTERFACE.md. Not frozen by us, so its sha256
  # is taken before and after and the run fails if the file changed.
  any|any-native)
    mode="$1"
    wasm="${2:?usage: $0 $mode <guard.wasm> [label]}"
    label="${3:-$(basename "$wasm" .wasm)}"
    label=$(printf '%s' "$label" | tr -c 'A-Za-z0-9_-' '-')
    native_flag=()
    [ "$mode" = "any-native" ] && native_flag=(--native)
    before=$(shasum -a 256 "$wasm" | cut -d' ' -f1)
    echo "any-target fingerprint (before): $wasm $before"
    run_dir scripted "$mode-$label" --wasm "$wasm" --wasm-label "$label" --label scripted "${native_flag[@]+"${native_flag[@]}"}"
    after=$(shasum -a 256 "$wasm" | cut -d' ' -f1)
    if [ "$before" != "$after" ]; then
      echo "ANY-TARGET FINGERPRINT CHANGED during the run: $before -> $after" >&2
      exit 1
    fi
    echo "any-target fingerprint (after): $wasm $after"
    ;;
  replay)
    shift
    ensure_built
    check_frozen "before replay"
    "$HARNESS" replay "$@" 2>&1 | tee -a "$EVIDENCE/replays.log"
    check_frozen "after replay"
    ;;
  *)
    echo "usage: $0 scripted | ai | control | native-control | native-fixed | bypass [vault|control] | any <guard.wasm> [label] | any-native <guard.wasm> [label] | replay <file.json> [--target vault|control|native-control|native-fixed | --wasm <path> [--native]]" >&2
    exit 1
    ;;
esac
