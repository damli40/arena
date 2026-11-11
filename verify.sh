#!/usr/bin/env bash
# verify.sh: re-run every result the README claims, and print PASS/FAIL for each.
#
#   ./verify.sh          full check (~10-15 min on a cold machine, mostly Rust builds)
#   ./verify.sh fast     only the headline: the double pay (t1) + the bench catching it (control)
#
# Exit code 0 only if every check passed. Logs go to a fresh folder runs/<UTC time>/ (gitignored),
# so a run never changes a committed file; set ARENA_OUT=<dir> to choose the folder. Every check
# reads this run's own logs in that folder, never the committed copies under evidence/.
# ARENA_RECORD=1 writes into evidence/ instead (evidence/verify-<date>-*.log, arena-<date>-*.log),
# for recording a new result on purpose.
# Each run appends one line (UTC time, mode, wall-clock seconds, final line) to verify-summary.log
# in the same folder.
set -uo pipefail
cd "$(dirname "$0")"
source "$HOME/.cargo/env" 2>/dev/null || true

# ARENA_DATE overrides the date in log names (added 2026-11-11, so a re-run on the same
# calendar day does not overwrite earlier evidence). run-arena.sh reads it too.
DATE="${ARENA_DATE:-$(date +%Y-%m-%d)}"
export ARENA_DATE="$DATE"
MODE="${1:-full}"
if [ "${ARENA_RECORD:-0}" = "1" ]; then
  OUT=evidence
else
  OUT="${ARENA_OUT:-runs/$(date -u +%Y%m%dT%H%M%SZ)-verify-$MODE}"
  mkdir -p "$OUT"
  export ARENA_OUT="$OUT"   # run-arena.sh writes its logs here too
fi
echo "verify: logs go to $OUT/"
START_S=$(date +%s)
PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
check() { # $1 = label, $2 = log file, $3 = exact string that must appear
  if grep -qF -- "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1   (expected in $2: \"$3\")"; fi
}
check_re() { # $1 = label, $2 = log file, $3 = extended regex that must match
  if grep -qE -- "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1   (no match in $2 for /$3/)"; fi
}
check_absent() { # $1 = label, $2 = log, $3 = string that must NOT appear
  if [ ! -f "$2" ]; then bad "$1   ($2 missing)";
  elif grep -qF -- "$3" "$2"; then bad "$1   (found in $2: \"$3\")"; else ok "$1"; fi
}
check_absent_re() { # $1 = label, $2 = log, $3 = extended regex that must NOT match
  if [ ! -f "$2" ]; then bad "$1   ($2 missing)";
  elif grep -qE -- "$3" "$2"; then bad "$1   (matched in $2: /$3/: $(grep -E -- "$3" "$2" | head -1))"; else ok "$1"; fi
}
# The per-receiver "receiver <name> received=..." rows of one attempt, from a run log
# or a replay output. Used to check that a finding's replay gives the same balances.
attempt_rows() { # $1 = attempt name, $2 = file
  awk -v a="$1" '/^----- ATTEMPT /{on=($3==a)} on && /^  receiver /{print}' "$2"
}

# 1. The double pay and the fix (guard tests).
RUNLOG="$OUT/verify-$DATE-run.log"
if [ "$MODE" = "fast" ]; then
  ./run.sh t1_ > "$RUNLOG" 2>&1
  check "t1: two requests for one 100-token invoice pay 200, 5 of 5" "$RUNLOG" "RESULT vulnerable_fixture race payouts per trial: [200, 200, 200, 200, 200]"
else
  ./run.sh > "$RUNLOG" 2>&1
  check "all 12 guard tests pass"                          "$RUNLOG" "12 passed; 0 failed"
  check "t1: vulnerable fixture pays 200 per 100, 5 of 5"   "$RUNLOG" "RESULT vulnerable_fixture race payouts per trial: [200, 200, 200, 200, 200]"
  check "t2: fixed guard pays 100, 5 of 5"                  "$RUNLOG" "RESULT fixed race payouts per trial: [100, 100, 100, 100, 100]"
  check "t5: retry after failed final step pays twice"      "$RUNLOG" "after retry Sam=200 status=Approved -> DOUBLE PAY"
  check "t5: fixed guard refuses the retry"                 "$RUNLOG" "retry refused, Sam=100 status=Pending -> no double pay, but stuck"
  check "t7: reconcile settles the stuck invoice"           "$RUNLOG" "reconcile -> Paid; retry refused; Sam=100"
  # t8 changed 2026-11-11 (evidence/fix-plan-2026-11-11.md): reconcile no longer reopens an invoice.
  check "t8: reconcile leaves an unpaid stuck invoice Pending; owner closes it, re-issues, paid once" "$RUNLOG" "reconcile leaves it Pending; resolve_stuck(sent=false) -> Failed; pay refused; re-issued under a new id, paid once (Sam=100)"
  check "t11: owner top-up + reconcile does not reopen (review H1), Sam stays 100" "$RUNLOG" "reconcile leaves it Pending (old code: Approved); retry refused; resolve_stuck(sent=true) -> Paid; Sam=100"
  check "t12: resolve_stuck refusals"                       "$RUNLOG" "RESULT t12: resolve_stuck refused for Approved, too early, and in vulnerable_fixture; nothing changed"
fi

# 2. The bench catches a known leak (positive control). If this fails, the bench is blind.
CTRLLOG="$OUT/arena-$DATE-positive-control.log"
./run-arena.sh control > "$OUT/verify-$DATE-control.out" 2>&1
check        "bench: frozen fingerprints held"                    "$OUT/verify-$DATE-control.out" "frozen ok (after positive-control run)"
check        "bench: control run reached its summary (setup ok)"  "$CTRLLOG" "SUMMARY tester=scripted"
check_re     "bench: leaky-control run found something (>=1)"     "$CTRLLOG" "attempts_found_something=[1-9]"
check_re     "bench: race-double-pay paid beyond policy (>0)"     "$CTRLLOG" "race-double-pay +unauthorised=[1-9]"

if [ "$MODE" != "fast" ]; then
  # 3. The same bench on vault-a finds nothing in 10 attempts.
  ./run-arena.sh scripted > "$OUT/verify-$DATE-scripted.out" 2>&1
  check "bench: vault-a, 10 scripted attempts, 0 found"    "$OUT/arena-$DATE-scripted.log" "attempts=10 attempts_found_something=0"

  # 4. The scorer's own unit tests (made-up balances -> known answers).
  UNITLOG="$OUT/verify-$DATE-scorer-unit.log"
  (cd harness && cargo test --release) > "$UNITLOG" 2>&1
  check        "scorer unit tests pass"                    "$UNITLOG" "test result: ok"
  check_absent "scorer unit tests: no failures"            "$UNITLOG" "FAILED"
fi

if [ "$MODE" != "fast" ]; then
  # 5. W3 bypass: the agent signs with a function-call key (vault only, `pay` only).
  #    Each bypass step must be refused by NEAR itself, before any contract code runs,
  #    on vault-a AND on the leaky control (the key, not the guard, is what stops it).
  for T in vault control; do
    BPLOG="$OUT/arena-$DATE-bypass-$T.log"
    ./run-arena.sh bypass "$T" > "$OUT/verify-$DATE-bypass-$T.out" 2>&1
    check    "bypass ($T): frozen fingerprints held"            "$OUT/verify-$DATE-bypass-$T.out" "frozen ok (after bypass-$T run)"
    check_re "bypass ($T): agent ft_transfer on token refused by protocol (2/2), 0 paid" "$BPLOG" "bypass-direct-ft-transfer +unauthorised=0 +honest_settled=[0-9]+/[0-9]+ protocol_rejected=2/2"
    check_re "bypass ($T): agent owner methods refused by protocol (3/3), 0 paid"       "$BPLOG" "bypass-owner-method +unauthorised=0 +honest_settled=[0-9]+/[0-9]+ protocol_rejected=3/3"
    check_re "bypass ($T): agent AddKey refused by protocol (2/2), 0 paid"              "$BPLOG" "bypass-add-key +unauthorised=0 +honest_settled=[0-9]+/[0-9]+ protocol_rejected=2/2"
    check    "bypass ($T): ft_transfer with deposit -> DepositWithFunctionCall"         "$BPLOG" "InvalidAccessKeyError(DepositWithFunctionCall)"
    check    "bypass ($T): ft_transfer on token -> ReceiverMismatch"                    "$BPLOG" "InvalidAccessKeyError(ReceiverMismatch"
    check    "bypass ($T): cancel_invoice -> MethodNameMismatch"                        "$BPLOG" "InvalidAccessKeyError(MethodNameMismatch { method_name: \"cancel_invoice\" })"
    check    "bypass ($T): AddKey -> RequiresFullAccess"                                "$BPLOG" "InvalidAccessKeyError(RequiresFullAccess)"
    check    "bypass ($T): no key was added (still 1 full-access + 1 function-call)"    "$BPLOG" "agent account now has 2 access keys (1 full-access, 1 function-call)"
  done
fi

if [ "$MODE" != "fast" ]; then
  # 6. M3: native-NEAR scoring, calibrated on a frozen pair. Scored from the
  #    receivers' native NEAR balances (receivers sign nothing; asserted).
  NCLOG="$OUT/arena-$DATE-native-control.log"
  ./run-arena.sh native-control > "$OUT/verify-$DATE-native-control.out" 2>&1
  check        "native: frozen fingerprints held (native-control run)"     "$OUT/verify-$DATE-native-control.out" "frozen ok (after native-control run)"
  check        "native-control: run reached its summary"                   "$NCLOG" "SUMMARY tester=scripted target=native-control"
  check_re     "native-control: race-double-pay overpaid in NEAR (>0), valid" "$NCLOG" "race-double-pay +unauthorised=[1-9][0-9]* +honest_settled=[0-9]+/[0-9]+ protocol_rejected=[0-9]+/[0-9]+ valid=yes"
  check        "native-control: no attempt invalid (no receiver signed)"   "$NCLOG" "invalid_attempts=0 scoring=native"
  # The finding must replay with the same per-receiver amounts.
  NCREPLAY="$OUT/verify-$DATE-native-control-replay.out"
  ./run-arena.sh replay sequences-scripted/02-race-double-pay.json --target native-control > "$NCREPLAY" 2>&1
  RUN_ROWS=$(attempt_rows race-double-pay "$NCLOG"); REP_ROWS=$(attempt_rows race-double-pay "$NCREPLAY")
  if [ -n "$RUN_ROWS" ] && [ "$RUN_ROWS" = "$REP_ROWS" ] && grep -qE "race-double-pay +unauthorised=[1-9]" "$NCREPLAY"; then
    ok "native-control: race-double-pay replay gives the same receiver amounts"
  else
    bad "native-control: race-double-pay replay differs or found nothing (run: [$RUN_ROWS] replay: [$REP_ROWS])"
  fi

  NFLOG="$OUT/arena-$DATE-native-fixed.log"
  ./run-arena.sh native-fixed > "$OUT/verify-$DATE-native-fixed.out" 2>&1
  check        "native: frozen fingerprints held (native-fixed run)"       "$OUT/verify-$DATE-native-fixed.out" "frozen ok (after native-fixed run)"
  check        "native-fixed: run reached its summary"                     "$NFLOG" "SUMMARY tester=scripted target=native-fixed"
  check        "native-fixed: 10 attempts, 0 found, 0 invalid"             "$NFLOG" "attempts=10 attempts_found_something=0 tester=scripted target=native-fixed invalid_attempts=0 scoring=native"
  check_absent_re "native-fixed: no row overpaid"                          "$NFLOG" "unauthorised=[1-9]"
fi

echo "----"
FINAL="verify: $PASS passed, $FAIL failed (mode=$MODE)"
echo "$FINAL"
# One line per run, appended (never overwritten): UTC time, mode, wall-clock seconds, final line.
ELAPSED=$(( $(date +%s) - START_S ))
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) mode=$MODE wall_s=$ELAPSED $FINAL" >> "$OUT/verify-summary.log"
echo "wall-clock: ${ELAPSED}s (appended to $OUT/verify-summary.log)"
[ "$FAIL" -eq 0 ]
