#!/usr/bin/env bash
# Model-check the guard (Guard.tla) with TLC on near-tla's modules.
# Exits 0 only if every check comes out as evidence/tla-plan.md expects.
#
#   ./run.sh              every check
#   ./run.sh vuln_race    only the named checks
#
# Needs: Java 17+ (default: Homebrew openjdk@21; override with JAVA=/path/to/java),
# tla/vendor/tla2tools.jar and tla/vendor/near-tla (see README.md, "Setup").
set -u
cd "$(dirname "$0")"
HERE="$PWD"
JAVA="${JAVA:-/opt/homebrew/opt/openjdk@21/bin/java}"
JAR="$HERE/vendor/tla2tools.jar"
LIB="$HERE/vendor/near-tla/modules"
WORKERS="${WORKERS:-4}"
BUILD="$HERE/build"
mkdir -p "$BUILD"
SUMMARY="$BUILD/summary.tsv"
: > "$SUMMARY"

[ -x "$JAVA" ] || { echo "no java at $JAVA (set JAVA=...)"; exit 2; }
[ -f "$JAR" ] || { echo "missing $JAR"; exit 2; }
[ -f "$LIB/NearAsync.tla" ] || { echo "missing near-tla modules at $LIB"; exit 2; }

FAILED=0
SELECT=("$@")

selected() {
  [ ${#SELECT[@]} -eq 0 ] && return 0
  local s; for s in "${SELECT[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1
}

# write_cfg DIR MODE NINV MAXPAY MAXREC WAITRULE MAYFAIL MAXFAILS "INV1 INV2 ..." [ACTION_CONSTRAINT]
write_cfg() {
  local dir=$1 mode=$2 ninv=$3 maxpay=$4 maxrec=$5 wait=$6 mayfail=$7 maxfails=$8 invs=$9 ac=${10:-}
  {
    echo "SPECIFICATION Spec"
    echo "CONSTANTS"
    echo "  Mode = \"$mode\""
    echo "  NInv = $ninv"
    echo "  MaxPay = $maxpay"
    echo "  MaxRec = $maxrec"
    echo "  WaitRule = $wait"
    echo "  MayFail = $mayfail"
    echo "  MaxFails = $maxfails"
    cat <<'EOF'
  Accounts <- Accts
  Exists <- Accts
  StakingAcct = "guard"
  MinStake = 1
  MaxEpoch = 0
  MaxReward = 0
  StorageFloor <- PFloor
  GasMode = "fault"
  GasCall <- NoGasTable
  GasBurn <- NoGasTable
  LogOn = FALSE
  TokYocto = 1
  TokenAccts = {"ft"}
  WNearAccts = {}
  TokHolders <- PTokHolders
  TokStorageMin <- PTokMin
  TokDev <- PTokDev
  TokCallReserve <- PTokReserve
  TrackSigner <- FalseDef
EOF
    echo "INVARIANTS"
    local i; for i in $invs; do echo "  $i"; done
    [ -n "$ac" ] && echo "ACTION_CONSTRAINT $ac"
  } > "$dir/Guard.cfg"
}

# check NAME EXPECT SPECFILE <write_cfg args...>
#   EXPECT: "pass" | "violation:<Invariant>"
check() {
  local name=$1 expect=$2 spec=$3; shift 3
  selected "$name" || return 0
  local dir="$BUILD/$name"
  rm -rf "$dir"; mkdir -p "$dir/jtmp"
  cp "$spec" "$dir/Guard.tla"
  write_cfg "$dir" "$@"
  local t0 t1 out got
  t0=$(date +%s)
  ( cd "$dir" && "$JAVA" -XX:+UseParallelGC -Xss16m -Djava.io.tmpdir="$dir/jtmp" \
      -DTLA-Library="$LIB" -cp "$JAR" tlc2.TLC -deadlock -workers "$WORKERS" \
      -metadir "$dir/states" -config Guard.cfg Guard.tla > "$dir/tlc.out" 2>&1 )
  t1=$(date +%s)
  rm -rf "$dir/states" "$dir/jtmp"
  out="$dir/tlc.out"
  if grep -q "Model checking completed. No error has been found." "$out"; then
    got="pass"
  elif v=$(grep -o "Invariant [A-Za-z_0-9]* is violated" "$out" | head -1) && [ -n "$v" ]; then
    got="violation:$(echo "$v" | awk '{print $2}')"
  else
    got="error"
  fi
  local gen dist depth
  gen=$(grep -o "^[0-9,]* states generated" "$out" | tail -1 | awk '{print $1}')
  dist=$(grep -o "[0-9,]* distinct states found" "$out" | tail -1 | awk '{print $1}')
  depth=$(grep -o "depth of the complete state graph search is [0-9]*" "$out" | awk '{print $NF}')
  local ok="OK"; [ "$got" = "$expect" ] || { ok="UNEXPECTED"; FAILED=1; }
  printf "%-40s expect %-28s got %-28s %s  (%ss, %s generated, %s distinct, depth %s)\n" \
    "$name" "$expect" "$got" "$ok" "$((t1 - t0))" "${gen:-?}" "${dist:-?}" "${depth:-?}"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$expect" "$got" "$ok" "$((t1 - t0))" \
    "${gen:-?}" "${dist:-?}" "${depth:-?}" >> "$SUMMARY"
}

# mutant ID FIND REPLACE -> path of a patched copy of Guard.tla (FIND must occur exactly once)
mutant() {
  local id=$1 find=$2 repl=$3
  local dst="$BUILD/mutants/$id.tla"
  mkdir -p "$BUILD/mutants"
  FIND="$find" REPL="$repl" python3 -I -c '
import os, sys
s = open(sys.argv[1]).read(); f = os.environ["FIND"]; r = os.environ["REPL"]
n = s.count(f)
if n != 1:
    sys.exit("mutant: find string occurs %d times, expected 1: %r" % (n, f))
open(sys.argv[2], "w").write(s.replace(f, r))
' "$HERE/Guard.tla" "$dst" || { echo "mutant $id: patch failed"; FAILED=1; return 1; }
  echo "$dst"
}

PROPS="NoOverpay FailedStaysPayable Sane"
FAULTS='{"ft_transfer", "on_transfer"}'
SPEC="$HERE/Guard.tla"

# ---- the two modes ---------------------------------------------------------------------
#      name                 expect               spec  mode                 inv pay rec wait  mayfail  fails props
check vuln_race             violation:NoOverpay  "$SPEC" vulnerable_fixture  1   2   0  TRUE  '{}'      0  "$PROPS"
check vuln_testnet_order    violation:NoOverpay  "$SPEC" vulnerable_fixture  1   2   0  TRUE  '{}'      0  "$PROPS" TestnetOrder
check fixed_1inv            pass                 "$SPEC" fixed               1   3   1  TRUE  "$FAULTS" 1  "$PROPS"
check fixed_2inv            pass                 "$SPEC" fixed               2   3   1  TRUE  "$FAULTS" 1  "$PROPS"
# added after the plan (see the DEVIATION note below): 2 forced failures, 1 invoice
check fixed_1inv_2faults     pass                 "$SPEC" fixed               1   3   1  TRUE  "$FAULTS" 2  "$PROPS"

# ---- witnesses: each must be reached (TLC reports Wit_x violated) -----------------------
for w in paid race_setup refused_in_flight repaid_after_failed_transfer stuck_pending \
         reconcile_says_paid; do
  check "wit_${w}" "violation:Wit_${w}" "$SPEC" fixed 1 3 1 TRUE "$FAULTS" 1 "Wit_${w}"
done
# DEVIATION from evidence/tla-plan.md (recorded in evidence/tla-2026-11-10.md):
# the plan expected reconcile's "money did not leave" arm to be reached at 1 forced failure.
# It is not: with WaitRule, an invoice is stuck Pending only if on_transfer failed, and the
# money is still there only if ft_transfer failed too, which is 2 failures. So the plan's
# expectation is kept here as a recorded miss (expect pass = unreachable at MaxFails 1), and
# the arm is checked at MaxFails 2 by fixed_1inv_2faults and its witness below.
check wit_reconcile_says_approved_1fault pass "$SPEC" fixed 1 3 1 TRUE "$FAULTS" 1 "Wit_reconcile_says_approved"
check wit_reconcile_says_approved violation:Wit_reconcile_says_approved "$SPEC" fixed 1 3 1 TRUE "$FAULTS" 2 "Wit_reconcile_says_approved"
check wit_reconcile_ambiguous violation:Wit_reconcile_ambiguous "$SPEC" fixed 2 3 1 TRUE "$FAULTS" 1 "Wit_reconcile_ambiguous"

# ---- mutants: each must be caught by fixed_1inv's bounds -------------------------------
if selected mut_no_pending_write; then
  m=$(mutant no_pending_write '!.st[i] = "Pending", !.pend' '!.pend') && \
  check mut_no_pending_write violation:NoOverpay "$m" fixed 1 3 1 TRUE "$FAULTS" 1 "$PROPS"
fi
if selected mut_no_release_on_failure; then
  m=$(mutant no_release_on_failure 'ELSE IF wasP THEN "Approved" ELSE @,' 'ELSE @,') && \
  check mut_no_release_on_failure violation:FailedStaysPayable "$m" fixed 1 3 1 TRUE "$FAULTS" 1 "$PROPS"
fi
# no_wait_rule changes a constant, not the text: WaitRule = FALSE
check mut_no_wait_rule      violation:NoOverpay  "$SPEC" fixed               1   3   1  FALSE "$FAULTS" 1  "$PROPS"

echo
if [ "$FAILED" -eq 0 ]; then
  echo "verdict: all as planned ($(wc -l < "$SUMMARY" | tr -d ' ') checks); details in build/summary.tsv"
  exit 0
else
  echo "verdict: FAILED (see UNEXPECTED above; TLC output in build/<check>/tlc.out)"
  exit 1
fi
