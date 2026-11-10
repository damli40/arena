#!/usr/bin/env bash
# Runs both proofs and exits 0 only if every outcome matches evidence/proofs-plan.md.
#
#   proofs/run.sh            # everything (257 s measured on an M-series Mac, after first build)
#   proofs/run.sh proof1     # Kani on the model + exhaustive run of the real contract
#   proofs/run.sh proof2     # z3 on vault-a's policy
#
# Logs go to $OUT (default proofs/out/). The sandbox cross-check is separate:
# proofs/crosscheck.sh.
#
# Needs: Kani (`cargo install --locked kani-verifier && cargo kani setup`), stable Rust,
# and z3-solver in proofs/.venv (`python3 -m venv proofs/.venv && proofs/.venv/bin/pip install z3-solver`).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="${OUT:-$HERE/out}"
mkdir -p "$OUT"
WHAT="${1:-all}"
PASS=0
FAIL=0
ok() { echo "PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL + 1)); }
t_start=$(date +%s)

if [ "$WHAT" = all ] || [ "$WHAT" = proof1 ]; then
  echo "== Proof 1: one invoice is never paid twice"

  # 0. The mutant really is the guard minus line 186, nothing else.
  d="$(diff "$ROOT/contracts/guard/src/lib.rs" "$HERE/guard-real-mutant/src/lib.rs")"
  if [ "$d" = "$(printf '186d185\n<                 inv.status = Status::Pending;')" ]; then
    ok "mutant = contracts/guard minus line 186 only"
  else
    bad "mutant diff is not exactly line 186"; echo "$d"
  fi

  # 1. Kani on the model (proofs/guard-model). Layer A (verdict) and B (must-fail,
  #    covers, unwinding assertions).
  cd "$HERE/guard-model"
  for h in vulnerable_fixture_n3 fixed_n3 fixed_mutant_no_pending_write_n3 fixed_n3_bound_too_small fixed_n4 vulnerable_fixture_n4; do
    t0=$(date +%s)
    cargo kani --exact --harness "proofs::$h" > "$OUT/kani-$h.log" 2>&1
    echo "  (wall $(( $(date +%s) - t0 )) s)" >> "$OUT/kani-$h.log"
    if python3 -I "$HERE/check_kani.py" "$OUT/kani-$h.log" "$h"; then ok "kani $h"; else bad "kani $h"; fi
  done

  # 2. Concrete playback: Kani's failing schedule, replayed through the same world()
  #    code and printed in plain words.
  cargo +stable build --release --bin playback > "$OUT/build-playback.log" 2>&1
  for pair in "vulnerable_fixture_n3:vulnerable_fixture" "fixed_mutant_no_pending_write_n3:mutant"; do
    h="${pair%%:*}"; m="${pair##*:}"
    cargo kani --exact --harness "proofs::$h" -Z concrete-playback --concrete-playback=print > "$OUT/kani-$h.playback.log" 2>&1
    if ./target/release/playback "$m" "$OUT/kani-$h.playback.log" > "$OUT/kani-$h.trace.txt" 2>&1 \
       && grep -q 'RESULT failed_checks=\["P1' "$OUT/kani-$h.trace.txt"; then
      ok "playback of $h reproduces the P1 failure"; sed 's/^/      /' "$OUT/kani-$h.trace.txt"
    else
      bad "playback of $h"
    fi
  done

  # 3. The REAL contract (contracts/guard, unchanged) on near-sdk's mocked chain:
  #    every schedule, model in lockstep. Layer C for the model; second bounded check of the code.
  cd "$HERE/guard-real"
  cargo +stable build --release --bin exhaustive > "$OUT/build-exhaustive.log" 2>&1 || bad "build exhaustive"
  CARGO_TARGET_DIR=target-mutant cargo +stable build --release --features mutant --bin exhaustive > "$OUT/build-exhaustive-mutant.log" 2>&1 || bad "build exhaustive mutant"
  run_ex() { # name, binary, mode, n, expected RESULT fragment, [env]
    local name="$1" bin="$2" mode="$3" n="$4" want="$5"
    env ${6:-} "$bin" "$mode" "$n" > "$OUT/exhaustive-$name.log" 2>&1
    if grep -q "RESULT .*$want" "$OUT/exhaustive-$name.log"; then ok "exhaustive $name: $(grep RESULT "$OUT/exhaustive-$name.log")"; else bad "exhaustive $name: $(grep RESULT "$OUT/exhaustive-$name.log")"; fi
  }
  run_ex real-vulnerable_fixture-n3 ./target/release/exhaustive vulnerable_fixture 3 "build=real mode=vulnerable_fixture n=3 p1=FAILS p2=HOLDS filter=AGREES model=AGREES"
  run_ex real-fixed-n3 ./target/release/exhaustive fixed 3 "build=real mode=fixed n=3 p1=HOLDS p2=HOLDS filter=AGREES model=AGREES"
  run_ex real-vulnerable_fixture-n4 ./target/release/exhaustive vulnerable_fixture 4 "build=real mode=vulnerable_fixture n=4 p1=FAILS p2=HOLDS filter=AGREES model=AGREES"
  run_ex real-fixed-n4 ./target/release/exhaustive fixed 4 "build=real mode=fixed n=4 p1=HOLDS p2=HOLDS filter=AGREES model=AGREES"
  run_ex mutant-fixed-n3 ./target-mutant/release/exhaustive fixed 3 "build=mutant mode=fixed n=3 p1=FAILS p2=HOLDS filter=AGREES model=AGREES"
  # Lockstep self-test: model given the wrong mutant flag must DISAGREE.
  run_ex lockstep-selftest ./target/release/exhaustive fixed 3 "model=DISAGREES" "LOCKSTEP_SELFTEST=1"
fi

if [ "$WHAT" = all ] || [ "$WHAT" = proof2 ]; then
  echo "== Proof 2: the owner's policy vs the owner's intent (z3)"
  t0=$(date +%s)
  "$HERE/.venv/bin/python" -I "$HERE/z3/policy_proof.py" --json "$OUT/z3-results.json" > "$OUT/z3.log" 2>&1
  rc=$?
  echo "  (wall $(( $(date +%s) - t0 )) s)" >> "$OUT/z3.log"
  grep RESULT "$OUT/z3.log" | sed 's/^/      /'
  if [ $rc -eq 0 ]; then ok "z3 policy proof: every query as planned"; else bad "z3 policy proof"; fi
fi

echo "proofs: $PASS passed, $FAIL failed ($(( $(date +%s) - t_start )) s). Logs: $OUT"
[ "$FAIL" -eq 0 ]
