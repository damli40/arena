#!/usr/bin/env bash
# Runs both proofs and exits 0 only if every outcome matches evidence/proofs-plan.md.
#
#   proofs/run.sh            # everything (257 s on Nov 10; 1,504 s on Nov 11 with the full world + inductive proofs)
#   proofs/run.sh proof1     # Kani on the model + exhaustive run of the real contract
#   proofs/run.sh proof2     # z3 on vault-a's policy
#   proofs/run.sh proof3     # z3 on direct-pay rules (cap, payee list, approval threshold), up to 8 steps
#   proofs/run.sh repro      # the guard source builds the testnet wasm 0382023b... (fresh export)
#   proofs/run.sh properties # the property library, then no-double-pay on Arena's guard (not in `all`)
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
  # Scoped wording (2026-11-11): this proves the pay/callback race and, in the "full" world,
  # dead callbacks + reconcile + resolve_stuck + one outside transfer, within the stated bounds.
  # It is not a proof that no invoice can ever be paid twice under every possible world.
  echo "== Proof 1: the pay/callback race, plus the full world (dead callback, reconcile, resolve_stuck, outside transfer), bounded"

  # 0. The mutants really are the guard with one change each, nothing else.
  d="$(diff "$ROOT/contracts/guard/src/lib.rs" "$HERE/guard-real-mutant/src/lib.rs")"
  if [ "$d" = "$(printf '194d193\n<                 inv.status = Status::Pending;')" ]; then
    ok "mutant = contracts/guard minus line 194 only"
  else
    bad "mutant diff is not exactly line 194"; echo "$d"
  fi
  d="$(diff "$ROOT/contracts/guard/src/lib.rs" "$HERE/guard-real-mutant-reopen/src/lib.rs")"
  want_reopen="$(printf '303,306c303,304\n<             env::log_str(&format!(\n<                 "reconcile: invoice={id} ledger={expected} token_balance={actual} -> unchanged balance proves nothing; stays Pending, owner must call resolve_stuck"\n<             ));\n<             return Status::Pending;\n---\n>             inv.status = Status::Approved;\n>             Status::Approved')"
  if [ "$d" = "$want_reopen" ]; then
    ok "reopen mutant = contracts/guard with the pre-2026-11-11 Approved arm put back, nothing else"
  else
    bad "reopen mutant diff is not exactly the reconcile arm"; echo "$d"
  fi

  # 1. Kani on the model (proofs/guard-model). Layer A (verdict) and B (must-fail,
  #    covers, unwinding assertions).
  cd "$HERE/guard-model"
  for h in vulnerable_fixture_n3 fixed_n3 fixed_mutant_no_pending_write_n3 fixed_n3_bound_too_small fixed_n4 vulnerable_fixture_n4 \
           fixed_full_n2 old_reconcile_full_n2 vulnerable_fixture_full_n2 \
           inductive_step_fixed_k2 inductive_step_fixed_k3 inductive_step_old_reconcile_k2 inductive_step_vulnerable_k2 \
           inductive_init_k2 inductive_init_k3 invariant_implies_no_overpay_k2; do
    t0=$(date +%s)
    case "$h" in inductive_*|invariant_*) q="inductive::harnesses::$h" ;; *) q="proofs::$h" ;; esac
    cargo kani --exact --harness "$q" > "$OUT/kani-$h.log" 2>&1
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
  CARGO_TARGET_DIR=target-mutant-reopen cargo +stable build --release --features mutant-reopen --bin exhaustive > "$OUT/build-exhaustive-mutant-reopen.log" 2>&1 || bad "build exhaustive mutant-reopen"
  run_ex() { # name, binary, mode, n, expected RESULT fragment, [env], [world]
    local name="$1" bin="$2" mode="$3" n="$4" want="$5"
    env ${6:-} "$bin" "$mode" "$n" ${7:-} > "$OUT/exhaustive-$name.log" 2>&1
    if grep -q "RESULT .*$want" "$OUT/exhaustive-$name.log"; then ok "exhaustive $name: $(grep RESULT "$OUT/exhaustive-$name.log")"; else bad "exhaustive $name: $(grep RESULT "$OUT/exhaustive-$name.log")"; fi
  }
  run_ex real-vulnerable_fixture-n3 ./target/release/exhaustive vulnerable_fixture 3 "build=real mode=vulnerable_fixture n=3 world=base p1=FAILS p2=HOLDS filter=AGREES model=AGREES"
  run_ex real-fixed-n3 ./target/release/exhaustive fixed 3 "build=real mode=fixed n=3 world=base p1=HOLDS p2=HOLDS filter=AGREES model=AGREES"
  run_ex real-vulnerable_fixture-n4 ./target/release/exhaustive vulnerable_fixture 4 "build=real mode=vulnerable_fixture n=4 world=base p1=FAILS p2=HOLDS filter=AGREES model=AGREES"
  run_ex real-fixed-n4 ./target/release/exhaustive fixed 4 "build=real mode=fixed n=4 world=base p1=HOLDS p2=HOLDS filter=AGREES model=AGREES"
  run_ex mutant-fixed-n3 ./target-mutant/release/exhaustive fixed 3 "build=mutant mode=fixed n=3 world=base p1=FAILS p2=HOLDS filter=AGREES model=AGREES"
  # Full world (2026-11-11): one dead callback, reconcile, resolve_stuck, one outside transfer.
  run_ex real-fixed-n2-full ./target/release/exhaustive fixed 2 "build=real mode=fixed n=2 world=full p1=HOLDS p2=HOLDS filter=AGREES model=AGREES" "" full
  run_ex real-vulnerable_fixture-n2-full ./target/release/exhaustive vulnerable_fixture 2 "build=real mode=vulnerable_fixture n=2 world=full p1=FAILS .*model=AGREES" "" full
  run_ex mutant-reopen-fixed-n2-full ./target-mutant-reopen/release/exhaustive fixed 2 "build=mutant-reopen mode=fixed n=2 world=full p1=FAILS .*model=AGREES" "" full
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

if [ "$WHAT" = all ] || [ "$WHAT" = proof3 ]; then
  # Added 2026-11-11: a direct-pay guard's rules (cap, payee list, approval threshold, refunds),
  # every policy and amount symbolic, any order of up to 8 steps. A model of the rules, not code.
  echo "== Proof 3: direct-pay rules never pay beyond their own policy (z3, up to 8 steps)"
  t0=$(date +%s)
  "$HERE/.venv/bin/python" -I "$HERE/z3/direct_pay_proof.py" 8 --json "$OUT/z3-direct-pay.json" > "$OUT/z3-direct-pay.log" 2>&1
  rc=$?
  echo "  (wall $(( $(date +%s) - t0 )) s)" >> "$OUT/z3-direct-pay.log"
  tail -1 "$OUT/z3-direct-pay.log" | sed 's/^/      /'
  if [ $rc -eq 0 ]; then ok "z3 direct-pay proof: 54 queries as planned (the designs hold, every planted design flaw is found)"; else bad "z3 direct-pay proof"; grep UNEXPECTED "$OUT/z3-direct-pay.log"; fi
fi

if [ "$WHAT" = all ] || [ "$WHAT" = repro ]; then
  # Added 2026-11-11: the proved source builds the wasm hash recorded from testnet (constant in
  # repro/build.sh). No network once toolchain and crates are cached; the live testnet check is
  # repro/build.sh --onchain.
  echo "== Reproducible build: guard source -> wasm sha256 0382023b..."
  "$HERE/repro/build.sh" > "$OUT/repro-build.log" 2>&1 && grep -q "REPRO MATCH" "$OUT/repro-build.log" \
    && ok "repro: fresh export of contracts/ builds 0382023b..." || { bad "repro build"; tail -3 "$OUT/repro-build.log"; }
  "$HERE/repro/build.sh" --mutant > "$OUT/repro-build-mutant.log" 2>&1 && grep -q "MUTANT DETECTED" "$OUT/repro-build-mutant.log" \
    && ok "repro mutant: one deleted line changes the hash" || { bad "repro mutant"; tail -3 "$OUT/repro-build-mutant.log"; }
fi

if [ "$WHAT" = properties ]; then
  # Added 2026-11-12, not part of `all`: the property library (proofs/properties) checks itself,
  # then checks no-double-pay on Arena's guard (real source, every order of 3 pay calls) and on
  # the one-line mutant, which must break it.
  echo "== Property library: self-check, then no-double-pay on Arena's guard"
  "$HERE/properties/run.sh" > "$OUT/properties-self.log" 2>&1 && ok "property library: 7 self-checks" || { bad "property library self-check"; tail -5 "$OUT/properties-self.log"; }
  cd "$HERE/guard-real"
  cargo +stable build --release --bin properties > "$OUT/build-properties.log" 2>&1 || bad "build properties"
  CARGO_TARGET_DIR=target-mutant cargo +stable build --release --features mutant --bin properties > "$OUT/build-properties-mutant.log" 2>&1 || bad "build properties mutant"
  ./target/release/properties 3 > "$OUT/properties-arena-real.log" 2>&1
  tail -1 "$OUT/properties-arena-real.log" | sed 's/^/      /'
  grep -q 'build=real .*broken=\[\]$' "$OUT/properties-arena-real.log" && ok "no-double-pay holds on the real guard (3 pays)" || bad "no-double-pay on the real guard"
  target-mutant/release/properties 3 > "$OUT/properties-arena-mutant.log" 2>&1
  tail -1 "$OUT/properties-arena-mutant.log" | sed 's/^/      /'
  grep -q 'build=mutant .*broken=\["no-double-pay"\]$' "$OUT/properties-arena-mutant.log" && ok "the mutant breaks no-double-pay" || bad "mutant not caught"
fi

echo "proofs: $PASS passed, $FAIL failed ($(( $(date +%s) - t_start )) s). Logs: $OUT"
[ "$FAIL" -eq 0 ]
