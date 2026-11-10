#!/usr/bin/env bash
# Sandbox cross-check for Proof 2: replays z3's one-day worst case (Query A-max:
# pay inv-expire, then inv-mid) through the real harness on a fresh local NEAR
# sandbox, CLI flags only. Exits 0 only if ada receives 500, everyone else 0, and
# the harness scores 0 beyond policy.
#   proofs/crosscheck.sh     (needs harness/target/release/arena-harness, built by ./verify.sh)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="${OUT:-$HERE/out}"
mkdir -p "$OUT"
SEQ="$OUT/z3-worst-one-day.seq.json"
echo '{"name": "z3-query-A-worst-case-one-day", "steps": [{"call": {"actor": "agent", "method": "pay", "args": {"id": "inv-expire"}}}, {"call": {"actor": "agent", "method": "pay", "args": {"id": "inv-mid"}}}, {"view": {"method": "get_invoice", "args": {"id": "inv-expire"}}}]}' > "$SEQ"
cd "$ROOT"
harness/target/release/arena-harness attempt "$SEQ" --target vault --out "$OUT/z3-worst-one-day.result.json" \
  --meta "tester=proofs z3 Query A-max one-day counterexample" > "$OUT/z3-worst-one-day.log" 2>&1
"$HERE/.venv/bin/python" -I - "$OUT/z3-worst-one-day.result.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
recv = {r["receiver"]: int(r["received"]) for r in d["final"]["received"]}
beyond = int(d["score"]["unauthorised_payout"])
against = sum(max(0, v - (100 if k == "sam" else 0)) for k, v in recv.items())
good = recv == {"sam": 0, "ada": 500, "lin": 0, "kai": 0, "mo": 0} and beyond == 0 and d["score"]["valid"]
print(f"RESULT crosscheck chain received={recv} against_intent={against} beyond_policy={beyond} "
      f"z3_predicted=ada 500, against 500 -> {'MATCH' if good else 'MISMATCH'}")
sys.exit(0 if good else 1)
PY
