"""Re-judge the Nov 10 testnet race trials from their committed raw files (no network).

    python3 -I tools/race/testnet_rows.py

Reads evidence/testnet-2026-11-11-run{1,2,3}-raw.json (written by tools/testnet at the time), turns
each trial's two `pay` calls into the judge's leg format and applies tools/race/ordering.py.
Prints one row per trial, then one summary line:

    testnet-2026-11-10: 10 trials; checks in the same block 7, one block apart 2, two blocks apart 1; judge: overlap-proven 9, tie-unproven 1, sequential 0, not-produced 0
"""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "race"))
import ordering as O  # noqa: E402


def as_step(pay):
    st = [s for s in pay.get("steps", []) if not s.get("role", "").startswith("tx_to_receipt")]
    tx = next((s["block_height"] for s in pay.get("steps", []) if s.get("role", "").startswith("tx_to_receipt")), None)
    if not st:
        return {"outcome": "not-included", "receipts": None, "logs": []}
    rs = [{"index": n, "executor": s["executor"], "block_height": s.get("block_height"), "ok": bool(s.get("ok"))} for n, s in enumerate(st)]
    return {"outcome": "ok", "receipts": {"tx_block_height": tx, "receipts": rs}, "logs": []}


def main():
    gaps = {0: 0, 1: 0, 2: 0}
    verdicts = {O.OVERLAP: 0, O.TIE: 0, O.SEQUENTIAL: 0, O.NOT_PRODUCED: 0}
    n = 0
    for run in (1, 2, 3):
        raw = json.loads((ROOT / "evidence" / f"testnet-2026-11-11-run{run}-raw.json").read_text())
        for t in raw["trials"]:
            n += 1
            legs = [O.leg_of(as_step(t["pay_a"])), O.leg_of(as_step(t["pay_b"]))]
            v = O.ordering_verdict(legs)
            checks = [l.get("check") for l in legs]
            gap = abs(checks[0] - checks[1]) if None not in checks else None
            if gap in gaps:
                gaps[gap] += 1
            verdicts[v["verdict"]] += 1
            print(f"row {n:>2} run{run} {t['mode']:<18} checks A {checks[0]} B {checks[1]} (apart {gap}); "
                  f"callbacks A {legs[0].get('callback')} B {legs[1].get('callback')}; paid {t['guard_paid_out']}; {v['verdict']}")
    print(f"testnet-2026-11-10: {n} trials; checks in the same block {gaps[0]}, one block apart {gaps[1]}, two blocks apart {gaps[2]}; "
          f"judge: overlap-proven {verdicts[O.OVERLAP]}, tie-unproven {verdicts[O.TIE]}, sequential {verdicts[O.SEQUENTIAL]}, not-produced {verdicts[O.NOT_PRODUCED]}")


if __name__ == "__main__":
    main()
