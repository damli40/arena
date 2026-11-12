"""Block-height table for race result files (evidence only; reads harness result JSONs).

    python3 -I tools/race/table.py [--summary] <result.json> [...]

One row per file: for each race leg, the block its transaction was accepted in, its guard check
(x = refused there), the token transfer and the guard callback; then the judge's verdict
(tools/race/ordering.py) and the score field `beyond_authorised`.
"""
import json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ordering as O  # noqa: E402


def leg_cells(step):
    t = step.get("receipts") or {}
    rs = t.get("receipts") or []
    if not rs:
        return "-", "-", "-", "-"
    guard = rs[0]["executor"]
    token = [r["block_height"] for r in rs[1:] if r["executor"] != guard and r.get("children", 0) > 0]
    cbs = [r["block_height"] for r in rs[1:] if r["executor"] == guard]
    check = f"{rs[0]['block_height']}" + ("" if rs[0]["ok"] else " (refused)")
    return (str(t.get("tx_block_height")), check, str(min(token)) if token else "-", str(min(cbs)) if cbs else "-")


def legs_idx(result):
    race = [i for i, s in enumerate(result["steps"]) if s["kind"] == "race-call"]
    if race:
        return race
    return [i for i, s in enumerate(result["steps"]) if s["kind"] == "call" and s["method"] == "pay"]


def row(path):
    r = json.loads(pathlib.Path(path).read_text())
    idx = legs_idx(r)
    v = O.ordering_verdict(O.legs_of(r, idx))
    cells = [leg_cells(r["steps"][i]) for i in idx]
    legs = " / ".join(f"{a} → {b} → {c} → {d}" for a, b, c, d in cells)
    return f"| `{pathlib.Path(path).name}` | {r['target']} | {legs} | {v['verdict']} (last check {v['last_check']}, first callback {v['first_cb']}) | {r['score']['beyond_authorised']} |"


def summary(paths):
    """One line over plain two-leg race results: how many had both checks in one block, the callback
    exactly 2 blocks after the last check, the judge's verdicts, and which guards broke or held.

    Broke/held is read only from a COUNTED run, the same rule as tools/race/run.py: the score is valid
    and the judge says overlap-proven; then broke = 100 beyond policy with the receiver paid 200, held =
    0 beyond with the receiver paid 100, anything else is a mismatch and not counted either. Any other run (invalid score, tie, sequential, not-produced) is
    listed under "not counted" with why, never as held or broke. Returns how many were not counted."""
    same = gap2 = 0
    verdicts, broke, held, skipped = {}, [], [], []
    for p in paths:
        r = json.loads(pathlib.Path(p).read_text())
        idx = legs_idx(r)
        v = O.ordering_verdict(O.legs_of(r, idx))
        verdicts[v["verdict"]] = verdicts.get(v["verdict"], 0) + 1
        if v["achieved_offsets"] and all(x == 0 for x in v["achieved_offsets"]):
            same += 1
        if v["first_cb"] is not None and v["first_cb"] - v["last_check"] == 2:
            gap2 += 1
        if not r["score"].get("valid"):
            skipped.append(f"{r['target']}: score invalid")
            continue
        if v["verdict"] != O.OVERLAP:
            skipped.append(f"{r['target']}: {v['verdict']}")
            continue
        b = int(r["score"]["beyond_authorised"])
        got = next((int(x["received"]) for x in r["final"]["received"] if x["receiver"] == "sam"), None)
        if b == 100 and got == 200:
            broke.append(f"{r['target']} {b}")
        elif b == 0 and got == 100:
            held.append(r["target"])
        else:  # neither one payment nor exactly one extra: a mismatch, never held
            skipped.append(f"{r['target']}: beyond policy {b}, receiver got {got}")
    vs = ", ".join(f"{k} {verdicts[k]}" for k in sorted(verdicts))
    print(f"race-c1: {len(paths)} runs; both checks in one block {same}; first callback 2 blocks after the last check {gap2}; "
          f"judge: {vs}; broke {len(broke)} ({', '.join(sorted(set(broke)))}); held {len(held)} ({', '.join(sorted(set(held)))}); "
          f"not counted {len(skipped)}" + (f" ({'; '.join(sorted(skipped))})" if skipped else ""))
    return len(skipped)


def main(argv):
    summ = "--summary" in argv
    paths = [a for a in argv if a != "--summary"]
    print("| file | guard | per leg: accepted → check → transfer → callback | judge | beyond policy |")
    print("|---|---|---|---|---|")
    for p in paths:
        print(row(p))
    if summ and not paths:
        print("race-c1: no runs")
        sys.exit(1)
    if summ and summary(paths):
        sys.exit(1)  # a run that is not counted fails the check (c1.sh exits non-zero)


if __name__ == "__main__":
    main(sys.argv[1:])
