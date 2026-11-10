#!/usr/bin/env python3
"""Compare an `arena check` report with what the board recorded for the same guard.

  python3 -I tools/check/compare_board.py <report.json> <registry guard id>

The board's numbers come from the trusted hunt files (evidence/hunts/*.json): for each attack,
the newest trusted hunt that ran it against that guard. Attacks are matched by id. Prints one
line per difference and a final count; exits 1 if any attack differs in status or in tokens
paid beyond the rules.
"""
import glob, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def board(guard_id):
    seen = {}
    for f in sorted(glob.glob(str(ROOT / "evidence/hunts/*.json"))):
        d = json.loads(pathlib.Path(f).read_text())
        if not isinstance(d, dict) or not d.get("trusted") or "attacks" not in d:
            continue
        for a in d["attacks"]:
            c = a.get("results", {}).get(guard_id)
            if c and c.get("status") in ("held", "broke"):
                seen[a["id"]] = (c["status"], int(c.get("unauthorised", 0)), pathlib.Path(f).name)
    return seen


def main(report, guard_id):
    rep = json.loads(pathlib.Path(report).read_text())
    b = board(guard_id)
    diffs, same, missing = [], 0, []
    for r in rep["attacks"]:
        if r["id"] not in b:
            missing.append(r["id"])
            continue
        st, amt, src = b[r["id"]]
        if (st, amt) == (r["status"], int(r["beyond_policy"] or 0)):
            same += 1
        else:
            diffs.append(f"DIFF {r['id']}: check {r['status']} {r['beyond_policy']} vs board {st} {amt} ({src})")
    for line in diffs:
        print(line)
    for m in missing:
        print(f"NOT ON BOARD {m}")
    print(f"compare {pathlib.Path(report).parent.name} vs board[{guard_id}]: {same} same, {len(diffs)} different, {len(missing)} not on the board")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
