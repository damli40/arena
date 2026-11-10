#!/usr/bin/env python3
"""Compare an `arena check` report with what the board shows for the same guard.

  python3 -I tools/check/compare_board.py <report.json> <registry guard id>

The board's cells come from tools/hunter/board.py build(): for each attack, the newest trusted
hunt that ran it against that guard, classified with the same rule as `arena check`
(tools/check/applicable.py), so both sides can say held, broke or not-applicable. Attacks are
matched by id. The honest-payment control is not an attack and is skipped on both sides (older
reports still list it as a row). Prints one line per difference and a final count; exits 1 if
any attack differs in status or in tokens paid beyond the rules.
"""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "hunter"))
import board as B  # noqa: E402


def board(guard_id):
    return {c["attack"]: (c["result"], int(c.get("unauthorised") or 0), c["hunt_id"])
            for c in B.build()["cells"] if c["guard"] == guard_id and c["result"] in ("held", "broke", "not-applicable")}


def main(report, guard_id):
    rep = json.loads(pathlib.Path(report).read_text())
    b = board(guard_id)
    diffs, same, missing = [], 0, []
    for r in rep["attacks"]:
        if r["id"] == B.CONTROL_ID:
            continue
        if r["id"] not in b:
            missing.append(r["id"])
            continue
        st, amt, src = b[r["id"]]
        mine = int(r["beyond_policy"] or 0)
        if (st, amt) == (r["status"], mine):
            same += 1
        else:
            diffs.append(f"DIFF {r['id']}: check {r['status']} {r['beyond_policy']} vs board {st} {amt} ({src})")
    for line in diffs:
        print(line)
    for m in missing:
        print(f"NOT ON BOARD {m}")
    print(f"compare {pathlib.Path(report).parent.name} vs board[{guard_id}]: {same} same, {len(diffs)} different, "
          f"{len(missing)} not on the board (the honest-payment control is skipped on both sides)")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
