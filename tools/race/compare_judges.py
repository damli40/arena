#!/usr/bin/env python3
"""Run both race-ordering judges on every stored run of one admission gate folder and say whether they agree.

  python3 -I tools/race/compare_judges.py <attack.json> <evidence/admission/<id>/<stamp>>

The gate's judge is tools/admission/admit.py:race_ordering; the second is tools/race/ordering.py:ordering_verdict.
Their verdict names differ; this maps admit's onto ordering.py's: proven = overlap-proven, not-overlapping =
sequential, a tie = tie-unproven, any other unproven = not-produced. Prints JSON; exit 0 only if every run agrees.
No sandbox: it reads the stored result files only.
"""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "tools" / "admission"), str(ROOT / "tools" / "race"), str(ROOT / "tools" / "hunter")]
import admit, ordering  # noqa: E402

MAP = {"proven": ordering.OVERLAP, "not-overlapping": ordering.SEQUENTIAL}


def compare(doc, folder):
    ev = json.loads((folder / "admission.json").read_text())
    _, races = admit.recorded_layout(doc["steps"])
    rows, agree = [], True
    for r in ev["runs"]:
        if not r["file"]:
            rows.append({"reference": r["reference"], "n": r["n"], "admit": None, "ordering_py": None, "agree": False,
                         "why": "no stored result (harness error): neither judge has anything to read"})
            agree = False
            continue
        res = json.loads((folder / r["file"]).read_text())
        for k, idx in enumerate(races):
            a = admit.race_ordering(res, idx)
            o = ordering.ordering_verdict(ordering.legs_of(res, idx))
            want = MAP.get(a["status"]) or (ordering.TIE if a.get("tie") else ordering.NOT_PRODUCED)
            ok = want == o["verdict"]
            agree &= ok
            rows.append({"reference": r["reference"], "n": r["n"], "race": k, "counted_by_gate": r["counted"],
                         "admit": a["status"] + (" (tie)" if a.get("tie") else ""), "ordering_py": o["verdict"], "agree": ok,
                         "admit_why": a["why"], "ordering_py_why": "; ".join(o["reasons"])})
    return {"attack_id": ev["attack_id"], "gate_folder": str(folder), "class": ev["class"], "races_per_run": len(races),
            "runs": len(ev["runs"]), "all_agree": agree, "rows": rows}


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    out = compare(json.loads(pathlib.Path(argv[0]).read_text()), pathlib.Path(argv[1]))
    print(json.dumps(out, indent=1))
    return 0 if out["all_agree"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
