#!/usr/bin/env python3
"""Exit 0 if two folders hold the same scripted attacks: same file names, same `name` and `steps`.

  python3 -I tools/mutation/same_scripted.py <gen-scripted output dir> sequences-scripted

The harness's gen-scripted writes `name` and `steps` only, compact. The library files add a
`meta` block (written by hand, and since 2026-11-12 meta.spec by a person and meta.admission by
tools/admission/admit.py) and are pretty-printed. Neither changes what the harness runs, so the
old byte-for-byte `diff -r` always printed "differs" (checked 2026-11-12 on main: all 10 files).
This compares what the harness runs. Prints each difference; never edits anything.
"""
import json, pathlib, sys

def norm(p):
    d = json.loads(p.read_text())
    return {"name": d.get("name"), "steps": d.get("steps")}


def main(a, b):
    a, b = pathlib.Path(a), pathlib.Path(b)
    na = sorted(p.name for p in a.glob("*.json"))
    nb = sorted(p.name for p in b.glob("*.json"))
    bad = 0
    if na != nb:
        print(f"different files: only in {a}: {sorted(set(na) - set(nb))}; only in {b}: {sorted(set(nb) - set(na))}")
        bad += 1
    for n in sorted(set(na) & set(nb)):
        if norm(a / n) != norm(b / n):
            print(f"differs: {n}")
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
