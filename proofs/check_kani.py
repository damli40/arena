#!/usr/bin/env python3
"""Reads one Kani log and checks it against the pre-registered expectation.

  python3 -I proofs/check_kani.py <log> <harness-name>

Prints one RESULT line; exits 0 only if the verdict, the failing check and every
cover status match evidence/proofs-plan.md (and its addendum)."""
import re, sys

RACE = "race: two inv-a payments in flight at once"
DOUBLE = "double pay reached: 200 sent on the 100 invoice"
ONCE = "inv-a paid exactly once"
REFUSED = "a pay refused because a payment is in flight"
RETRY = "a pay accepted again after a failed transfer"
P1 = "P1: tokens sent for an invoice never exceed its amount"

VULN = {"verdict": "FAILED", "fails": [P1], "covers": {RACE: "SATISFIED", DOUBLE: "SATISFIED", ONCE: "SATISFIED", REFUSED: "UNSATISFIABLE", RETRY: "SATISFIED"}}
FIXED = {"verdict": "SUCCESSFUL", "fails": [], "covers": {RACE: "UNSATISFIABLE", DOUBLE: "UNSATISFIABLE", ONCE: "SATISFIED", REFUSED: "SATISFIED", RETRY: "SATISFIED"}}
MUTANT = {"verdict": "FAILED", "fails": [P1], "covers": {RACE: "SATISFIED", DOUBLE: "SATISFIED", ONCE: "SATISFIED", REFUSED: "UNSATISFIABLE", RETRY: "SATISFIED"}}
SHORT = {"verdict": "FAILED", "fails": ["unwinding assertion"], "covers": None}
EXPECT = {"vulnerable_fixture_n3": VULN, "vulnerable_fixture_n4": VULN, "fixed_n3": FIXED, "fixed_n4": FIXED,
          "fixed_mutant_no_pending_write_n3": MUTANT, "fixed_n3_bound_too_small": SHORT}

log, name = open(sys.argv[1]).read(), sys.argv[2]
want = EXPECT[name]
checks = re.findall(r'^Check \d+: .*?\n\t - Status: (\w+)\n\t - Description: "(.*?)"\n', log, flags=re.M | re.S)
verdict = re.search(r"VERIFICATION:- (\w+)", log)
verdict = verdict.group(1) if verdict else "NONE"
failed = [d.strip('"') for s, d in checks if s == "FAILURE"]
covers = {d: s for s, d in checks if s in ("SATISFIED", "UNSATISFIABLE", "UNREACHABLE")}
t = re.search(r"Verification Time: ([\d.]+)s", log)
problems = []
if verdict != want["verdict"]:
    problems.append(f"verdict {verdict} != {want['verdict']}")
if any(not any(w in f for f in failed) for w in want["fails"]) or (not want["fails"] and failed):
    problems.append(f"failed checks {failed} != {want['fails']}")
if want["fails"] and len(failed) != 1:
    problems.append(f"expected exactly one failing check, got {failed}")
if want["covers"] is not None:
    for c, s in want["covers"].items():
        if covers.get(c) != s:
            problems.append(f"cover {c!r}: {covers.get(c)} != {s}")
summary = re.search(r"\*\* (\d+) of (\d+) failed", log)
print(f"RESULT kani harness={name} verdict={verdict} failed={failed} "
      f"checks={summary.group(2) if summary else '?'} covers={ {k[:24]: v for k, v in covers.items()} } "
      f"time={t.group(1) if t else '?'}s -> {'as planned' if not problems else 'SURPRISE: ' + '; '.join(problems)}")
sys.exit(1 if problems else 0)
