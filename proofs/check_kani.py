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
# 2026-11-11: world_full (dead callbacks, reconcile, resolve_stuck, outside transfer) and the
# inductive step (evidence/fix-plan-2026-11-11.md, evidence/proofs-inductive-2026-11-11.md).
H1 = "full: reconcile read balance == ledger although the tokens left (H1)"
FULLC = ["full: a callback died", H1, "full: on_reconcile settled Paid", "full: resolve_stuck closed an invoice as Failed",
         "full: resolve_stuck closed an invoice as Paid", "full: outside transfer, then a reconcile read after tokens left"]
FULL_FIXED = {"verdict": "SUCCESSFUL", "fails": [], "covers": {**{c: "SATISFIED" for c in FULLC}, DOUBLE: "UNSATISFIABLE"}}
FULL_OLD = {"verdict": "FAILED", "fails": [P1], "covers": {H1: "SATISFIED", DOUBLE: "SATISFIED"}}
FULL_VULN = {"verdict": "FAILED", "fails": [P1], "covers": {DOUBLE: "SATISFIED"}}
INV = "inductive step: the invariant still holds after any one action"
SLOT = "a pay accepted from an invariant state always has a free slot"
APPLIED = ["applied: " + a for a in ("pay", "transfer runs", "callback runs", "callback dies", "approve_invoice again", "reconcile",
                                    "on_reconcile", "resolve_stuck", "sync_ledger", "on_sync_ledger", "outside transfer")]
IND_FIXED = {"verdict": "SUCCESSFUL", "fails": [], "covers": {c: "SATISFIED" for c in APPLIED}}
IND_OLD = {"verdict": "FAILED", "fails": [INV], "covers": {c: "SATISFIED" for c in APPLIED}}
IND_VULN = {"verdict": "FAILED", "fails": [SLOT, INV], "covers": None}
IND_INIT = {"verdict": "SUCCESSFUL", "fails": [], "covers": None}
SAT = ["invariant satisfiable", "satisfiable: Pending, callback waiting after the tokens moved",
       "satisfiable: stuck Pending after a dead callback, tokens moved (the H1 state)",
       "satisfiable: closed as Failed, nothing sent", "satisfiable: Paid while its transfer is still in flight"]
IND_IMPLIES = {"verdict": "SUCCESSFUL", "fails": [], "covers": {c: "SATISFIED" for c in SAT}}
EXPECT = {"fixed_full_n2": FULL_FIXED, "old_reconcile_full_n2": FULL_OLD, "vulnerable_fixture_full_n2": FULL_VULN,
          "inductive_step_fixed_k2": IND_FIXED, "inductive_step_fixed_k3": IND_FIXED,
          "inductive_step_old_reconcile_k2": IND_OLD, "inductive_step_vulnerable_k2": IND_VULN,
          "inductive_init_k2": IND_INIT, "inductive_init_k3": IND_INIT, "invariant_implies_no_overpay_k2": IND_IMPLIES,
          "vulnerable_fixture_n3": VULN, "vulnerable_fixture_n4": VULN, "fixed_n3": FIXED, "fixed_n4": FIXED,
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
if want["fails"] and len(failed) != len(want["fails"]):
    problems.append(f"expected exactly {len(want['fails'])} failing check(s), got {failed}")
if want["covers"] is not None:
    for c, s in want["covers"].items():
        if covers.get(c) != s:
            problems.append(f"cover {c!r}: {covers.get(c)} != {s}")
summary = re.search(r"\*\* (\d+) of (\d+) failed", log)
print(f"RESULT kani harness={name} verdict={verdict} failed={failed} "
      f"checks={summary.group(2) if summary else '?'} covers={ {k[:24]: v for k, v in covers.items()} } "
      f"time={t.group(1) if t else '?'}s -> {'as planned' if not problems else 'SURPRISE: ' + '; '.join(problems)}")
sys.exit(1 if problems else 0)
