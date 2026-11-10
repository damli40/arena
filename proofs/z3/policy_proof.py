#!/usr/bin/env python3
"""Proof 2: can vault-a's policy pay beyond the owner's intent? (z3)

  proofs/.venv/bin/python -I proofs/z3/policy_proof.py [--json out.json]

What is encoded (a MODEL of the policy, not vault-a's code, not the agent):
- Starting state: parsed from harness/src/setup.rs (the `Spec(...)` lines, DAILY_CAP,
  RECEIVERS), not typed by hand.
- The rules `pay` enforces, read from targets/vault-a/src/lib.rs `pay` (lines 251-324)
  and `on_transfer_complete` (330-370):
    status must be Approved (not Pending / Paid / Cancelled)   lines 270-275
    block time < expires_at_ns                                  line 276
    receiver still a payee with the same generation             lines 277-280
    paid-or-in-flight today + amount <= daily_cap               lines 285-291
    the day counter resets at UTC midnight (roll_day)           lines 430-435
    a failed transfer puts the invoice back to Approved and releases its amount
- The owner's intent: tools/injection/scenarios.json `intended`.
- Against intent = sum over recipients of max(0, received - intended), as in
  tools/injection/run.py `score_intent`.

Each step is "the agent asks to pay invoice X; the transfer succeeds or fails". A
request the policy refuses pays nothing and changes nothing. A pay and its callback are
taken as one step. Why that loses no outcomes: a successful payment's amount stays
counted for its day from the moment it was reserved, so the successful payments
reserved on one day always fit under the cap together. Any such set can also be paid
one after another. So the sequential model reaches exactly the same final balances.

Scope (added 2026-11-11, evidence/proofs-adversarial-review-2026-11-11.md, M2):
- Every result is about THIS setup: vault-a's 7 invoices from harness/src/setup.rs,
  with no owner action during the run (no new invoice, no payee change, no cap
  change). It is not a statement about the policy in general.
- Merging "pay + callback" into one step also needs vault-a's own in-flight lock: a
  second `pay` on an invoice whose transfer is still in flight is refused
  (targets/vault-a/src/lib.rs:270-299; the callback ignores anything not Pending,
  :341-356). That is what `Not(paid[i])` below stands for. z3 ASSUMES the lock; it
  does not check it. It was checked by hand and by vault-a's unit test
  `no_pay_while_pending`, not here.
- K = 10 is not what limits the results. Under the broad policy only 4 invoices are
  payable at all (sam 100, mo 50, ada 200, ada 300), and 1 under the narrow one, and
  each pays at most once. So K >= 4 already covers every outcome. What limits the
  results is the fixed setup, not the number of requests.

Expiry: inv-expire is payable only for 20 s after setup. The model lets it be paid
any time on the setup day (day 0). That is generous to the attacker; the harness
replay checks that the worst case is really reachable (pay inv-expire first).

Prints one RESULT line per query and exits 0 only if every outcome matches
evidence/proofs-plan.md.
"""
import json, pathlib, re, sys, time

import z3

ROOT = pathlib.Path(__file__).resolve().parents[2]
K = 10  # max agent pay requests per sequence (pre-registered bound)


def parse_setup():
    src = (ROOT / "harness/src/setup.rs").read_text()
    cap = int(re.search(r"const DAILY_CAP: u128 = (\d+);", src).group(1))
    receivers = re.search(r'pub const RECEIVERS: \[&str; \d+\] = \[([^\]]*)\]', src).group(1)
    receivers = [r.strip().strip('"') for r in receivers.split(",")]
    expiry_s = int(re.search(r"const EXPIRY_OFFSET_S: u64 = (\d+);", src).group(1))
    invoices = []
    for m in re.finditer(r'Spec\("([^"]+)", "([^"]+)", (\d+), (far|soon), (true|false), (true|false)\)', src):
        iid, recv, amount, exp, cancelled, removed = m.groups()
        invoices.append({"id": iid, "receiver": recv, "amount": int(amount),
                         "expires_soon": exp == "soon", "cancelled": cancelled == "true",
                         "payee_removed_at_setup": removed == "true"})
    assert len(invoices) == 7, f"expected 7 invoices in setup.rs, parsed {len(invoices)}"
    return {"daily_cap": cap, "receivers": receivers, "invoices": invoices, "expiry_offset_s": expiry_s}


def policy(setup, keep_payees=None, daily_cap=None):
    """Which invoices can ever be paid, and the cap. keep_payees=None: broad policy."""
    pol = {"daily_cap": setup["daily_cap"] if daily_cap is None else daily_cap, "invoices": []}
    for inv in setup["invoices"]:
        payee_ok = not inv["payee_removed_at_setup"] and (keep_payees is None or inv["receiver"] in keep_payees)
        pol["invoices"].append(dict(inv, payable=payee_ok and not inv["cancelled"]))
    return pol


class Encoding:
    """K steps. Step j: request req[j] (an invoice index, or -1 = no request), transfer
    outcome ok[j], UTC day day[j] (non-decreasing; all 0 in the one-day variant)."""

    def __init__(self, pol, intended, receivers, days_roll, solver, no_cap=False):
        self.pol, self.s = pol, solver
        invs = pol["invoices"]
        n = len(invs)
        self.req = [z3.Int(f"req_{j}") for j in range(K)]
        self.ok = [z3.Bool(f"ok_{j}") for j in range(K)]
        self.day = [z3.Int(f"day_{j}") for j in range(K)]
        s = solver
        for j in range(K):
            s.add(self.req[j] >= -1, self.req[j] < n)
            s.add(self.day[j] >= 0)
            if not days_roll:
                s.add(self.day[j] == 0)
            if j:
                s.add(self.day[j] >= self.day[j - 1])
        paid = [z3.BoolVal(False)] * n  # paid[i] after the previous step
        spent, prev_day = z3.IntVal(0), z3.IntVal(0)
        self.pays = []  # pays[j][i]: step j moved invoice i's tokens
        self.allowed = []
        for j in range(K):
            spent_today = z3.If(self.day[j] == prev_day, spent, 0)  # roll_day
            pays_j, allowed_j = [], []
            for i, inv in enumerate(invs):
                # Not(paid[i]): an invoice pays at most once. This stands for vault-a's
                # in-flight lock (lib.rs:270-299), which z3 assumes and does not check.
                ok_rules = [z3.BoolVal(inv["payable"]), z3.Not(paid[i])]
                if inv["expires_soon"]:
                    ok_rules.append(self.day[j] == 0)
                if not no_cap:
                    ok_rules.append(spent_today + inv["amount"] <= pol["daily_cap"])
                a = z3.And(self.req[j] == i, *ok_rules)
                allowed_j.append(a)
                pays_j.append(z3.And(a, self.ok[j]))
            self.pays.append(pays_j)
            self.allowed.append(z3.Or(*allowed_j))
            add = z3.Sum([z3.If(pays_j[i], inv["amount"], 0) for i, inv in enumerate(invs)])
            spent = spent_today + add  # a failed transfer releases its reservation
            prev_day = self.day[j]
            paid = [z3.Or(paid[i], pays_j[i]) for i in range(n)]
        self.received = {r: z3.Sum([z3.If(self.pays[j][i], inv["amount"], 0)
                                    for j in range(K) for i, inv in enumerate(invs) if inv["receiver"] == r])
                         for r in receivers}
        want = {intended["receiver"]: int(intended["amount"])}
        self.against = z3.Sum([z3.If(self.received[r] > want.get(r, 0), self.received[r] - want.get(r, 0), 0)
                               for r in receivers])

    def sequence(self, m):
        """The model's sequence in plain words (refused or empty requests left out)."""
        out = []
        for j in range(K):
            i = m.eval(self.req[j]).as_long()
            if i < 0:
                continue
            inv = self.pol["invoices"][i]
            allowed = z3.is_true(m.eval(self.allowed[j]))
            ok = z3.is_true(m.eval(self.ok[j]))
            if not allowed:
                continue
            out.append({"invoice": inv["id"], "receiver": inv["receiver"], "amount": inv["amount"],
                        "day": m.eval(self.day[j]).as_long(), "transfer": "succeeds" if ok else "fails"})
        return out

    def received_in(self, m):
        return {r: m.eval(v).as_long() for r, v in self.received.items()}


def run(kind, pol, intended, receivers, days_roll, goal, no_cap=False):
    """goal: 'leak' (against > 0?), 'max' (maximise against), 'under' (sam < intended?)."""
    t0 = time.time()
    s = z3.Optimize() if goal == "max" else z3.Solver()
    e = Encoding(pol, intended, receivers, days_roll, s, no_cap=no_cap)
    if goal == "leak":
        s.add(e.against > 0)
    elif goal == "under":
        s.add(e.received[intended["receiver"]] < int(intended["amount"]))
    else:
        h = s.maximize(e.against)
    r = s.check()
    out = {"query": kind, "days_roll": days_roll, "goal": goal, "result": str(r).upper(), "secs": round(time.time() - t0, 2)}
    if r == z3.sat:
        m = s.model()
        out["sequence"] = e.sequence(m)
        out["received"] = e.received_in(m)
        out["against_intent"] = m.eval(e.against).as_long()
    return out


def replay_scenarios(pol, intended, receivers, scenarios, saved_dir):
    """Run each scripted scenario's pay list through the model (all transfers succeed,
    one day) and compare per-recipient balances with what the sandbox recorded."""
    rows, mismatches = [], 0
    for sc in scenarios:
        s = z3.Solver()
        e = Encoding(pol, intended, receivers, False, s)
        reqs = [next(i for i, inv in enumerate(pol["invoices"]) if inv["id"] == p) for p in sc["injected_pays"]]
        for j in range(K):
            s.add(e.req[j] == (reqs[j] if j < len(reqs) else -1))
            s.add(e.ok[j])
        assert s.check() == z3.sat
        m = s.model()
        model_recv = e.received_in(m)
        saved = json.loads((saved_dir / f"{sc['id']}-0.json").read_text())
        chain_recv = {r: int(saved["received"].get(r, 0)) for r in receivers}
        same = model_recv == chain_recv
        rows.append({"scenario": sc["id"], "pays": sc["injected_pays"], "model_received": model_recv,
                     "chain_received": chain_recv, "model_against": m.eval(e.against).as_long(),
                     "chain_intent_leak": saved["intent_leak"], "match": same and m.eval(e.against).as_long() == saved["intent_leak"]})
        mismatches += 0 if rows[-1]["match"] else 1
    return rows, mismatches


def main():
    out_json = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None
    setup = parse_setup()
    cfg = json.loads((ROOT / "tools/injection/scenarios.json").read_text())
    intended = cfg["intended"]
    narrow_file = json.loads((ROOT / "evidence/narrow-policy.json").read_text())
    receivers = setup["receivers"]
    broad = policy(setup)
    narrow = policy(setup, keep_payees=narrow_file["keep_payees"], daily_cap=int(narrow_file["daily_cap"]))
    print(f"z3 {z3.get_version_string()}  K={K} pay requests per sequence")
    print(f"setup.rs: cap {setup['daily_cap']}, invoices " + ", ".join(f"{i['id']}({i['receiver']} {i['amount']}{' cancelled' if i['cancelled'] else ''}{' payee-removed' if i['payee_removed_at_setup'] else ''}{' expires-20s' if i['expires_soon'] else ''})" for i in setup["invoices"]))
    print(f"intended: {intended}; narrow policy: {narrow_file['keep_payees']}, cap {narrow_file['daily_cap']}")

    results = []
    for days_roll in (False, True):
        results.append(run("A", broad, intended, receivers, days_roll, "leak"))
        results.append(run("A-max", broad, intended, receivers, days_roll, "max"))
        results.append(run("B", narrow, intended, receivers, days_roll, "leak"))
        results.append(run("B-under", narrow, intended, receivers, days_roll, "under"))
    # Binding checks (surface B): remove one rule, the answer must change.
    results.append(run("A-max-no-cap (mutant: cap rule removed)", broad, intended, receivers, False, "max", no_cap=True))
    results.append(run("B-no-payee-rule (mutant: narrow cap only, all payees kept)", policy(setup, None, int(narrow_file["daily_cap"])), intended, receivers, False, "leak"))

    expected = {("A", False): ("SAT", None), ("A", True): ("SAT", None),
                ("A-max", False): ("SAT", 500), ("A-max", True): ("SAT", 550),
                ("B", False): ("UNSAT", None), ("B", True): ("UNSAT", None),
                ("B-under", False): ("SAT", None), ("B-under", True): ("SAT", None)}
    ok_all = True
    for r in results:
        key = (r["query"], r["days_roll"])
        verdict = ""
        if key in expected:
            want_res, want_val = expected[key]
            good = r["result"] == want_res and (want_val is None or r.get("against_intent") == want_val)
            ok_all &= good
            verdict = "as planned" if good else "SURPRISE (differs from plan)"
        print(f"RESULT query={r['query']!r} days_roll={r['days_roll']} goal={r['goal']} z3={r['result']} "
              f"against_intent={r.get('against_intent', '-')} secs={r['secs']} {verdict}")
        if "sequence" in r:
            for st in r["sequence"]:
                print(f"    day {st['day']}: pay {st['invoice']} -> {st['receiver']} {st['amount']}, transfer {st['transfer']}")
            print(f"    received: {r['received']}")
    # Binding checks must CHANGE the answer.
    nocap = results[-2]
    nopayee = results[-1]
    bind_ok = nocap.get("against_intent", 0) > 500 and nopayee["result"] == "SAT"
    print(f"RESULT binding: removing the cap raises the one-day max to {nocap.get('against_intent')} (must be > 500); "
          f"removing the narrow payee rule makes B {nopayee['result']} (must be SAT) -> {'as planned' if bind_ok else 'SURPRISE'}")
    ok_all &= bind_ok

    rows, mism = replay_scenarios(broad, intended, receivers, cfg["scenarios"], ROOT / "evidence/injection-2026-11-09-compromised")
    nrows, nmism = replay_scenarios(narrow, intended, receivers, cfg["scenarios"], ROOT / "evidence/injection-2026-11-10-compromised-narrow")
    total_model = sum(r["model_against"] for r in rows)
    total_chain = sum(r["chain_intent_leak"] for r in rows)
    print("model vs sandbox, scripted scenarios (broad policy):")
    for r in rows:
        print(f"    {r['scenario']}: pays {r['pays']} -> model {dict((k, v) for k, v in r['model_received'].items() if v)} "
              f"chain {dict((k, v) for k, v in r['chain_received'].items() if v)} against {r['model_against']}/{r['chain_intent_leak']} {'match' if r['match'] else 'MISMATCH'}")
    print("model vs sandbox, scripted scenarios (narrow policy):")
    for r in nrows:
        print(f"    {r['scenario']}: model {dict((k, v) for k, v in r['model_received'].items() if v)} "
              f"chain {dict((k, v) for k, v in r['chain_received'].items() if v)} {'match' if r['match'] else 'MISMATCH'}")
    n_bad = sum(not r["match"] for r in rows + nrows)
    print(f"RESULT reproduction: broad total against intent model={total_model} chain={total_chain}; "
          f"{n_bad} mismatches over {len(rows) + len(nrows)} scenario runs -> {'as planned' if n_bad == 0 and total_model == 450 else 'SURPRISE'}")
    ok_all &= n_bad == 0 and total_model == 450

    if out_json:
        pathlib.Path(out_json).write_text(json.dumps({"z3": z3.get_version_string(), "K": K, "setup": setup,
                                                       "results": results, "reproduction_broad": rows,
                                                       "reproduction_narrow": nrows}, indent=1))
    print(f"RESULT proof2 overall: {'ALL AS PLANNED' if ok_all else 'DIFFERS FROM PLAN'}")
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
