#!/usr/bin/env python3
"""Proof 3: can a direct-pay guard pay beyond its own policy? (z3)

  proofs/.venv/bin/python -I proofs/z3/direct_pay_proof.py [K] [--json out.json]

A direct-pay guard: the agent names the receiver and the amount itself, and the guard
checks the request against the owner's rules (per-payment cap, daily cap, payee list,
approval threshold, refund on failure). This is a MODEL of those rules, not
any guard's code. What it is good for: it checks the rule DESIGN for every policy, every
amount and every order of events at once, which a test of one policy cannot.

What is symbolic (z3 chooses it, so a "holds" covers every choice):
- the policy: per-payment cap P > 0, daily cap D > 0, approval threshold T >= 0 (no
  relation between them is assumed), and which of 3 receivers are on the payee list;
- every step, up to K steps: which kind (agent request, a request by someone else, a
  transfer's callback, owner approve, owner reject, UTC midnight, nothing), and for a
  request its receiver and amount (any integer), for a callback which in-flight payment
  it belongs to and whether the transfer succeeded.

The guard, as modelled (one flag per design choice that differs between real guards):
- A request is refused unless: the caller is the agent; amount > 0; receiver on the list;
  amount <= P; and, for a payment that is not held, spent_today + amount <= D.
- amount > T: the request is HELD (nothing moves). `hold_counts`: "request" = it counts
  against today at once and expires at midnight;
  "approve" = it counts only when the owner approves, on the approve day, and never
  expires.
- Otherwise the payment starts: `charge`: "request" = spent_today += amount before the
  transfer (reserve, then transfer); "callback" = only after the transfer succeeds.
- A failed transfer gives the amount back. `refund`: "request_day" = only if the day has
  not changed since it was charged; "current_day" = from whatever today's counter is
  (saturating at 0).
- Midnight sets spent_today = 0.

Properties (each asked as "is there ANY run that breaks it?"; UNSAT = no run breaks it):
- agent_only: every delivered payment was requested by the agent;
- payee: every delivered payment went to a receiver on the list;
- hold: every delivered payment the owner did not approve is <= T;
- pertx: every delivered payment, approved or not, is <= P;
- daily: for every day, the delivered payments the agent started that day without
  approval add up to <= D;
- daily_incl_approved: the same, counting owner-approved payments by the day they were
  requested (only the hold-at-request design claims this).

Scope, said plainly:
- A model of the rules, not code. The tie to real code is the separate bounded checks of
  each guard's real source (private; counts in evidence/proofs-all-2026-11-11.md).
- Fixed allow-list during the run (no owner removes a payee); no pause (a paused guard
  refuses everything, so it can only lower what is paid); one agent; no vault balance
  limit (a balance check can only refuse more); amounts are unbounded integers (real
  guards use u128 and panic on overflow, which refuses).
- Bound: K steps. A "holds" means no run of up to K steps breaks it.

Prints one RESULT line per (variant, property) and exits 0 only if every outcome is the
expected one (written in EXPECT below before any run).
"""
import json, sys, time

import z3

K = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8
NRCV = 3
REQ, OTHER, CB, APPROVE, REJECT, ROLL, NOP = range(7)
# flight status
NONE, HELD, FLY, FLY_APPR, OK, FAIL, REJ = range(7)

# variant: (hold_counts, charge, refund, mutation)
VARIANTS = {
    "hold-at-request/refund-same-day": ("request", "request", "request_day", None),
    "hold-at-approve/refund-today": ("approve", "request", "current_day", None),
    "hold-at-approve/refund-same-day": ("approve", "request", "request_day", None),
    # planted design flaws on the hold-at-request design (each must break a property)
    "mut-charge-after-transfer": ("request", "callback", "request_day", None),
    "mut-cap-ignores-amount": ("request", "request", "request_day", "cap_ignores_amount"),
    "mut-no-hold": ("request", "request", "request_day", "no_hold"),
    "mut-no-payee-check": ("request", "request", "request_day", "no_payee_check"),
    "mut-no-pertx": ("request", "request", "request_day", "no_pertx"),
    "mut-other-caller": ("request", "request", "request_day", "other_caller"),
}
PROPS = ["agent_only", "payee", "hold", "pertx", "daily", "daily_incl_approved"]
H, V = "holds", "VIOLATED"
EXPECT = {
    "hold-at-request/refund-same-day": dict(agent_only=H, payee=H, hold=H, pertx=H, daily=H, daily_incl_approved=H),
    # a refund landing after midnight lowers the NEW day's counter:
    "hold-at-approve/refund-today": dict(agent_only=H, payee=H, hold=H, pertx=H, daily=V, daily_incl_approved=V),
    "hold-at-approve/refund-same-day": dict(agent_only=H, payee=H, hold=H, pertx=H, daily=H, daily_incl_approved=V),
    "mut-charge-after-transfer": dict(agent_only=H, payee=H, hold=H, pertx=H, daily=V, daily_incl_approved=V),
    "mut-cap-ignores-amount": dict(agent_only=H, payee=H, hold=H, pertx=H, daily=V, daily_incl_approved=V),
    "mut-no-hold": dict(agent_only=H, payee=H, hold=V, pertx=H, daily=H, daily_incl_approved=H),
    "mut-no-payee-check": dict(agent_only=H, payee=V, hold=H, pertx=H, daily=H, daily_incl_approved=H),
    "mut-no-pertx": dict(agent_only=H, payee=H, hold=H, pertx=V, daily=H, daily_incl_approved=H),
    "mut-other-caller": dict(agent_only=V, payee=H, hold=H, pertx=H, daily=H, daily_incl_approved=H),
}


def build(variant):
    hold_counts, charge, refund, mut = VARIANTS[variant]
    P, D, T = z3.Ints("P D T")
    listed = [z3.Bool(f"listed_{i}") for i in range(NRCV)]
    base = [P > 0, D > 0, T >= 0]
    kind = [z3.Int(f"kind_{s}") for s in range(K)]
    rcv = [z3.Int(f"rcv_{s}") for s in range(K)]
    amt = [z3.Int(f"amt_{s}") for s in range(K)]
    tgt = [z3.Int(f"tgt_{s}") for s in range(K)]
    okv = [z3.Bool(f"ok_{s}") for s in range(K)]
    for s in range(K):
        base += [kind[s] >= 0, kind[s] <= NOP, rcv[s] >= 0, rcv[s] < NRCV, tgt[s] >= 0, tgt[s] < max(s, 1)]
    spent, day = z3.IntVal(0), z3.IntVal(0)
    st = [z3.IntVal(NONE)] * K  # status of the flight started at step f
    rday = [z3.IntVal(0)] * K  # day the request was made
    cday = [z3.IntVal(-1)] * K  # day its amount was charged (-1 = not charged)
    appr = [z3.BoolVal(False)] * K
    for s in range(K):
        k, r, a = kind[s], rcv[s], amt[s]
        is_listed = z3.Or([z3.And(r == i, listed[i]) for i in range(NRCV)])
        caller_ok = (k == REQ) if mut != "other_caller" else z3.Or(k == REQ, k == OTHER)
        payee_ok = is_listed if mut != "no_payee_check" else z3.BoolVal(True)
        pertx_ok = a <= P if mut != "no_pertx" else z3.BoolVal(True)
        held = (a > T) if mut != "no_hold" else z3.BoolVal(False)
        cap_ok = (spent + a <= D) if mut != "cap_ignores_amount" else (spent <= D)
        accept = z3.And(caller_ok, a > 0, payee_ok, pertx_ok, z3.Or(held, cap_ok))
        if hold_counts == "request":
            # a held payment also counts against today, so it must fit too
            accept = z3.And(accept, cap_ok)
        is_held = z3.And(accept, held)
        is_direct = z3.And(accept, z3.Not(held))
        charge_now = z3.Or(z3.And(is_direct, charge == "request"), z3.And(is_held, hold_counts == "request"))
        new_spent = z3.If(charge_now, spent + a, spent)
        # the flight started at this step
        st_s = z3.If(is_held, HELD, z3.If(is_direct, FLY, NONE))
        cday_s = z3.If(charge_now, day, -1)
        nst, ncday, nappr = list(st), list(cday), list(appr)
        nst[s], ncday[s], rday_s = st_s, cday_s, day
        for f in range(s):
            fa = amt[f]
            hit = tgt[s] == f
            # callback of an in-flight payment
            cb = z3.And(k == CB, hit, z3.Or(st[f] == FLY, st[f] == FLY_APPR))
            charged = cday[f] >= 0
            if refund == "request_day":
                give_back = z3.If(z3.And(charged, cday[f] == day), fa, 0)
            else:
                give_back = z3.If(charged, z3.If(new_spent >= fa, fa, new_spent), 0)
            after_cb = z3.If(okv[s], z3.If(z3.And(charge == "callback", z3.Not(charged)), new_spent + fa, new_spent), new_spent - give_back)
            # owner approves a held payment
            can_appr = z3.And(k == APPROVE, hit, st[f] == HELD)
            if hold_counts == "request":
                can_appr = z3.And(can_appr, rday[f] == day)  # expired at midnight otherwise
            after_appr = new_spent if hold_counts == "request" else new_spent + fa
            # owner rejects a held payment (gives today's reservation back, hold-at-request design)
            rej = z3.And(k == REJECT, hit, st[f] == HELD)
            after_rej = z3.If(z3.And(cday[f] >= 0, cday[f] == day), new_spent - fa, new_spent)
            new_spent = z3.If(cb, after_cb, z3.If(can_appr, after_appr, z3.If(rej, after_rej, new_spent)))
            nst[f] = z3.If(cb, z3.If(okv[s], OK, FAIL), z3.If(can_appr, FLY_APPR, z3.If(rej, REJ, st[f])))
            nappr[f] = z3.Or(appr[f], can_appr)
            if hold_counts == "approve":
                ncday[f] = z3.If(can_appr, day, cday[f])
            ncday[f] = z3.If(z3.And(cb, z3.Not(okv[s])), -1, ncday[f]) if refund == "request_day" else ncday[f]
        roll = k == ROLL
        spent = z3.If(roll, z3.IntVal(0), new_spent)
        day = z3.If(roll, day + 1, day)
        st, cday, appr = nst, ncday, nappr
        rday = rday[:s] + [rday_s] + rday[s + 1:]
    delivered = [st[f] == OK for f in range(K)]
    q = {}
    q["agent_only"] = z3.Or([z3.And(delivered[f], kind[f] == OTHER) for f in range(K)])
    q["payee"] = z3.Or([z3.And(delivered[f], z3.Not(z3.Or([z3.And(rcv[f] == i, listed[i]) for i in range(NRCV)]))) for f in range(K)])
    q["hold"] = z3.Or([z3.And(delivered[f], z3.Not(appr[f]), amt[f] > T) for f in range(K)])
    q["pertx"] = z3.Or([z3.And(delivered[f], amt[f] > P) for f in range(K)])
    dd = z3.Int("dd")
    q["daily"] = z3.Sum([z3.If(z3.And(delivered[f], z3.Not(appr[f]), rday[f] == dd), amt[f], 0) for f in range(K)]) > D
    q["daily_incl_approved"] = z3.Sum([z3.If(z3.And(delivered[f], rday[f] == dd), amt[f], 0) for f in range(K)]) > D
    return base, q, dict(P=P, D=D, T=T, kind=kind, rcv=rcv, amt=amt, tgt=tgt, ok=okv, listed=listed, dd=dd)


NAMES = {REQ: "agent request", OTHER: "request by someone else", CB: "callback", APPROVE: "owner approves", REJECT: "owner rejects", ROLL: "UTC midnight", NOP: "nothing"}


def explain(m, v):
    out = [f"policy P={m.eval(v['P'])} D={m.eval(v['D'])} T={m.eval(v['T'])} listed={[z3.is_true(m.eval(x)) for x in v['listed']]}"]
    for s in range(K):
        k = m.eval(v["kind"][s]).as_long()
        if k == NOP:
            continue
        line = f"  step {s}: {NAMES[k]}"
        if k in (REQ, OTHER):
            line += f" receiver={m.eval(v['rcv'][s])} amount={m.eval(v['amt'][s])}"
        elif k == CB:
            line += f" for step {m.eval(v['tgt'][s])} transfer {'ok' if z3.is_true(m.eval(v['ok'][s])) else 'FAILED'}"
        elif k in (APPROVE, REJECT):
            line += f" step {m.eval(v['tgt'][s])}"
        out.append(line)
    out.append(f"  over-paid day: {m.eval(v['dd'])}")
    return out


def main():
    results, bad = [], 0
    t_all = time.time()
    for variant in VARIANTS:
        base, q, v = build(variant)
        for prop in PROPS:
            s = z3.Solver()
            s.add(base)
            s.add(q[prop])
            t0 = time.time()
            r = s.check()
            dt = time.time() - t0
            got = H if r == z3.unsat else (V if r == z3.sat else "unknown")
            want = EXPECT[variant][prop]
            mark = "as expected" if got == want else "UNEXPECTED"
            if got != want:
                bad += 1
            print(f"RESULT {variant:<32} {prop:<20} {got:<9} K={K} ({dt:.1f}s) {mark}")
            row = dict(variant=variant, property=prop, result=got, expected=want, k=K, secs=round(dt, 2))
            if r == z3.sat:
                ex = explain(s.model(), v)
                row["counterexample"] = ex
                if variant in ("hold-at-request/refund-same-day", "hold-at-approve/refund-today") or got != want:
                    for line in ex:
                        print("      " + line)
            results.append(row)
    print(f"z3 {z3.get_version_string()}, {len(results)} queries, {time.time() - t_all:.0f} s, unexpected: {bad}")
    if "--json" in sys.argv:
        json.dump(results, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
