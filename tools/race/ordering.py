"""The one race-ordering judge (RACE-ORDERING-DESIGN section 7). Pure functions, no I/O.

Plain version: line the payments up by the block their guard check ran in. It is a race only if
the LAST check ran in a block STRICTLY BEFORE the FIRST callback. Same block is a tie: the trace
does not show the order inside one block, so a tie is never counted, for "held" and "broke" alike.

    ordering_verdict(legs) -> {"verdict", "last_check", "first_cb", "achieved_offsets", "reasons", "legs"}
    legs_of(result, step_indexes) -> the per-leg facts read from a harness result JSON

Verdicts:
  not-produced     a leg was not included / has no trace / a height is missing, a HOLD-TIMEOUT was
                   logged, a block in the step's range does not exist (a fast-forward), the legs ran
                   on different accounts, no leg reached a callback, or an achieved offset differs
                   from the requested one. Nothing about this run is scored.
  overlap-proven   last_check < first_cb: a race. Held or broke is now meaningful.
  tie-unproven     last_check == first_cb: neither a race nor a sequential test. Never counted.
  sequential       last_check > first_cb: payments in a row, whatever the balances say.
  A leg refused (no callback) in a block strictly before every paying leg's check is left out and
  the other legs are judged; if fewer than 2 remain, the verdict is sequential.

Per leg (from steps[].receipts, written by harness/src/receipts.rs):
  guard account  = executor of receipt 0 (the transaction's own call)
  check block    = block_height of receipt 0 (ok there = the check passed)
  callback block = the SMALLEST block_height among later receipts run by the guard account. The
                   smallest is the cautious choice: a guard with several later receipts (a refund,
                   a second callback) gets the earliest, which makes a race harder to claim.
"""

NOT_PRODUCED = "not-produced"
OVERLAP = "overlap-proven"
TIE = "tie-unproven"
SEQUENTIAL = "sequential"


def _int(x):
    return x if isinstance(x, int) and not isinstance(x, bool) else None


def leg_of(step):
    """One result step -> leg facts, or {"error": why}."""
    if step.get("outcome") in ("not-included", "protocol-rejected"):
        return {"error": f"leg {step.get('outcome')}"}
    tr = step.get("receipts")
    rs = tr.get("receipts") if isinstance(tr, dict) else None
    if not rs:
        return {"error": "no receipt trace"}
    guard = rs[0].get("executor")
    check = _int(rs[0].get("block_height"))
    if check is None:
        return {"error": "check block height missing"}
    later = [r for r in rs[1:] if r.get("executor") == guard]
    if any(_int(r.get("block_height")) is None for r in later):
        return {"error": "a guard receipt's block height is missing"}
    cb = min((r["block_height"] for r in later), default=None)
    race = tr.get("race") if isinstance(tr.get("race"), dict) else None
    return {
        "guard": guard,
        "check": check,
        "check_ok": bool(rs[0].get("ok")),
        "callback": cb,
        "requested_offset": race.get("requested_offset") if race else None,
        "blocks_contiguous": race.get("blocks_contiguous") if race else None,
        "hold_timeout": any("HOLD-TIMEOUT" in str(l) for l in step.get("logs") or []),
    }


def legs_of(result, idxs):
    steps = result.get("steps", [])
    out = []
    for i in idxs:
        if i >= len(steps):
            out.append({"error": f"step {i} not recorded"})
        else:
            out.append(leg_of(steps[i]))
    return out


def ordering_verdict(legs):
    reasons = []
    res = {"verdict": NOT_PRODUCED, "last_check": None, "first_cb": None, "achieved_offsets": None,
           "reasons": reasons, "legs": legs}
    if len(legs) < 2:
        reasons.append("fewer than 2 legs")
        return res
    for n, l in enumerate(legs, 1):
        if "error" in l:
            reasons.append(f"leg {n}: {l['error']}")
    if reasons:
        return res
    if any(l["hold_timeout"] for l in legs):
        reasons.append("HOLD-TIMEOUT logged: the slow token answered on its own, the order was not controlled")
    if any(l["blocks_contiguous"] is False for l in legs):
        reasons.append("a block in the step's range does not exist (fast-forward): heights are not blocks that ran")
    if len({l["guard"] for l in legs}) != 1:
        reasons.append("legs ran on different accounts")
    achieved = [l["check"] - legs[0]["check"] for l in legs]
    res["achieved_offsets"] = achieved
    requested = [l["requested_offset"] for l in legs]
    if any(r is not None for r in requested):
        if any(r is None for r in requested):
            reasons.append("some legs have a requested offset and some do not")
        elif achieved != requested:
            reasons.append(f"achieved offsets {achieved} differ from requested {requested}")
    cbs = [l["callback"] for l in legs if l["callback"] is not None]
    if not cbs:
        reasons.append("no leg reached a callback: nothing for the other checks to overlap")
    if reasons:
        return res
    # A leg refused (no callback) in a block strictly before every paying leg's check was refused
    # with nothing in flight yet, so it says nothing about a race (admission's rule, its T3 trace).
    # Such legs are left out and the rest judged as normal; with fewer than 2 left it is no race.
    first_pay = min(l["check"] for l in legs if l["callback"] is not None)
    early = [n for n, l in enumerate(legs, 1) if l["callback"] is None and l["check"] < first_pay]
    judged = [l for n, l in enumerate(legs, 1) if n not in early]
    for n in early:
        reasons.append(f"leg {n} left out: refused in block {legs[n - 1]['check']}, before any paying "
                       f"leg's check (block {first_pay}), so it did not overlap a payment in flight")
    last_check, first_cb = max(l["check"] for l in judged), min(cbs)
    res["last_check"], res["first_cb"] = last_check, first_cb
    if len(judged) < 2:
        res["verdict"] = SEQUENTIAL
        reasons.append("fewer than 2 legs left to judge: not a race")
        return res
    if last_check < first_cb:
        res["verdict"] = OVERLAP
        reasons.append(f"last check in block {last_check}, strictly before the first callback in block {first_cb}")
    elif last_check == first_cb:
        res["verdict"] = TIE
        reasons.append(f"last check and first callback both in block {last_check}: order inside a block is not recorded")
    else:
        res["verdict"] = SEQUENTIAL
        reasons.append(f"last check in block {last_check}, after the first callback in block {first_cb}")
    return res
