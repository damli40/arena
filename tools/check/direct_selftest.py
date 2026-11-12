"""Evaluator self-tests for the direct-pay path (docs/GUARD-CAPABILITIES.md section 5).

    python3 tools/check/direct_selftest.py --out DIR [--jobs 4] [--only S1,S13]

Each self-test runs the whole direct check (direct_check.py) against the test fixture
fixtures/direct-fixture/direct_fixture.wasm in one mode (one deliberate defect, or none), and
asserts the result the design demands. A self-test passes only if its "must" holds AND its
"never" does not. Exit 0 only if every self-test passed.

The point: a missing method, a broken mapping or a guard that does something other than what was
asked must never come out as held, and must never come out as broke either.
"""
import argparse, json, pathlib, sys, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import direct_check as D  # noqa: E402

ROOT = D.ROOT
FIX = ROOT / "fixtures" / "direct-fixture"
WASM = FIX / "direct_fixture.wasm"
BASE = json.loads((FIX / "guard-config.json").read_text())
# One-change variants of the fixture (same methods), for the forged-callback checks S25 to S29.
WASM_CB_AMOUNT = ROOT / "fixtures" / "direct-fixture-cb-amount" / "direct_fixture_cb_amount.wasm"
WASM_ID_NUMBER = ROOT / "fixtures" / "direct-fixture-id-number" / "direct_fixture_id_number.wasm"
WASM_AMTCHK = ROOT / "fixtures" / "direct-fixture-amtchk" / "direct_fixture_amtchk.wasm"
WASM_NONCE = ROOT / "fixtures" / "direct-fixture-nonce" / "direct_fixture_nonce.wasm"
WASM_CBRES = ROOT / "fixtures" / "direct-fixture-cbres" / "direct_fixture_cbres.wasm"


def results(rep, dirs=None):
    return [a for a in rep.get("attacks", []) if dirs is None or a["dir"] in dirs]


def labels(rep, dirs=None):
    return {a["attack"]: a["result"] for a in results(rep, dirs)}


def none_of(rep, bad):
    hit = [a["attack"] for a in results(rep) if a["result"] in bad]
    return (not hit, f"{bad} on {hit}" if hit else "")


def gate_failed(rep, seq, text=None):
    g = rep.get("gate", {}).get(seq)
    if g is None or g["passed"]:
        return False, f"{seq} did not fail"
    if text and text not in g["why"]:
        return False, f"{seq} failed, but without '{text}': {g['why']}"
    return True, g["why"]


def all_cnf(rep, rule=None):
    rows = [a for a in results(rep) if rule is None or a["rule"] == rule]
    bad = [a["attack"] + "=" + a["result"] for a in rows if a["result"] != D.CNF]
    return (bool(rows) and not bad, f"not 'could not finish': {bad}" if bad else f"{len(rows)} attack(s) could not finish")


def s1_like(seq, text=None):
    def f(rep):
        ok, why = gate_failed(rep, seq, text)
        if not ok:
            return False, why
        if not rep["verdict"].startswith("could not finish"):
            return False, f"verdict is {rep['verdict']!r}"
        ok2, why2 = all_cnf(rep)
        return ok2, f"{seq}: {why}; {why2}"
    return f


def s8(rep):
    v = [r for r, s in rep["rules_status"].items() if not r.startswith("_") and s.get("validated")]
    ok, why = none_of(rep, [D.HELD, D.BROKE])
    return (not v and ok, f"validated rules: {v}; {why or 'no attack held or broke'}")


def s9(rep):
    ok, why = all_cnf(rep, "allowlist")
    # d09's key step is refused by NEAR whatever the guard does, so it may honestly say so.
    rows = [a for a in results(rep) if a["rule"] == "allowlist" and a["attack"] != "d09-agent-key-sets-policy"]
    bad = [a["attack"] + "=" + a["result"] for a in rows if a["result"] != D.CNF]
    return (not bad and not rep["rules_status"]["allowlist"]["validated"], f"allowlist attacks: {bad or 'all could not finish'}")


def s10(rep):
    a = rep["rules_status"]["approval"]
    lab = labels(rep).get("d07-skip-approval")
    return (not a["validated"] and lab == D.CNF, f"approval validated={a['validated']}; d07={lab}; {a.get('g6_why')}")


def s11(rep):
    st = rep["rules_status"]
    no_effect = all(not st[r]["g5_effect"] for r in ("allowlist", "per_payment", "window_utc_day"))
    l = labels(rep)
    ok, why = none_of(rep, [D.BROKE])
    d08 = l.get("d08-outsider-sets-policy")
    return (no_effect and ok and d08 == D.CNF, f"G5 effect on no rule={no_effect}; d08={d08}; {why or 'nothing broke'}")


def s13(rep):
    bad = [a["attack"] + "=" + a["result"] for a in results(rep) if a["result"] not in (D.HELD, D.KEY)]
    hr = [a["attack"] for a in results(rep) if a.get("honest_refusal_units") and a["attack"].startswith("d")]
    return (not bad and not hr, f"not held: {bad}; honest refusals: {hr}" if bad or hr else f"held {sum(1 for a in results(rep) if a['result'] == D.HELD)}, access key {sum(1 for a in results(rep) if a['result'] == D.KEY)}")


def only_broke(name, dirs):
    def f(rep):
        l = labels(rep, dirs)
        broke = sorted(a for a, r in l.items() if r == D.BROKE)
        return (broke == [name], f"broke in {dirs}: {broke}")
    return f


def s15(rep):
    a = [x for x in results(rep) if x["attack"] == "d06-failed-payment-burns-budget"]
    if not a:
        return False, "d06 missing"
    a = a[0]
    return (a["result"] == D.HELD and a.get("honest_refusal_units") == 100 and "HONEST REFUSAL" in a["why"], f"d06={a['result']}: {a['why'][:200]}")


def wrong_callback(rep):
    l = labels(rep, ["sequences-incidents"]).get("i03-forged-callback")
    cb = rep["rules_status"].get("_callback", {})
    return (l == D.CNF and not cb.get("confirmed"), f"i03={l}; callback confirmed={cb.get('confirmed')}; {cb.get('why', '')[:160]}")


def not_held_on(name):
    def f(rep):
        l = labels(rep, ["sequences-incidents"]).get(name)
        return (l in (D.CNF, D.BROKE), f"{name}={l}")
    return f


def cfg_with(mode=None, pay_method=None, callback=None):
    c = json.loads(json.dumps(BASE))
    if mode:
        c["init"]["args"]["mode"] = mode
    if pay_method:
        c["direct"]["pay"]["method"] = pay_method
    if callback:
        c["direct"]["callback"]["method"] = callback
    return c


TESTS = [
    # id, what, config, must, never
    ("S1", "spend succeeds and moves nothing", cfg_with("noop"), s1_like("g2-honest-sam"), "held"),
    ("S2", "mapping points pay at a method that pays nothing (list_pending)", cfg_with("correct", "list_pending"), s1_like("g2-honest-sam"), "held"),
    ("S3", "always pays 50 to sam, whatever it is asked", cfg_with("constant"), s1_like("g3-honest-ada"), "held"),
    ("S4", "pays the right amount to the wrong account (the agent itself)", cfg_with("wrong_receiver"), s1_like("g2-honest-sam"), "held"),
    ("S5", "pays twice the amount asked", cfg_with("double"), s1_like("g2-honest-sam"), "held"),
    ("S6", "holds every request for approval", cfg_with("hold_all"), s1_like("g2-honest-sam", "every legitimate payment was held"), "held"),
    ("S7", "refuses everything", cfg_with("refuse_all"), s1_like("g2-honest-sam"), "held"),
    ("S8", "pays the first request on each sandbox, refuses the rest", cfg_with("pay_once"), s8, "held or broke"),
    ("S9", "ignores the allowlist", cfg_with("ignore_allowlist"), s9, "held on the allowlist rule"),
    ("S10", "approve and reject swapped", cfg_with("swap_approve"), s10, "held on the approval rule"),
    ("S11", "the owner's set-policy changes the view, not what is enforced", cfg_with("noop_update_policy"), s11, "broke; held on d08"),
    ("S13", "correct direct-pay guard (negative control)", cfg_with("correct"), s13, "broke"),
    ("S14", "day total charged only in the callback (concurrent spends all pass; positive control)", cfg_with("cap_race"), only_broke("d04-race-the-day-limit", ["sequences-direct"]), "held on d04"),
    ("S15", "a failed payment keeps its charge against the day limit", cfg_with("budget_burn"), s15, "silent"),
    ("S20", "public callback that keeps settled records (positive control for i03)", cfg_with("public_callback"), only_broke("i03-forged-callback", ["sequences-incidents"]), "held on i03"),
    ("S21", "a failed payment gives back twice its amount (positive control for i01)", cfg_with("refund_twice"), only_broke("i01-failed-transfer-accounting", ["sequences-incidents"]), "held on i01"),
    ("S22", "day total charged only in the callback, on the incident set (positive control for i02)", cfg_with("cap_race"), only_broke("i02-calls-between-payment-and-callback", ["sequences-incidents"]), "held on i02"),
    ("S23", "public callback guard, callback mapped to get_mode (a view that never moves money)", cfg_with("public_callback", callback="get_mode"), wrong_callback, "held or broke on i03"),
    ("S24", "public callback guard, callback mapped to list_pending (a view that never moves money)", cfg_with("public_callback", callback="list_pending"), wrong_callback, "held or broke on i03"),
    ("S25", "public callback that takes a second argument only the guard's own call passes (forge copies it)", cfg_with("public_callback"), only_broke("i03-forged-callback", ["sequences-incidents"]), "held on i03", WASM_CB_AMOUNT),
    ("S26", "public callback; spend returns the id as a number, the callback wants a string (no forge can be built)", cfg_with("public_callback"), wrong_callback, "held or broke on i03", WASM_ID_NUMBER),
    ("S27", "public callback that refuses unless the amount matches the transfer (the forge sends the guard's own amount)", cfg_with("public_callback"), only_broke("i03-forged-callback", ["sequences-incidents"]), "held on i03", WASM_AMTCHK),
    ("S28", "public callback that refuses unless a nonce matches (the forge sends the guard's own nonce)", cfg_with("public_callback"), only_broke("i03-forged-callback", ["sequences-incidents"]), "held on i03", WASM_NONCE),
    ("S29", "public #[callback_result] callback: a direct call fails reading the promise result, before the guard's logic", cfg_with("public_callback"), not_held_on("i03-forged-callback"), "held on i03", WASM_CBRES),
]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only")
    a = ap.parse_args(argv)
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    only = set(a.only.split(",")) if a.only else None
    rows, reports = [], {}
    # S12: a wasm without the mapped pay method stops at G0 with exit 2, before any sandbox.
    if not only or "S12" in only:
        t = ROOT / "targets" / "leaky-control" / "leaky_control.wasm"
        cands = [t] + sorted((ROOT / "targets").glob("*/*.wasm"))
        w = next((p for p in cands if p.exists() and "spend" not in D.wasm_exports.methods(p.read_bytes())), None)
        cf_ = out / "S12.config.json"
        cf_.write_text(json.dumps(cfg_with("correct")))
        rep, rc = D.check(w, cf_, out / "S12", a.jobs, label="S12")
        ok = rc == 2 and not (out / "S12" / "gate").exists()
        rows.append(("S12", f"wasm without the mapped pay method ({w.relative_to(ROOT)})", ok, f"exit {rc}; {rep['verdict']}", "held"))
    cache = {}
    for t in TESTS:
        sid, what, cfg, must, never = t[:5]
        wasm = t[5] if len(t) > 5 else WASM
        if only and sid not in only:
            continue
        key = json.dumps(cfg, sort_keys=True) + str(wasm)
        if key not in cache:
            cf_ = out / f"{sid}.config.json"
            cf_.write_text(json.dumps(cfg, indent=2))
            t0 = time.time()
            rep, rc = D.check(wasm, cf_, out / sid, a.jobs, label=f"{sid} fixture mode {cfg['init']['args']['mode']}")
            rep["_seconds"] = round(time.time() - t0)
            cache[key] = rep
        rep = cache[key]
        reports[sid] = rep
        ok, why = must(rep)
        rows.append((sid, what, ok, why, never))
        print(f"{sid:<4} {'PASS' if ok else 'FAIL'}  {what}: {why}", flush=True)
    res = {"fixture_wasm": str(WASM.relative_to(ROOT)), "fixture_sha256": D.sha256(WASM),
           "tests": [{"id": r[0], "what": r[1], "passed": r[2], "observed": r[3], "never": r[4]} for r in rows],
           "verdicts": {k: v["verdict"] for k, v in reports.items()}}
    (out / "selftest.json").write_text(json.dumps(res, indent=2))
    n = sum(1 for r in rows if r[2])
    print(f"self-tests: {n}/{len(rows)} passed")
    return 0 if n == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
