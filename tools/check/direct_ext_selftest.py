"""Self-tests for the EXTENDED direct mode (harness/src/direct_ext.rs, tools/check/direct_ext.py).

    python3 tools/check/direct_ext_selftest.py --out DIR [--jobs 4] [--only X1,X3]

Each self-test runs the whole direct check (direct_check.py) against the extended test fixture
fixtures/direct-ext-fixture/direct_ext_fixture.wasm, switched at init into one interface shape, with
one config. Two kinds of test, for every new capability:

  positive   the right mapping for that shape: every rule validates, and no attack is anything but
             held, stopped by the access key, or not applicable (the fixture enforces every rule)
  refused    a WRONG mapping for that shape (the kind a person or an AI could plausibly write):
             the gate must refuse it, so the affected rule (or the whole check) is "could not
             finish", and nothing is held or broke on it

Exit 0 only if every self-test passed.
"""
import argparse, copy, json, pathlib, sys, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import direct_check as D  # noqa: E402

ROOT = D.ROOT
WASM = ROOT / "fixtures" / "direct-ext-fixture" / "direct_ext_fixture.wasm"
WIN = 600  # seconds: short fixture windows, so a window-kind proof needs ~11 minutes of sandbox clock

LIMITS = {"per_payment": "$per_payment", "window_limit": "$window_limit", "approval_above": "$approval_above"}


def cfg(signer="account", installs_key=False, payees="in_policy", window=("utc_day", 86400), one_yocto=False,
        signed=False, defect="none", ext=None, claims=None, versioned=False):
    opts = {"signer": signer, "installs_key": installs_key, "payees": payees,
            "window": {"kind": window[0], "secs": window[1]}, "one_yocto": one_yocto, "defect": defect, "versioned": versioned}
    if signed:
        opts["sig_pk"] = "$signer_public_key"
    limits = dict(LIMITS, allowlist="$allowlist" if payees == "in_policy" else None)
    c = {"arena_guard_config": 1, "shape": "direct", "pays_in": "native",
         "notes": "direct-ext self-test config (tools/check/direct_ext_selftest.py)",
         "init": {"method": "new", "args": {"owner": "$owner", "agent": "$agent", "opts": opts}},
         "direct": {"claims": claims or ["allowlist", "per_payment", "window_utc_day", "approval"],
                    "pay": {"method": "pay", "receiver_field": "receiver", "amount_field": "amount", "extra_args": {"memo": "arena"}},
                    "policy": {"method": "set_limits", "args": limits},
                    "set_policy": {"method": "set_limits", "args": limits},
                    "approve": {"method": "approve", "id_field": "id"},
                    "reject": {"method": "reject", "id_field": "id"},
                    "pending": {"status_field": "status", "pending_value": "pending", "id_field": "id"}}}
    if ext is not None:
        c["direct"]["ext"] = ext
    return c


KEY_SETUP = [{"method": "add_agent_key", "args": {"public_key": "$agent_public_key"}}]
PER_CALL_SETUP = [{"method": "add_payee", "args": {"account": "$each"}, "each": "allowlist"}]
PER_CALL_SET_POLICY = [{"method": "set_limits", "args": dict(LIMITS, allowlist=None)},
                       {"method": "remove_payee", "args": {"account": "$each"}, "each": "removed"},
                       {"method": "add_payee", "args": {"account": "$each"}, "each": "added"}]
SIGN = {"message": "arena-fixture:v1|{guard}|{receiver}|{amount}|{nonce}"}


def signed_cfg(message=SIGN["message"]):
    c = cfg(signed=True, ext={"sign": {"message": message}, "nonce": "counter"})
    c["direct"]["pay"]["extra_args"].update({"nonce": "$nonce", "signature": "$signature"})
    return c


def versioned_cfg():
    c = cfg(versioned=True, ext={"notes": "each policy change is a fresh version"})
    for k in ("policy", "set_policy"):
        c["direct"][k]["args"]["version"] = "$policy_version"
    c["direct"]["pay"]["extra_args"]["version"] = "$policy_version"
    return c


def window_cfg(kind, claim):
    return cfg(window=(kind, WIN), claims=["allowlist", "per_payment", claim, "approval"],
               ext={"window": {"claim": claim, "secs": WIN}})


# ------------------------------------------------------------------ assertions
def rows(rep):
    return rep.get("attacks", [])


def all_held(rep):
    return all_held_and_owner_changes_work(rep)


def held_only(rep):
    # The fixture maps no callback, so the callback-forging attack is "could not finish" (not run).
    no_cb = lambda a: a["result"] == D.CNF and a.get("why", "").startswith("not run: the config maps no callback")
    bad = [a["attack"] + "=" + a["result"] for a in rows(rep) if a["result"] not in (D.HELD, D.KEY, D.NA) and not no_cb(a)]
    unval = [r for r, s in rep.get("rules_status", {}).items() if not r.startswith("_") and s.get("claimed") and not s.get("validated")]
    held = sum(1 for a in rows(rep) if a["result"] == D.HELD)
    ok = not bad and not unval and held > 0
    return ok, f"held {held}; not held: {bad or 'none'}; unvalidated rules: {unval or 'none'}"


def all_held_and_owner_changes_work(rep):
    """all_held, AND the owner's set-policy changed every rule (G5): a mapping that fills the wrong
    policy version would still validate the rules but could never call anything broke."""
    ok, why = held_only(rep)
    no = [r for r, s in rep.get("rules_status", {}).items() if not r.startswith("_") and s.get("claimed") and r != "approval" and not s.get("g5_effect")]
    return ok and not no, f"{why}; owner change without effect on: {no or 'none'}"


def refused_whole(rep):
    """The mapping is wrong at G1/G2: the verdict is could not finish and nothing is held or broke."""
    hb = [a["attack"] for a in rows(rep) if a["result"] in (D.HELD, D.BROKE)]
    ok = rep["verdict"].startswith("could not finish") and not hb
    return ok, f"verdict {rep['verdict'][:160]!r}; held or broke: {hb or 'none'}"


def refused_rule(rule):
    def f(rep):
        st = rep.get("rules_status", {}).get(rule, {})
        on = [a for a in rows(rep) if a["rule"] == rule]
        bad = [a["attack"] + "=" + a["result"] for a in on if a["result"] not in (D.CNF, D.NA)]
        ok = st.get("claimed") and not st.get("validated") and on and not bad
        return ok, f"{rule}: validated={st.get('validated')} ({(st.get('g8_why') or st.get('g4_why') or '')[:140]}); attacks not 'could not finish': {bad or 'none'}"
    return f


TESTS = [
    # id, capability, what, config, must
    ("X1", "pay key", "agent key on the guard account, installed by Arena, registered by an owner call",
     cfg(signer="guard_key", ext={"pay_key": {"on": "guard", "installed_by": "arena"}, "setup": KEY_SETUP}), all_held),
    ("X2", "pay key", "agent key on the guard account, installed by the guard's own setup call",
     cfg(signer="guard_key", installs_key=True, ext={"pay_key": {"on": "guard", "installed_by": "guard"}, "setup": KEY_SETUP}), all_held),
    ("X3", "pay key", "REFUSED: guard wants a key on its own account, mapping uses a separate agent account",
     cfg(signer="guard_key", installs_key=True, ext={"setup": [{"method": "add_agent_key", "args": {"public_key": "ed25519:11111111111111111111111111111111"}}]}), refused_whole),
    ("X4", "pay key", "REFUSED: mapping says the guard installs the key, but the guard's setup does not",
     cfg(signer="guard_key", installs_key=False, ext={"pay_key": {"on": "guard", "installed_by": "guard"}, "setup": KEY_SETUP}), refused_whole),
    ("X5", "pay key", "REFUSED: guard checks a separate agent account, mapping puts the key on the guard",
     cfg(signer="account", ext={"pay_key": {"on": "guard", "installed_by": "arena"}}), refused_whole),
    ("X6", "setup calls", "payee list one owner call per account, set-policy as several calls",
     (lambda c: (c["direct"].pop("set_policy"), c)[1])(cfg(payees="per_call", ext={"setup": PER_CALL_SETUP, "set_policy_calls": PER_CALL_SET_POLICY})), all_held),
    ("X7", "setup calls", "REFUSED: payee list one call per account, mapping makes no per-account calls",
     cfg(payees="per_call"), refused_whole),
    ("X8", "deposits", "owner calls need exactly 1 yoctoNEAR, mapping attaches it",
     cfg(one_yocto=True, ext={"deposits": {"policy": "1", "set_policy": "1", "approve": "1", "reject": "1"}}), all_held),
    ("X9", "deposits", "REFUSED: owner calls need 1 yoctoNEAR, mapping attaches none",
     cfg(one_yocto=True), refused_whole),
    ("X10", "window", "rolling window, labelled rolling", window_cfg("rolling", "window_rolling"), all_held),
    ("X11", "window", "REFUSED: rolling window labelled anchored", window_cfg("rolling", "window_anchored"), refused_rule("window_anchored")),
    ("X12", "window", "anchored period, labelled anchored", window_cfg("anchored", "window_anchored"), all_held),
    ("X13", "window", "REFUSED: anchored period labelled rolling", window_cfg("anchored", "window_rolling"), refused_rule("window_rolling")),
    ("X14", "window", "lifetime budget, labelled lifetime", window_cfg("lifetime", "window_lifetime"), all_held),
    ("X15", "window", "REFUSED: rolling window labelled lifetime", window_cfg("rolling", "window_lifetime"), refused_rule("window_lifetime")),
    ("X16", "signing", "guard checks a signature per payment; Arena holds the signer key and signs", signed_cfg(), all_held),
    ("X18", "setup calls", "a policy cannot be edited, each change needs a fresh version ($policy_version)", versioned_cfg(), all_held_and_owner_changes_work),
    ("X17", "signing", "REFUSED: mapping signs a different message than the guard checks",
     signed_cfg("arena-fixture:v1|{guard}|{amount}|{receiver}|{nonce}"), refused_whole),
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
    res = []
    for sid, cap, what, c, must in TESTS:
        if only and sid not in only:
            continue
        cf = out / f"{sid}.config.json"
        cf.write_text(json.dumps(c, indent=2))
        t0 = time.time()
        rep, rc = D.check(WASM, cf, out / sid, a.jobs, label=f"{sid} {what}")
        ok, why = must(rep)
        secs = round(time.time() - t0)
        res.append({"id": sid, "capability": cap, "what": what, "passed": ok, "observed": why, "verdict": rep.get("verdict"), "seconds": secs})
        print(f"{sid:<4} {'PASS' if ok else 'FAIL'}  [{cap}] {what}: {why} ({secs} s)", flush=True)
    (out / "selftest-ext.json").write_text(json.dumps({"fixture_wasm": str(WASM.relative_to(ROOT)), "fixture_sha256": D.sha256(WASM), "tests": res}, indent=2))
    n = sum(1 for r in res if r["passed"])
    print(f"ext self-tests: {n}/{len(res)} passed")
    return 0 if n == len(res) else 1


if __name__ == "__main__":
    sys.exit(main())
