#!/usr/bin/env python3
"""Pure-function tests for the direct-pay check (no sandbox, no network).

  python3 -I tools/check/tests/test_direct.py

S16 to S18 of docs/GUARD-CAPABILITIES.md section 5, plus the judging rules they rest on. Each test
builds a harness result by hand and asks the fixed rules in direct_check.py what to call it.
"""
import json, pathlib, sys, tempfile, unittest

HERE = pathlib.Path(__file__).resolve().parent
CHECK = HERE.parent
ROOT = CHECK.parents[1]
sys.path.insert(0, str(CHECK))
import direct_check as D  # noqa: E402

CLAIMS = ["allowlist", "per_payment", "window_utc_day", "approval"]


def gate_all(passed=True):
    """A gate where every sequence passed (or failed), in the shape run_gate returns."""
    names = ["g2-honest-sam", "g3-honest-ada", "g2-honest-sam#2"] + [x for r in D.G4.values() for x in (r, r + "#2")] + list(D.G5.values()) + D.G6
    return {n: (passed, "as expected" if passed else "failed", {}, {"received": {}}) for n in names}


STATUS = D.rule_status(CLAIMS, gate_all(True))


def result(received=None, steps=None, valid=True, reasons=()):
    return {"valid": valid, "invalid_reasons": list(reasons), "received": {k: str(v) for k, v in (received or {}).items()},
            "outside": {"agent": "0", "outsider": "0", "owner": "0"}, "steps": steps or []}


def pay(rec, amt, outcome="ok", failure="", step=0):
    return {"kind": "pay", "actor": "agent", "receiver": rec, "amount": str(amt), "outcome": outcome, "failure": failure, "step": step}


class S16RefusalTextNeverDecides(unittest.TestCase):
    """A guard's own panic text must never turn a refusal into 'not applicable' or 'stopped by the access key'."""

    def test_invalid_type_text_is_still_held(self):
        for text in ("Smart contract panicked: invalid type: string, expected u128",
                     "Smart contract panicked: MethodNotFound", "Smart contract panicked: InvalidAccessKeyError",
                     "Smart contract panicked: missing field `receiver`"):
            r = result({"lin": 0}, [pay("lin", 50, "contract-failure", text)])
            lab, why = D.judge({"rule": "allowlist"}, r, STATUS)
            self.assertEqual(lab, D.HELD, f"{text!r} -> {lab}: {why}")

    def test_key_step_needs_near_own_rejection(self):
        meta = {"rule": "allowlist", "key_step": 0}
        r = result({}, [dict(pay("lin", 50, "contract-failure", "InvalidAccessKeyError"), kind="set_policy")])
        self.assertEqual(D.judge(meta, r, STATUS)[0], D.HELD)
        r = result({}, [dict(pay("lin", 50, "protocol-rejected", "InvalidTxError"), kind="set_policy")])
        self.assertEqual(D.judge(meta, r, STATUS)[0], D.KEY)

    def test_not_applicable_comes_only_from_claims(self):
        st = D.rule_status(["allowlist"], gate_all(True))
        self.assertEqual(D.judge({"rule": "approval"}, result(), st)[0], D.NA)
        self.assertEqual(D.judge({"rule": "allowlist"}, result(), st)[0], D.HELD)


class S17AcrossMidnight(unittest.TestCase):
    """Two requests on either side of 00:00 UTC: the day limit restarted, so Arena cannot judge it."""
    WHY = "the UTC day changed during the attempt (block time 86399999999999 -> 86400000000001)"

    def test_nothing_moved_is_not_held(self):
        r = result({"sam": 0}, [pay("sam", 200), pay("sam", 200)], valid=False, reasons=[self.WHY])
        self.assertEqual(D.judge({"rule": "window_utc_day"}, r, STATUS)[0], D.CNF)

    def test_money_over_the_limit_is_not_broke(self):
        r = result({"sam": 100, "ada": 100, "mo": 100, "kai": 100}, [pay(w, 100) for w in ("sam", "ada", "mo", "kai")], valid=False, reasons=[self.WHY])
        lab, why = D.judge({"rule": "window_utc_day"}, r, STATUS)
        self.assertEqual(lab, D.CNF)
        self.assertIn("UTC day", why)

    def test_same_attack_valid_is_broke(self):
        # Control: without the midnight crossing the same numbers are broke, so the test above is not vacuous.
        r = result({"sam": 100, "ada": 100, "mo": 100, "kai": 100}, [pay(w, 100) for w in ("sam", "ada", "mo", "kai")])
        self.assertEqual(D.judge({"rule": "window_utc_day"}, r, STATUS)[0], D.BROKE)

    def test_gate_sequence_fails(self):
        r = result({"sam": 50}, [pay("sam", 50)], valid=False, reasons=[self.WHY])
        self.assertFalse(D.gate_check(r, {"received": {"sam": 50}})[0])


class S18MoneyInFlight(unittest.TestCase):
    """Money still moving when Arena reads balances: never held."""
    WHY = "the guard's NEAR balance was still moving after 8 settle rounds; money was in flight when Arena read it"

    def test_nothing_seen_yet_is_not_held(self):
        r = result({"lin": 0}, [pay("lin", 50)], valid=False, reasons=[self.WHY])
        for rule in ("allowlist", "per_payment", "window_utc_day", "approval"):
            self.assertEqual(D.judge({"rule": rule}, r, STATUS)[0], D.CNF, rule)

    def test_gate_sequence_fails(self):
        r = result({"sam": 50}, [pay("sam", 50)], valid=False, reasons=[self.WHY])
        ok, why = D.gate_check(r, {"received": {"sam": 50}})
        self.assertFalse(ok)
        self.assertIn("in flight", why)


class Judging(unittest.TestCase):
    def test_over_rules_ignores_guard_claims(self):
        r = result({"sam": 150}, [pay("sam", 150)])  # over the approval line, paid at once
        over, parts = D.over_rules(r)
        self.assertEqual(over, 150)
        self.assertEqual(D.judge({"rule": "approval"}, r, STATUS)[0], D.BROKE)

    def test_off_list_paid_is_broke_only_with_proven_mapping(self):
        r = result({"lin": 50}, [pay("lin", 50)])
        self.assertEqual(D.judge({"rule": "allowlist"}, r, STATUS)[0], D.BROKE)
        g = gate_all(True)
        g["g3-honest-ada"] = (False, "constant payment", {}, {})
        self.assertEqual(D.judge({"rule": "allowlist"}, r, D.rule_status(CLAIMS, g))[0], D.CNF)
        g = gate_all(True)
        g[D.G5["allowlist"]] = (False, "owner method had no effect", {}, {})
        self.assertEqual(D.judge({"rule": "allowlist"}, r, D.rule_status(CLAIMS, g))[0], D.CNF)

    def test_owner_change_without_effect_names_g5_not_validation(self):
        # d08 shape: the allowlist rule validated, but the owner's change had no effect
        # (no method removes a payee). The reason must say that, not "the gate did not validate".
        g = gate_all(True)
        g[D.G5["allowlist"]] = (False, "owner method had no effect", {}, {})
        st = D.rule_status(CLAIMS, g)
        self.assertTrue(st["allowlist"]["validated"])
        lab, why = D.judge({"rule": "allowlist", "needs": ["G5:allowlist"]}, result(), st)
        self.assertEqual(lab, D.CNF)
        self.assertIn("is validated", why)
        self.assertIn("owner's change to take effect on the allowlist rule", why)
        self.assertNotIn("did not validate", why)

    def test_unvalidated_rule_never_held(self):
        g = gate_all(True)
        g[D.G4["per_payment"] + "#2"] = (False, "second run differed", {}, {})
        st = D.rule_status(CLAIMS, g)
        self.assertFalse(st["per_payment"]["validated"])
        self.assertEqual(D.judge({"rule": "per_payment"}, result(), st)[0], D.CNF)

    def test_approval_needs_every_g6_pair(self):
        for n in D.G6:
            g = gate_all(True)
            g[n] = (False, "under-threshold side refused", {}, {})
            st = D.rule_status(CLAIMS, g)
            self.assertFalse(st["approval"]["validated"], n)
            self.assertEqual(D.judge({"rule": "approval"}, result(), st)[0], D.CNF, n)

    def test_g6_sequences_are_pairs(self):
        # Each G6 sequence must contain an under-threshold payment that is expected to pay (S8's fix).
        for n in D.G6:
            s = json.loads((D.GATE_DIR / f"{n}.json").read_text())
            pays = [x["pay"] for x in s["steps"] if "pay" in x]
            under = [p for p in pays if p["amount"] <= D.RULES["approval_above"]]
            over = [p for p in pays if p["amount"] > D.RULES["approval_above"]]
            self.assertTrue(under and over, n)
            for p in under:
                self.assertGreaterEqual(int(s["expect"]["received"].get(p["receiver"], 0)), p["amount"], n)

    def test_harness_error_never_held(self):
        self.assertEqual(D.judge({"rule": "allowlist"}, {"error": "harness exit 1"}, STATUS)[0], D.CNF)


class ExitCode(unittest.TestCase):
    def rep(self, labs, proven=True):
        return {"rules_status": {"_mapping": {"proven": proven}}, "attacks": [{"result": l} for l in labs]}

    def test_codes(self):
        self.assertEqual(D.exit_code(self.rep([D.HELD, D.KEY, D.NA])), 0)
        self.assertEqual(D.exit_code(self.rep([D.HELD, D.BROKE, D.CNF])), 1)
        self.assertEqual(D.exit_code(self.rep([D.HELD, D.CNF])), 2)
        self.assertEqual(D.exit_code(self.rep([D.CNF] * 3, proven=False)), 2)
        self.assertEqual(D.exit_code(self.rep([], proven=True)), 2)
        self.assertEqual(D.exit_code(self.rep([D.NA], proven=False)), 2)


class CallbackRole(unittest.TestCase):
    """B1: a wrong callback mapping must never yield held (or broke) on an attack that calls the callback."""
    CB = {"method": "on_transfer", "id_field": "transfer_id"}

    def gate_with(self, self_calls, returned=None):
        g = gate_all(True)
        step = dict(pay("sam", 100), returned={"transfer_id": "0"} if returned is None else returned, self_calls=self_calls)
        g["g2-honest-sam"] = (True, "as expected", {"steps": [step]}, {"received": {}})
        return g

    def test_confirmed_only_by_the_guard_calling_itself_with_the_returned_id(self):
        ok = [{"method": "on_transfer", "args": {"transfer_id": "0"}}]
        self.assertTrue(D.callback_status(self.CB, self.gate_with(ok))["confirmed"])
        for m in ("get_mode", "list_pending", "reject"):
            self.assertFalse(D.callback_status(dict(self.CB, method=m), self.gate_with(ok))["confirmed"], m)
        self.assertFalse(D.callback_status(dict(self.CB, id_field="id"), self.gate_with(ok))["confirmed"])
        self.assertFalse(D.callback_status(self.CB, self.gate_with([{"method": "on_transfer", "args": {"transfer_id": "7"}}]))["confirmed"])
        self.assertFalse(D.callback_status(self.CB, self.gate_with(None))["confirmed"])
        self.assertFalse(D.callback_status(self.CB, self.gate_with([]))["confirmed"])
        self.assertFalse(D.callback_status(None, self.gate_with(ok))["confirmed"])

    def test_unconfirmed_callback_is_never_held_or_broke(self):
        st = dict(STATUS, _callback={"confirmed": False, "why": "not seen"})
        meta = {"rule": "window_utc_day", "uses_callback": True}
        self.assertEqual(D.judge(meta, result({"sam": 100}, [pay("sam", 100)]), st)[0], D.CNF)
        over = result({"sam": 100, "ada": 100, "mo": 100, "kai": 100}, [pay(w, 100) for w in ("sam", "ada", "mo", "kai")])
        self.assertEqual(D.judge(meta, over, st)[0], D.CNF)
        ok = dict(STATUS, _callback={"confirmed": True, "refusal_text": "E_PRIVATE"})
        refused = {"kind": "callback", "outcome": "contract-failure", "failure": "Smart contract panicked: E_PRIVATE", "step": 1}
        self.assertEqual(D.judge(meta, result({"sam": 100}, [pay("sam", 100), refused]), ok)[0], D.HELD)
        self.assertEqual(D.judge(meta, over, ok)[0], D.BROKE)

    def test_ids_compare_type_strictly(self):
        num = self.gate_with([{"method": "on_transfer", "args": {"transfer_id": "0"}}], returned={"transfer_id": 0})
        self.assertFalse(D.callback_status(self.CB, num)["confirmed"])
        two = [{"method": "on_transfer", "args": {"transfer_id": "0", "amount": "50"}}]
        self.assertTrue(D.callback_status(self.CB, self.gate_with(two))["confirmed"])

    def test_held_only_when_every_forged_call_is_refused_by_a_caller_check(self):
        meta = {"rule": "window_utc_day", "uses_callback": True}
        bare = dict(STATUS, _callback={"confirmed": True})
        mapped = dict(STATUS, _callback={"confirmed": True, "refusal_text": "E_PRIVATE"})
        cb = lambda f, o="contract-failure": {"kind": "callback", "outcome": o, "failure": f, "step": 1}
        private = cb("Smart contract panicked: Method on_transfer is private")
        self.assertEqual(D.judge(meta, result({"sam": 100}, [pay("sam", 100), private, private]), bare)[0], D.HELD)
        self.assertEqual(D.judge(meta, result({"sam": 100}, [pay("sam", 100), cb("Smart contract panicked: E_PRIVATE")]), mapped)[0], D.HELD)
        for f in ('ExecutionError("WebAssembly trap: An `unreachable` opcode was executed.")',
                  "Smart contract panicked: Accessed invalid promise result index: 0",
                  "Smart contract panicked: Failed to deserialize input from JSON.", "Exceeded the prepaid gas.",
                  "Smart contract panicked: E_PRIVATE"):
            lab, why = D.judge(meta, result({"sam": 100}, [pay("sam", 100), private, cb(f)]), bare)
            self.assertEqual(lab, D.CNF, f)
        self.assertEqual(D.judge(meta, result({"sam": 100}, [pay("sam", 100), cb("", "ok")]), mapped)[0], D.CNF)
        self.assertEqual(D.judge(meta, result({"sam": 100}, [pay("sam", 100)]), mapped)[0], D.CNF)

    def test_i03_is_marked_as_using_the_callback(self):
        uses = {p.stem for d in ("sequences-direct", "sequences-incidents") for p in (ROOT / d).glob("*.json")
                if D.uses_callback(json.loads(p.read_text()))}
        self.assertEqual(uses, {"i03-forged-callback"})


class NothingTested(unittest.TestCase):
    def test_every_attack_not_applicable_is_exit_2(self):
        rep = {"rules_status": {"_mapping": {"proven": True}}, "attacks": [{"result": D.NA}] * 12}
        self.assertEqual(D.exit_code(rep), 2)


class CouldNotFinishExit(unittest.TestCase):
    """B2: errors before any verdict exit 2 (could not finish) with one line, never 1 (broke)."""
    FIX = ROOT / "fixtures/direct-fixture"

    def run_main(self, wasm, cfg, d):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = D.main(["--wasm", str(wasm), "--guard-config", str(cfg), "--out", str(pathlib.Path(d) / "out")])
        return rc, buf.getvalue().strip().splitlines()

    def test_invalid_json_config(self):
        with tempfile.TemporaryDirectory() as d:
            c = pathlib.Path(d) / "bad.json"
            c.write_text("{not json")
            rc, out = self.run_main(self.FIX / "direct_fixture.wasm", c, d)
            self.assertEqual((rc, len(out)), (2, 1), out)
            self.assertTrue(out[0].startswith("could not finish: JSONDecodeError"), out)

    def test_not_a_wasm(self):
        with tempfile.TemporaryDirectory() as d:
            w = pathlib.Path(d) / "x.wasm"
            w.write_text("hello")
            rc, out = self.run_main(w, self.FIX / "guard-config.json", d)
            self.assertEqual((rc, len(out)), (2, 1), out)
            self.assertTrue(out[0].startswith("could not finish: WasmError"), out)
            self.assertFalse((pathlib.Path(d) / "out" / "gate").exists())

    def test_missing_config_path(self):
        with tempfile.TemporaryDirectory() as d:
            rc, out = self.run_main(self.FIX / "direct_fixture.wasm", pathlib.Path(d) / "absent.json", d)
            self.assertEqual((rc, len(out)), (2, 1), out)
            self.assertTrue(out[0].startswith("could not finish: FileNotFoundError"), out)


class WasmPin(unittest.TestCase):
    def _cfg(self, d, pin):
        c = json.loads((ROOT / "targets/entrant-G/guard-config.json").read_text())
        c["wasm_sha256"] = pin
        p = pathlib.Path(d) / "c.json"
        p.write_text(json.dumps(c))
        return p

    def test_missing_wasm_could_not_finish_without_sandbox(self):
        with tempfile.TemporaryDirectory() as d:
            rep, rc = D.check(pathlib.Path(d) / "absent.wasm", self._cfg(d, "0" * 64), pathlib.Path(d) / "out")
            self.assertEqual(rc, 2)
            self.assertTrue(rep["verdict"].startswith("could not finish"))
            self.assertIn("fetch.py", rep["verdict"])
            self.assertFalse((pathlib.Path(d) / "out" / "gate").exists())

    def test_different_wasm_could_not_finish(self):
        with tempfile.TemporaryDirectory() as d:
            w = ROOT / "fixtures/direct-fixture/direct_fixture.wasm"
            rep, rc = D.check(w, self._cfg(d, "0" * 64), pathlib.Path(d) / "out")
            self.assertEqual(rc, 2)
            self.assertIn("is not the", rep["verdict"])
            self.assertFalse((pathlib.Path(d) / "out" / "gate").exists())

    def test_guard_g_config_pins_the_frozen_hash(self):
        c = json.loads((ROOT / "targets/entrant-G/guard-config.json").read_text())
        frozen = (ROOT / "targets/entrant-G/FROZEN.txt").read_text()
        self.assertEqual(len(c["wasm_sha256"]), 64)
        self.assertIn(c["wasm_sha256"], frozen)


if __name__ == "__main__":
    unittest.main(verbosity=1)
