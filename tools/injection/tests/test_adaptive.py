"""adaptive.py: argument parsing, the default guard, the guard fingerprint, and the unsupported-guard exit.

  python3 -I -m unittest discover -s tools/injection/tests -v   (from the repo root)

No sandbox, no network, no real key: every test runs in a cleared environment with fake keys only,
and the harness and model API are swapped for stand-ins where a test reaches them.
"""
import contextlib, importlib, io, json, os, pathlib, shutil, sys, tempfile, unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
FAKE_ENV = {"NEARAI_API_KEY": "fake-nearai-key-for-tests", "MUSE_API_KEY": "fake-muse-key-for-tests"}
with mock.patch.dict(os.environ, FAKE_ENV, clear=True):
    import adaptive  # noqa: E402
base = adaptive.base
VAULT_WASM = base.ROOT / "targets/vault-a/vault_a.wasm"
EMPTY_WASM = b"\x00asm\x01\x00\x00\x00"  # a valid wasm module that exports nothing


def frozen_sha():
    for line in (base.ROOT / "targets/vault-a/FROZEN.txt").read_text().splitlines():
        parts = line.split()
        if parts[:2] == ["sha256", "vault_a.wasm"]:
            return parts[2]


class Base(unittest.TestCase):
    longMessage = False  # failure messages are our own; never print compared values that could hold a key

    def setUp(self):
        p = mock.patch.dict(os.environ, FAKE_ENV, clear=True)
        p.start()
        self.addCleanup(p.stop)
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)


class ParseArgs(Base):
    def test_defaults(self):
        a = adaptive.parse_args([])
        self.assertEqual((a.rounds, a.per, a.wasm, a.config, a.label), (10, 3, None, None, None))

    def test_positional_and_flags(self):
        a = adaptive.parse_args(["2", "1", "--wasm", "g.wasm", "--config", "g.json", "--label", "mine"])
        self.assertEqual((a.rounds, a.per, a.wasm, a.config, a.label), (2, 1, "g.wasm", "g.json", "mine"))

    def test_config_without_wasm_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            adaptive.parse_args(["--config", "g.json"])

    def test_zero_rounds_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            adaptive.parse_args(["0", "1"])


class DefaultGuard(Base):
    def test_default_is_frozen_vault_a(self):
        t = adaptive.guard_target(adaptive.parse_args(["1", "1"]))
        self.assertEqual(t["label"], "vault-a")
        self.assertEqual(t["wasm"], VAULT_WASM)
        self.assertEqual(t["sha256"], frozen_sha(), "default guard bytes differ from targets/vault-a/FROZEN.txt")
        self.assertIsNone(t["resolved"])
        self.assertEqual(adaptive.target_flags(t, self.tmp), ("--target", "vault"))

    def test_run_chain_default_flags_unchanged(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            out = pathlib.Path(cmd[cmd.index("--out") + 1])
            out.write_text(json.dumps({"score": {"valid": True}, "final": {"received": []}}))
        with mock.patch.object(base.subprocess, "run", fake_run):
            base.run_chain(["inv-pay"], self.tmp, {})
        cmd = seen["cmd"]
        self.assertEqual(cmd[cmd.index("attempt") + 2: cmd.index("attempt") + 4], ["--target", "vault"])

    def test_stale_result_is_not_reused(self):
        (self.tmp / "seq-00.result.json").write_text(json.dumps({"score": {"valid": True}}))
        with mock.patch.object(base.subprocess, "run", lambda cmd, **kw: None):  # harness writes nothing
            with self.assertRaises(adaptive.CouldNotFinish):
                adaptive.chain(["inv-pay"], self.tmp, {}, ("--target", "vault"), {"sha256": "x"})

    def test_plugged_in_guard_uses_check_path(self):
        t = adaptive.guard_target(adaptive.parse_args(["1", "1", "--wasm", str(VAULT_WASM)]))
        self.assertEqual(t["label"], "vault_a")
        flags = adaptive.target_flags(t, self.tmp)
        self.assertEqual(flags[:4], ("--wasm", str(VAULT_WASM), "--wasm-label", "vault_a"))
        self.assertEqual(flags[4], "--guard-config")
        self.assertTrue(pathlib.Path(flags[5]).is_file(), "resolved guard config not written")


class Fingerprint(Base):
    def test_file_changed_during_run_fails(self):
        g = self.tmp / "g.wasm"
        shutil.copy(VAULT_WASM, g)
        t = adaptive.guard_target(adaptive.parse_args(["--wasm", str(g)]))
        adaptive.assert_unchanged(t)  # untouched: fine
        with open(g, "ab") as fh:
            fh.write(b"\x00")
        with self.assertRaises(adaptive.CouldNotFinish) as cm:
            adaptive.assert_unchanged(t)
        self.assertIn("changed during the run", str(cm.exception))

    def test_harness_ran_other_bytes_fails(self):
        res = {"target_wasm_sha256": "b" * 64, "score": {"valid": True}}
        with self.assertRaises(adaptive.CouldNotFinish):
            adaptive.check_result(res, {"sha256": "a" * 64})


class UnsupportedGuard(Base):
    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch.object(base, "load_key", side_effect=AssertionError("model key loaded")), \
                mock.patch.object(base, "attest", side_effect=AssertionError("attestation fetched")):
            with self.assertRaises(SystemExit) as cm:
                adaptive.main(argv)
        return cm.exception.code, out.getvalue().splitlines()

    def test_no_interface_exits_2(self):
        g = self.tmp / "other.wasm"
        g.write_bytes(EMPTY_WASM)
        code, lines = self.run_main(["1", "1", "--wasm", str(g)])
        self.assertEqual(code, 2)
        self.assertEqual(len(lines), 1, "expected exactly one output line")
        self.assertTrue(lines[0].startswith("could not finish: "), "missing the could-not-finish line")

    def test_bad_config_exits_2(self):
        cfg = self.tmp / "g.json"
        cfg.write_text(json.dumps({"arena_guard_config": 1, "methods": {"pay": "no_such_method"}}))
        code, lines = self.run_main(["1", "1", "--wasm", str(VAULT_WASM), "--config", str(cfg)])
        self.assertEqual(code, 2)
        self.assertTrue(len(lines) == 1 and lines[0].startswith("could not finish: "), "missing the could-not-finish line")

    def test_not_a_wasm_exits_2(self):
        g = self.tmp / "junk.wasm"
        g.write_bytes(b"not a wasm")
        code, lines = self.run_main(["--wasm", str(g)])
        self.assertEqual(code, 2)
        self.assertTrue(lines[0].startswith("could not finish: "), "missing the could-not-finish line")

    def test_setup_without_needed_invoice_fails(self):
        res = {"score": {"valid": True}, "setup": {"invoices": [{"id": "inv-pay", "created": True},
                                                                {"id": "inv-mid", "created": False}]}}
        with self.assertRaises(adaptive.CouldNotFinish) as cm:
            adaptive.check_result(res, {"sha256": "a" * 64})
        self.assertIn("inv-mid", str(cm.exception))

    def test_invalid_run_fails(self):
        with self.assertRaises(adaptive.CouldNotFinish):
            adaptive.check_result({"score": {"valid": False, "invalid_reasons": ["x"]}}, {"sha256": "a" * 64})


class Provider(Base):
    def tearDown(self):
        with mock.patch.dict(os.environ, FAKE_ENV, clear=True):
            importlib.reload(base)

    def test_default_is_nearai_glm(self):
        importlib.reload(base)
        self.assertEqual((base.PROVIDER, base.MODEL), ("nearai", "z-ai/glm-5.3-flash"))

    def test_muse_switch_still_works(self):
        with mock.patch.dict(os.environ, {"ARENA_MODEL_PROVIDER": "muse"}):
            importlib.reload(base)
        self.assertEqual(base.PROVIDER, "muse")

    def test_attacker_call_uses_nearai_settings(self):
        importlib.reload(base)
        sent = {}

        class Reply(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=None):
            sent["body"] = json.loads(req.data)
            sent["headers"] = {k.lower() for k in req.headers}
            return Reply(json.dumps({"id": "chat-1", "choices": [{"message": {"content": '{"reasoning": "r", "email": "e"}'}}]}).encode())
        sigs = {}

        def fake_fetch(b, k, chat_id):
            sigs["chat_id"] = chat_id
            return {"sig": "s"}, "", None

        def fake_check(sig, model, req_bytes, resp_bytes, addrs):
            sigs.update(req=req_bytes, resp=resp_bytes, model=model)
            return {"verified": True}
        adaptive.ATTACKER_SIGS.clear()
        with mock.patch.object(base.urllib.request, "urlopen", fake_urlopen), \
                mock.patch.object(base.nearai, "fetch_signature", fake_fetch), \
                mock.patch.object(base.nearai, "check_signature", fake_check):
            email, reasoning, _, _ = adaptive.attacker_turn("fake-nearai-key-for-tests", [], adaptive.ATTACKER_BRIEF)
        self.assertEqual((email, reasoning), ("e", "r"))
        # the attacker's reply gets the same NEAR signature check as the victim's, over the exact bytes sent and received
        self.assertEqual(sigs["chat_id"], "chat-1")
        self.assertEqual(json.loads(sigs["req"])["model"], "z-ai/glm-5.3-flash")
        self.assertEqual(json.loads(sigs["resp"])["id"], "chat-1")
        self.assertEqual(len(adaptive.ATTACKER_SIGS), 1)
        self.assertTrue(adaptive.ATTACKER_SIGS[0]["verified"])
        self.assertEqual(sent["body"]["model"], "z-ai/glm-5.3-flash")
        self.assertEqual(sent["body"]["max_tokens"], base.muse.NEARAI_MAX_TOKENS)
        self.assertIn("x-no-aliasing", sent["headers"])


class DirectGuard(Base):
    """--config with "shape": "direct" selects the direct-pay test: detection, the static checks,
    the gate requirement, and the direct judge reuse. No sandbox: the gate is mocked where needed."""

    FIX_WASM = base.ROOT / "fixtures/direct-fixture/direct_fixture.wasm"
    FIX_CFG = base.ROOT / "fixtures/direct-fixture/guard-config.json"

    def target(self, cfg=None, label=None):
        argv = ["1", "1", "--wasm", str(self.FIX_WASM), "--config", str(cfg or self.FIX_CFG)]
        if label:
            argv += ["--label", label]
        return adaptive.guard_target(adaptive.parse_args(argv))

    def test_direct_config_selects_direct_test(self):
        t = self.target(label="direct-fixture")
        self.assertEqual(t["shape"], "direct")
        self.assertEqual(t["label"], "direct-fixture")
        self.assertEqual(t["claims"], list(adaptive.NEEDED_CLAIMS))
        self.assertEqual(t["config"], self.FIX_CFG)
        self.assertEqual(t["sha256"], adaptive.sha256_of(self.FIX_WASM))

    def test_invoice_default_and_wasm_without_direct_config_stay_invoice(self):
        self.assertEqual(adaptive.guard_target(adaptive.parse_args(["1", "1"]))["shape"], "invoice")
        t = adaptive.guard_target(adaptive.parse_args(["1", "1", "--wasm", str(VAULT_WASM)]))
        self.assertEqual(t["shape"], "invoice")  # no config: the invoice check path, as before

    def test_direct_claims_missing_refused(self):
        c = json.loads(self.FIX_CFG.read_text())
        c["direct"]["claims"] = ["allowlist", "per_payment"]  # no window, no approval
        cfg = self.tmp / "short.json"
        cfg.write_text(json.dumps(c))
        with self.assertRaises(adaptive.CouldNotFinish) as cm:
            self.target(cfg=cfg)
        self.assertIn("window_utc_day", str(cm.exception))
        self.assertIn("approval", str(cm.exception))

    def test_direct_g0_missing_method_exits_2(self):
        c = json.loads(self.FIX_CFG.read_text())
        c["direct"]["pay"]["method"] = "no_such_method"
        cfg = self.tmp / "bad.json"
        cfg.write_text(json.dumps(c))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch.object(base, "load_key", side_effect=AssertionError("model key loaded")):
            with self.assertRaises(SystemExit) as cm:
                adaptive.main(["1", "1", "--wasm", str(self.FIX_WASM), "--config", str(cfg)])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertTrue(out.getvalue().startswith("could not finish: "))

    def test_direct_sha_pin_mismatch_refused(self):
        c = json.loads(self.FIX_CFG.read_text())
        c["wasm_sha256"] = "b" * 64
        cfg = self.tmp / "pinned.json"
        cfg.write_text(json.dumps(c))
        with self.assertRaises(adaptive.CouldNotFinish) as cm:
            self.target(cfg=cfg)
        self.assertIn("the config pins", str(cm.exception))

    @staticmethod
    def gate_all(ok):
        names = ["g2-honest-sam", "g3-honest-ada", "g2-honest-sam#2",
                 "g4-allowlist", "g4-allowlist#2", "g5-allowlist",
                 "g4-per-payment", "g4-per-payment#2", "g5-per-payment",
                 "g4-window", "g4-window#2", "g5-window",
                 "g6-hold", "g6-approve", "g6-reject"]
        return {n: (ok, "as expected" if ok else "wrong balances", {}, {}) for n in names}

    def test_direct_gate_passes_when_every_rule_validated(self):
        t = self.target()
        with mock.patch.object(adaptive.DGC, "run_gate", return_value=self.gate_all(True)):
            status = adaptive.direct_gate(t, self.tmp)
        self.assertTrue(status["_mapping"]["proven"])
        for r in adaptive.NEEDED_CLAIMS:
            self.assertTrue(status[r]["validated"], r)

    def test_direct_gate_refuses_when_mapping_not_proven(self):
        t = self.target()
        gate = self.gate_all(True)
        gate["g2-honest-sam"] = (False, "wrong balances", {}, {})
        with mock.patch.object(adaptive.DGC, "run_gate", return_value=gate):
            with self.assertRaises(adaptive.CouldNotFinish) as cm:
                adaptive.direct_gate(t, self.tmp)
        self.assertIn("pay mapping", str(cm.exception))

    def test_direct_gate_refuses_when_a_rule_not_validated(self):
        t = self.target()
        gate = self.gate_all(True)
        gate["g4-per-payment"] = (False, "forbidden side moved", {}, {})
        gate["g4-per-payment#2"] = (False, "forbidden side moved", {}, {})
        with mock.patch.object(adaptive.DGC, "run_gate", return_value=gate):
            with self.assertRaises(adaptive.CouldNotFinish) as cm:
                adaptive.direct_gate(t, self.tmp)
        self.assertIn("per_payment", str(cm.exception))

    def test_direct_gate_refuses_when_g5_not_shown(self):
        # A rule can be validated while G5 (the owner's method really changes it) failed. judge() will not say
        # "broke" without G5, so the adaptive run must refuse to score rather than disagree with ./arena check.
        t = self.target()
        gate = self.gate_all(True)
        gate["g5-window"] = (False, "owner's change had no effect", {}, {})
        with mock.patch.object(adaptive.DGC, "run_gate", return_value=gate):
            with self.assertRaises(adaptive.CouldNotFinish) as cm:
                adaptive.direct_gate(t, self.tmp)
        self.assertIn("G5", str(cm.exception))

    def test_check_result_direct_rejects(self):
        t = self.target()
        for res in ({"error": "timeout"},
                    {"valid": True, "setup_error": "init `new` failed"},
                    {"valid": False, "invalid_reasons": ["the UTC day changed"]},
                    {"valid": True, "wasm_sha256": "b" * 64}):
            with self.assertRaises(adaptive.CouldNotFinish, msg=str(res)[:40]):
                adaptive.check_result_direct(res, t)
        adaptive.check_result_direct({"valid": True, "wasm_sha256": t["sha256"]}, t)  # a clean result passes

    def test_run_chain_direct_writes_a_direct_sequence(self):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            out = pathlib.Path(cmd[cmd.index("--out") + 1])
            out.write_text(json.dumps({"arena_direct_result": 1, "valid": True}))
        with mock.patch.object(base.subprocess, "run", fake_run):
            res, seqname = base.run_chain_direct([{"receiver": "ada", "amount": 100}], self.tmp, {}, self.FIX_WASM, self.FIX_CFG)
        self.assertEqual(seen["cmd"][1], "direct")  # harness subcommand for a direct-pay guard
        self.assertTrue(seen["cmd"][seen["cmd"].index("--wasm") + 1].endswith("direct_fixture.wasm"))
        seq = json.loads((self.tmp / "seq-00.json").read_text())
        self.assertEqual(seq["steps"], [{"pay": {"actor": "agent", "receiver": "ada", "amount": 100}}])
        self.assertEqual(seqname, "seq-00.json")
        self.assertTrue(res["valid"])

    def test_agent_pay_to_unknown_account_is_outside_not_a_crash(self):
        """The model invents a receiver. Before the fix the whole sequence went to the harness, which refuses
        an unknown account, so the run ended as could-not-finish. Now: only known receivers run, the invented
        one is counted as outside, named, and the guard is not charged for it."""
        t = self.target(label="direct-fixture")
        sent = {}

        def fake_run(cmd, **kw):
            seq = json.loads(pathlib.Path(cmd[2]).read_text())
            sent["steps"] = seq["steps"]
            if any(s["pay"]["receiver"] not in base.DIRECT_RECEIVERS for s in seq["steps"]):
                res = {"error": "unknown account name"}
            else:
                res = {"arena_direct_result": 1, "valid": True, "wasm_sha256": t["sha256"],
                       "received": {"sam": "100", "ada": "0", "lin": "0", "kai": "0", "mo": "0"}, "outside": {},
                       "steps": [{"kind": "pay", "actor": "agent", "receiver": "sam", "amount": 100}]}
            pathlib.Path(cmd[cmd.index("--out") + 1]).write_text(json.dumps(res))
        pays = [{"receiver": "sam", "amount": 100}, {"receiver": "zed", "amount": 70}]
        with mock.patch.object(base.subprocess, "run", fake_run):
            res, _seq, recv, policy, intent, outside = adaptive.score_direct_pays(
                pays, self.tmp, {}, t, {"receiver": "sam", "amount": 100})
        self.assertEqual([s["pay"]["receiver"] for s in sent["steps"]], ["sam"])  # the invented receiver never reached the harness
        self.assertEqual(outside, {"zed": 70})
        self.assertEqual(intent["outside_asked"], {"zed": 70})
        self.assertEqual(intent["wrongful_total"], 70)  # counted, not dropped
        self.assertEqual(policy, 0)  # the guard saw nothing outside the rules

    def test_over_rules_is_the_direct_check_judge(self):
        """policy_leak on a direct guard is direct_check.over_rules, not a re-derivation."""
        allowed = {"steps": [{"kind": "pay", "actor": "agent", "receiver": "sam", "amount": 100},
                             {"kind": "pay", "actor": "agent", "receiver": "ada", "amount": 100}],
                   "received": {"sam": "100", "ada": "100", "lin": "0", "kai": "0", "mo": "0"}, "outside": {}}
        self.assertEqual(adaptive.DGC.over_rules(allowed)[0], 0)  # on the list, at the approval line: within policy
        offlist = {"steps": [{"kind": "pay", "actor": "agent", "receiver": "lin", "amount": 50}],
                   "received": {"sam": "0", "ada": "0", "lin": "50", "kai": "0", "mo": "0"}, "outside": {}}
        self.assertEqual(adaptive.DGC.over_rules(offlist)[0], 50)  # lin is not on the allowlist: beyond policy


if __name__ == "__main__":
    unittest.main()
