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
            return Reply(json.dumps({"choices": [{"message": {"content": '{"reasoning": "r", "email": "e"}'}}]}).encode())
        with mock.patch.object(base.urllib.request, "urlopen", fake_urlopen):
            email, reasoning, _, _ = adaptive.attacker_turn("fake-nearai-key-for-tests", [])
        self.assertEqual((email, reasoning), ("e", "r"))
        self.assertEqual(sent["body"]["model"], "z-ai/glm-5.3-flash")
        self.assertEqual(sent["body"]["max_tokens"], base.muse.NEARAI_MAX_TOKENS)
        self.assertIn("x-no-aliasing", sent["headers"])


if __name__ == "__main__":
    unittest.main()
