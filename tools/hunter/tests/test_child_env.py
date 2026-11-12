"""The harness child must not see the hunt's keys.

  python3 -I -m unittest discover -s tools/hunter/tests -p test_child_env.py -v   (from the repo root)

runner.run_one starts the harness; here the harness is swapped for a tiny shell script that writes
its own environment to the --out file and exits 1. No sandbox, no network, no real key.
"""
import os, pathlib, stat, sys, tempfile, unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import runner  # noqa: E402

KEYS = ("NEARAI_API_KEY", "MUSE_API_KEY", "ELFA_API_KEY", "NEAR_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY")
STAND_IN = """#!/bin/sh
out=""
while [ $# -gt 0 ]; do [ "$1" = "--out" ] && out="$2"; shift; done
/usr/bin/env > "$out"
exit 1
"""


class ChildEnvTest(unittest.TestCase):
    longMessage = False  # print only our own message, never the compared values

    def test_harness_child_sees_no_keys(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            fake = d / "fake-harness"
            fake.write_text(STAND_IN)
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            fake_env = {k: "fake-secret-value-" + k for k in KEYS}
            fake_env.update(RUST_LOG="info", NEAR_SANDBOX_LOG="near=error")
            with mock.patch.dict(os.environ, fake_env), mock.patch.object(runner, "HARNESS", fake):
                cell = runner.run_one(d / "seq.json", {"id": "g", "harness_flags": []}, d, "tester=test", timeout=30)
            self.assertEqual(cell["status"], "error")  # the stand-in exits 1 on purpose
            seen = dict(line.split("=", 1) for line in (d / "seq__g.result.json").read_text().splitlines() if "=" in line)
        # Failure messages name variables only, never values: this test's own output must not leak a real key.
        leaked = sorted(k for k in KEYS if k in seen)
        self.assertTrue(not leaked, f"reached the harness child: {leaked}")
        self.assertTrue(not any("fake-secret-value" in v for v in seen.values()), "a fake key value reached the child")
        # allow-listed variables still get through, so the real harness keeps working
        self.assertTrue(seen.get("RUST_LOG") == "info", "RUST_LOG was dropped")
        self.assertTrue(seen.get("NEAR_SANDBOX_LOG") == "near=error", "NEAR_SANDBOX_LOG was dropped")
        self.assertTrue("PATH" in seen, "PATH was dropped")
        extra = sorted(set(seen) - set(runner.CHILD_ENV_ALLOW) - {"PWD", "SHLVL", "_", "OLDPWD"})  # set by /bin/sh itself
        self.assertTrue(not extra, f"not on the allow-list: {extra}")

    def test_child_env_is_exact_names_only(self):
        with mock.patch.dict(os.environ, {"NEAR_SANDBOX_LOG_X": "1", "PATHX": "1", "NEARAI_API_KEY": "x"}):
            env = runner.child_env()
        self.assertTrue(not ({"NEAR_SANDBOX_LOG_X", "PATHX", "NEARAI_API_KEY"} & set(env)), "a near-miss name got through")


if __name__ == "__main__":
    unittest.main()
