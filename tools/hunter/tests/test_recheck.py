"""Tests for tools/hunter/recheck_attestation.py: the offline re-check of a saved NEAR AI report.

  python3 -I -m unittest discover -s tools/hunter/tests -v      (from the repo root)

No network, no key. Uses the real saved report from the Nov 11 paper hunt, and tampered copies.
"""
import contextlib, io, json, pathlib, shutil, sys, tempfile, unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import recheck_attestation as R  # noqa: E402

ROOT = HERE.parent.parent.parent
REC = ROOT / "evidence" / "hunts" / "2026-11-11-papers-e3db55.json"


def run(path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = R.main(["recheck", str(path)])
    return rc, out.getvalue()


class Recheck(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.rec = self.tmp / "h.json"
        shutil.copy(REC, self.rec)
        (self.tmp / "h").mkdir()
        self.report = json.loads((REC.with_suffix("") / "attestation-report.json").read_text())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write_report(self, report):
        (self.tmp / "h" / "attestation-report.json").write_text(json.dumps(report))

    def test_saved_report_passes(self):
        rc, out = run(REC)
        self.assertEqual(rc, 0, out)
        self.assertIn("matches the record", out)
        self.assertIn("all checks pass", out)

    def test_changed_nonce_fails(self):
        self.report["gateway_attestation"]["request_nonce"] = "00" * 32
        self.write_report(self.report)
        rc, out = run(self.rec)
        self.assertEqual(rc, 1, out)
        self.assertIn("DOES NOT match the record", out)
        self.assertIn("FAIL: nonce_echoed", out)

    def test_same_bytes_but_record_hash_edited_fails(self):
        shutil.copy(REC.with_suffix("") / "attestation-report.json", self.tmp / "h" / "attestation-report.json")
        rec = json.loads(self.rec.read_text())
        rec["attestation_sha256"] = "0" * 64
        self.rec.write_text(json.dumps(rec))
        rc, out = run(self.rec)
        self.assertEqual(rc, 1, out)

    def test_no_model_attestation_fails(self):
        self.report["model_attestations"] = []
        self.write_report(self.report)
        rc, out = run(self.rec)
        self.assertEqual(rc, 1, out)
        self.assertIn("no model attestation", out)

    def test_muse_record_is_bad_input_never_pass(self):
        rc, out = run(ROOT / "evidence" / "hunts" / "2026-11-11-news-d340fd.json")
        self.assertEqual(rc, 2, out)
        self.assertIn("no attestation to check", out)

    def test_missing_file_is_bad_input(self):
        rc, _ = run(self.tmp / "nope.json")
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
