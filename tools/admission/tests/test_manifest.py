"""The count manifest is current, and every public sentence that quotes it says the same numbers.

  python3 -I -m unittest discover -s tools/admission/tests -v
"""
import json, pathlib, re, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools" / "admission"))
import manifest as M  # noqa: E402

# The one sentence form README.md and EVALUATE.md use (a test, not a convention):
#   "Attack admission: **V of N** attacks validated, P partially validated, U unvalidated"
SENTENCE = re.compile(r"Attack admission: \*\*(\d+) of (\d+)\*\* attacks validated, (\d+) partially validated, (\d+) unvalidated")


class Manifest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = M.build()

    def test_committed_manifest_is_current(self):
        self.assertTrue(M.OUT_JSON.exists() and M.OUT_MD.exists(), "run tools/admission/manifest.py")
        self.assertEqual(M.OUT_JSON.read_text(), M.dump(self.m), "evidence/MANIFEST.json is stale: run tools/admission/manifest.py")
        self.assertEqual(M.OUT_MD.read_text(), M.render_md(self.m), "evidence/MANIFEST.md is stale: run tools/admission/manifest.py")

    def test_classes_add_up(self):
        a = self.m["attacks"]
        self.assertEqual(sum(a["classes"].values()), a["library_intents"])
        self.assertEqual(sum(a["classes_token_suite"].values()), a["library_token"])

    def test_public_sentences_match(self):
        a = self.m["attacks"]
        want = (a["classes"]["validated"], a["library_intents"], a["classes"]["partially-validated"], a["classes"]["unvalidated"])
        for f in ("README.md", "EVALUATE.md"):
            found = SENTENCE.findall((ROOT / f).read_text())
            self.assertTrue(found, f"{f} has no 'Attack admission:' sentence")
            for g in found:
                self.assertEqual(tuple(int(x) for x in g), want, f"{f} quotes {g}, manifest says {want}")

    def test_validated_rows_really_validated(self):
        # every validated row's stamp re-judges from stored runs (rederive), never a copied word
        for r in self.m["attacks"]["rows"]:
            if r["class"] != "unvalidated":
                self.assertTrue(r["evidence"], r["id"])
                self.assertTrue((ROOT / r["evidence"] / "admission.json").is_file(), r["id"])

    def test_recorded_reasons_only_for_attacks_the_gate_has_not_judged(self):
        # a person's reason (tools/admission/unvalidated.json) never sits on an attack with a spec or a stamp
        reasons = M.load_reasons()
        rows = {r["id"]: r for r in self.m["attacks"]["rows"]}
        for aid, (reason, _) in reasons.items():
            self.assertIn(aid, rows)
            self.assertEqual(rows[aid]["class"], "unvalidated", aid)
            self.assertTrue(rows[aid]["why"].startswith(reason + ":"), aid)

    def test_reason_on_a_specced_attack_is_refused(self):
        a = {"meta": {"id": "x", "spec": {"property": "p"}}, "steps": []}
        with self.assertRaises(SystemExit):
            M.attack_class(a, {"x": ("intent-only", "d")})


if __name__ == "__main__":
    unittest.main()
