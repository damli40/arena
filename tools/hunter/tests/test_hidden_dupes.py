"""The hunter's hidden-set duplicate check: refuses a folder that is not the committed set, and its
public record never carries a hash or a name from the hidden set.

  python3 -I -m unittest discover -s tools/hunter/tests -v
"""
import json, pathlib, sys, tempfile, unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import hidden_dupes as HD  # noqa: E402
import validate as V  # noqa: E402

STEPS = [{"call": {"actor": "agent", "method": "pay", "args": {"id": "inv-mid"}}}]


def fake_set(d):
    doc = {"name": "x", "steps": STEPS, "meta": {"id": "hidden-01-x", "steps_sha256": V.steps_hash(STEPS),
           "spec": {"property": "p", "failure_mode": "f", "capabilities": ["C1"]}}}
    (pathlib.Path(d) / "a.json").write_text(json.dumps(doc))


class HiddenDupes(unittest.TestCase):
    def test_folder_that_is_not_the_committed_set_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            fake_set(d)
            with self.assertRaisesRegex(ValueError, "not the committed"):
                HD.load(d)

    def test_empty_folder_and_folder_inside_repo_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "no attack files"):
                HD.load(d)
        with self.assertRaisesRegex(ValueError, "outside the repo"):
            HD.load(HD.ROOT / "sequences-scripted")

    def test_not_run_never_matches_and_says_why(self):
        st = HD.not_run("no folder")
        self.assertFalse(HD.match(st, V.steps_hash(STEPS)))
        self.assertEqual(HD.record(st), {"ran": False, "set_sha256": None, "matches": 0, "why": "no folder"})

    def test_match_counts_and_record_carries_no_hash(self):
        h = V.steps_hash(STEPS)
        st = {"ran": True, "why": "", "set_sha256": "ab" * 32, "hashes": frozenset([h]), "matches": 0}
        self.assertTrue(HD.match(st, h))
        self.assertFalse(HD.match(st, "00" * 32))
        rec = HD.record(st)
        self.assertEqual(rec["matches"], 1)
        self.assertNotIn(h, json.dumps(rec))
        self.assertIn("retire", rec)


if __name__ == "__main__":
    unittest.main()
