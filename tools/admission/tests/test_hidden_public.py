"""Hidden set: disjoint from EVERY tracked attack-shaped file, and public runs ordered after their commitment.

  python3 -I -m unittest discover -s tools/admission/tests -v

Case 1 is the one a merge review found: a hidden attack whose steps equal a hunt proposal tracked under
evidence/hunts/**/attacks/, which the old check (library + intents only) did not see.
"""
import json, pathlib, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools" / "hidden"))
import hidden as H  # noqa: E402

STEPS = [{"call": {"actor": "agent", "method": "pay", "args": {"id": "inv-big"}}},
         {"call": {"actor": "agent", "method": "pay", "args": {"id": "inv-big"}}}]


def git(root, *a):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def write(root, rel, obj):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj))
    return p


class Disjoint(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        git(self.tmp, "init", "-q")

    def hidden_doc(self, steps):
        return (pathlib.Path("hv-01-x.json"), {"steps": steps, "meta": {"steps_sha256": H.V.steps_hash(steps)}})

    def test_hunt_proposal_under_evidence_hunts_is_public(self):
        write(self.tmp, "evidence/hunts/2026-11-11-papers-x/attacks/p1-a.json",
              {"name": "p1-a", "steps": STEPS, "meta": {"id": "p1-a"}})
        git(self.tmp, "add", "-A"); git(self.tmp, "commit", "-qm", "x")
        self.assertIn(H.V.steps_hash(STEPS), H.public_hashes(self.tmp))
        self.assertEqual(H.public_overlap([self.hidden_doc(STEPS)], self.tmp), ["hv-01-x.json"])

    def test_stale_meta_hash_does_not_hide_a_match(self):
        write(self.tmp, "evidence/hunts/h/attacks/p2.json", {"steps": STEPS, "meta": {"steps_sha256": "0" * 64}})
        git(self.tmp, "add", "-A"); git(self.tmp, "commit", "-qm", "x")
        self.assertEqual(len(H.public_overlap([self.hidden_doc(STEPS)], self.tmp)), 1)

    def test_untracked_file_is_not_public_and_different_steps_do_not_match(self):
        write(self.tmp, "evidence/hunts/h/attacks/p3.json", {"steps": STEPS})  # never added
        write(self.tmp, "README.json", {"x": 1})
        git(self.tmp, "add", "README.json"); git(self.tmp, "commit", "-qm", "x")
        self.assertEqual(H.public_overlap([self.hidden_doc(STEPS)], self.tmp), [])
        write(self.tmp, "sequences-ai/a.json", {"steps": STEPS[:1]})
        git(self.tmp, "add", "sequences-ai/a.json"); git(self.tmp, "commit", "-qm", "y")
        self.assertEqual(H.public_overlap([self.hidden_doc(STEPS)], self.tmp), [])


class Order(unittest.TestCase):
    """check-public: a run counts only if git parent order puts it after its commitment."""
    SET = "a" * 64

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        git(self.tmp, "init", "-q")
        write(self.tmp, "README.md", "x")
        git(self.tmp, "add", "-A"); git(self.tmp, "commit", "-qm", "before commitment")
        self.before = git(self.tmp, "rev-parse", "HEAD")
        write(self.tmp, "hidden-set/COMMITMENT.json", {"set_sha256": self.SET, "attack_count": 1, "families_covered": ["f"]})
        git(self.tmp, "add", "-A"); git(self.tmp, "commit", "-qm", "commitment")
        self.after = git(self.tmp, "rev-parse", "HEAD")

    def run_file(self, commit, clean=True):
        return {"set_sha256": self.SET, "arena_commit": commit, "arena_tree_clean": clean, "guard_reference": "vault-a",
                "rows": [{"id": "h-01", "family": "f", "verdict": "held", "beyond_policy": 0}],
                "held": 1, "broke": 0, "inapplicable": 0, "beyond_policy": 0}

    def check(self, p):
        write(self.tmp, "evidence/hidden-set/r.json", p)
        return H.cmd_check_public(None, root=self.tmp)

    def test_run_after_commitment_passes(self):
        self.assertEqual(H.order_problems(self.run_file(self.after), self.tmp), [])
        self.assertEqual(self.check(self.run_file(self.after)), 0)

    def test_run_at_a_commit_without_the_commitment_fails(self):
        self.assertTrue(H.order_problems(self.run_file(self.before), self.tmp))
        self.assertEqual(self.check(self.run_file(self.before)), 1)

    def test_run_on_a_commit_not_in_history_of_head_fails(self):
        git(self.tmp, "checkout", "-q", "-b", "side")
        write(self.tmp, "side.txt", "x")
        git(self.tmp, "add", "-A"); git(self.tmp, "commit", "-qm", "side")
        side = git(self.tmp, "rev-parse", "HEAD")
        git(self.tmp, "checkout", "-q", "-")
        probs = H.order_problems(self.run_file(side), self.tmp)
        self.assertTrue(any("not an ancestor of HEAD" in x for x in probs), probs)
        self.assertTrue(H.order_problems(self.run_file("f" * 40), self.tmp))  # unknown commit

    def test_dirty_tree_run_fails(self):
        self.assertTrue(H.order_problems(self.run_file(self.after, clean=False), self.tmp))


if __name__ == "__main__":
    unittest.main()
