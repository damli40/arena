"""Pre-existing evidence is byte-identical: no file committed under evidence/ at the freeze is edited.

  python3 -I -m unittest discover -s tools/admission/tests -v

The list (tools/admission/evidence-baseline.sha256) is the sha256 of every evidence file at the
freeze commit named in its header, computed from git's stored bytes. This test needs no git, so it
also runs on a `git archive` export. Admission work may ADD evidence (new folders); it may not edit
or delete what was there.
"""
import hashlib, pathlib, unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
BASE = ROOT / "tools" / "admission" / "evidence-baseline.sha256"


class EvidenceUnchanged(unittest.TestCase):
    def test_every_baseline_file_is_byte_identical(self):
        rows = [l.split("  ", 1) for l in BASE.read_text().splitlines() if l and not l.startswith("#")]
        self.assertGreater(len(rows), 5000, "baseline list looks truncated")
        missing, changed = [], []
        for h, path in rows:
            p = ROOT / path
            if not p.is_file():
                missing.append(path)
            elif hashlib.sha256(p.read_bytes()).hexdigest() != h:
                changed.append(path)
        self.assertEqual(missing, [], f"{len(missing)} pre-existing evidence files are gone")
        self.assertEqual(changed, [], f"{len(changed)} pre-existing evidence files were edited")
        print(f"\n  evidence unchanged: {len(rows)} files byte-identical to the freeze", end="")


if __name__ == "__main__":
    unittest.main()
