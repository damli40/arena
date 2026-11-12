"""Tests for the race-ordering judge (tools/race/ordering.py). No sandbox needed.

    python3 -I -m unittest discover -s tools/race/tests
"""
import copy, json, pathlib, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools" / "race"))
import ordering as O  # noqa: E402

TRACES = ROOT / "evidence" / "race-ordering-2026-11-11" / "c1-traces"
G, T, A = "guard.test.near", "token.test.near", "agent.test.near"


def leg(tx, check, cb=None, ok=True, offset=None, contiguous=None, logs=()):
    rs = [{"index": 0, "executor": G, "block_height": check, "ok": ok, "children": 2 if ok else 0}]
    if ok and cb is not None:
        rs += [{"index": 1, "executor": T, "block_height": check + 1, "ok": True, "children": 1},
               {"index": 2, "executor": G, "block_height": cb, "ok": True, "children": 1},
               {"index": 3, "executor": A, "block_height": check + 1, "ok": True, "children": 0}]
    t = {"tx_hash": "x", "tx_block_height": tx, "receipts": rs}
    if offset is not None:
        t["race"] = {"requested_offset": offset, "blocks_contiguous": True if contiguous is None else contiguous}
    return {"kind": "race-call", "outcome": "ok" if ok else "contract-failure", "receipts": t, "logs": list(logs)}


def verdict(*steps):
    r = {"steps": list(steps)}
    return O.ordering_verdict(O.legs_of(r, range(len(steps))))


class Judge(unittest.TestCase):
    def test_same_block_checks_overlap(self):
        v = verdict(leg(110, 111, 113), leg(110, 111, 113))
        self.assertEqual(v["verdict"], O.OVERLAP)
        self.assertEqual((v["last_check"], v["first_cb"]), (111, 113))

    def test_next_block_check_overlaps(self):
        v = verdict(leg(110, 111, 113, offset=0), leg(111, 112, 114, offset=1))
        self.assertEqual(v["verdict"], O.OVERLAP)
        self.assertEqual(v["achieved_offsets"], [0, 1])

    def test_tie_is_never_a_race(self):
        # testnet 2026-11-10 row 3: A checked 182, callback 184; B checked 184.
        v = verdict(leg(277089181, 277089182, 277089184), leg(277089183, 277089184, 277089186))
        self.assertEqual(v["verdict"], O.TIE)

    def test_tie_with_a_refused_leg(self):
        # applied to "held" as much as to "broke": the refused leg's check in the callback's block
        v = verdict(leg(110, 111, 113), leg(112, 113, ok=False))
        self.assertEqual(v["verdict"], O.TIE)

    def test_sequential(self):
        v = verdict(leg(110, 111, 113), leg(114, 115, ok=False))
        self.assertEqual(v["verdict"], O.SEQUENTIAL)

    def test_refused_before_any_paying_check_is_not_a_race(self):
        # admission's T3 trace: the refused leg checked a block before the only paying leg checked,
        # so nothing was in flight when it was refused; its refusal is no evidence of a held race.
        v = verdict(leg(109, 110, ok=False), leg(110, 111, 113))
        self.assertEqual(v["verdict"], O.SEQUENTIAL)
        self.assertTrue(any("before any paying leg's check" in r for r in v["reasons"]))

    def test_early_refused_leg_is_dropped_not_fatal(self):
        # leg A refused in 109; legs B and C both pay, checks in 110, callbacks in 112: still a race.
        v = verdict(leg(108, 109, ok=False), leg(109, 110, 112), leg(109, 110, 112))
        self.assertEqual(v["verdict"], O.OVERLAP)
        self.assertEqual((v["last_check"], v["first_cb"]), (110, 112))
        self.assertTrue(any(r.startswith("leg 1 left out") for r in v["reasons"]))
        without_a = verdict(leg(109, 110, 112), leg(109, 110, 112))
        self.assertEqual(without_a["verdict"], O.OVERLAP)

    def test_refused_in_same_block_as_paying_check_still_overlaps(self):
        v = verdict(leg(110, 111, ok=False), leg(110, 111, 113))
        self.assertEqual(v["verdict"], O.OVERLAP)

    def test_testnet_one_block_apart_overlaps(self):
        # testnet row 8: B checked 725 (callback 727), A checked 726 and was refused.
        v = verdict(leg(277089725, 277089726, ok=False), leg(277089724, 277089725, 277089727))
        self.assertEqual(v["verdict"], O.OVERLAP)

    def test_refused_leg_has_no_callback(self):
        v = verdict(leg(110, 111, 113), leg(110, 111, ok=False))
        self.assertEqual(v["verdict"], O.OVERLAP)
        self.assertIsNone(v["legs"][1]["callback"])

    def test_both_refused_not_produced(self):
        v = verdict(leg(110, 111, ok=False), leg(110, 111, ok=False))
        self.assertEqual(v["verdict"], O.NOT_PRODUCED)

    def test_missing_height_not_produced(self):
        s = leg(110, 111, 113)
        s["receipts"]["receipts"][0]["block_height"] = None
        self.assertEqual(verdict(s, leg(110, 111, 113))["verdict"], O.NOT_PRODUCED)
        s = leg(110, 111, 113)
        s["receipts"]["receipts"][2]["block_height"] = None  # the callback's height
        self.assertEqual(verdict(s, leg(110, 111, 113))["verdict"], O.NOT_PRODUCED)

    def test_not_included_not_produced(self):
        s = {"kind": "race-call", "outcome": "not-included", "receipts": None, "logs": []}
        self.assertEqual(verdict(leg(110, 111, 113), s)["verdict"], O.NOT_PRODUCED)

    def test_no_trace_not_produced(self):
        s = leg(110, 111, 113)
        s["receipts"] = {"race": {"requested_offset": 1}}
        self.assertEqual(verdict(leg(110, 111, 113, offset=0), s)["verdict"], O.NOT_PRODUCED)

    def test_hold_timeout_not_produced(self):
        v = verdict(leg(110, 111, 113), leg(110, 111, 113, logs=["HOLD-TIMEOUT seq=1"]))
        self.assertEqual(v["verdict"], O.NOT_PRODUCED)

    def test_offset_mismatch_not_produced(self):
        # asked for the next block, landed in the same block: a miss, never scored
        v = verdict(leg(110, 111, 113, offset=0), leg(110, 111, 113, offset=1))
        self.assertEqual(v["verdict"], O.NOT_PRODUCED)
        self.assertIn("differ from requested", " ".join(v["reasons"]))
        # asked for the next block, landed two later (a tie): still not-produced, not a tie
        v = verdict(leg(110, 111, 113, offset=0), leg(112, 113, 115, offset=1))
        self.assertEqual(v["verdict"], O.NOT_PRODUCED)

    def test_fast_forward_gap_not_produced(self):
        v = verdict(leg(110, 111, 113, offset=0), leg(111, 112, 114, offset=1, contiguous=False))
        self.assertEqual(v["verdict"], O.NOT_PRODUCED)

    def test_different_accounts_not_produced(self):
        s = leg(110, 111, 113)
        for r in s["receipts"]["receipts"]:
            if r["executor"] == G:
                r["executor"] = "other.test.near"
        self.assertEqual(verdict(leg(110, 111, 113), s)["verdict"], O.NOT_PRODUCED)

    def test_three_legs(self):
        v = verdict(leg(110, 111, 113, offset=0), leg(110, 111, 113, offset=0), leg(111, 112, ok=False, offset=1))
        self.assertEqual(v["verdict"], O.OVERLAP)
        self.assertEqual((v["last_check"], v["first_cb"]), (112, 113))

    def test_earliest_guard_receipt_is_the_callback(self):
        # a guard with a second, later receipt (refund, second callback) uses the earliest one
        s = leg(110, 111, 113)
        s["receipts"]["receipts"].append({"index": 4, "executor": G, "block_height": 120, "ok": True, "children": 0})
        v = verdict(s, leg(110, 112, ok=False))
        self.assertEqual(v["first_cb"], 113)

    def test_one_leg_not_produced(self):
        self.assertEqual(verdict(leg(110, 111, 113))["verdict"], O.NOT_PRODUCED)


class CommittedTraces(unittest.TestCase):
    """Real sandbox traces committed in C1 (scripted-02, a plain race step)."""

    def load(self, name):
        r = json.loads((TRACES / name).read_text())
        idx = [i for i, s in enumerate(r["steps"]) if s["kind"] == "race-call"]
        return r, O.ordering_verdict(O.legs_of(r, idx))

    def test_every_committed_trace_is_overlap_proven(self):
        files = sorted(TRACES.glob("*.result.json"))
        self.assertEqual(len(files), 15)
        for f in files:
            r, v = self.load(f.name)
            self.assertEqual(v["verdict"], O.OVERLAP, f.name)
            self.assertEqual(v["achieved_offsets"], [0, 0], f.name)
            self.assertEqual(v["first_cb"] - v["last_check"], 2, f.name)

    def test_real_trace_made_late_is_sequential(self):
        r, _ = self.load("vault-a-1.result.json")
        r2 = copy.deepcopy(r)
        idx = [i for i, s in enumerate(r2["steps"]) if s["kind"] == "race-call"]
        for x in r2["steps"][idx[1]]["receipts"]["receipts"]:
            x["block_height"] += 5
        self.assertEqual(O.ordering_verdict(O.legs_of(r2, idx))["verdict"], O.SEQUENTIAL)


if __name__ == "__main__":
    unittest.main()
