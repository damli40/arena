"""Tests for attack admission: the spec rules (validator) and the gate's pure judgement (admit.py).

  python3 -I -m unittest discover -s tools/admission/tests -v      (from the repo root)

No sandbox, no network. The gate's judgement is run on result files already committed under
evidence/ (mutation table of 2026-11-11, intents check of 2026-11-11). Race-ordering cases add a
per-receipt trace (steps[].receipts, the shape harness/src/receipts.rs writes on the
universal-guards branch) to copies of those files in memory, because no committed run has one yet.
"""
import copy, hashlib, json, pathlib, shutil, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools" / "hunter"))
sys.path.insert(0, str(ROOT / "tools" / "admission"))
import validate as V  # noqa: E402
import admit as A  # noqa: E402

MUT = ROOT / "evidence" / "mutation-2026-11-11"
INT = ROOT / "evidence" / "check-intents-2026-11-11"
REFS = V.load_references()
# the gate's own committed runs for scripted-03 (three distinct results per reference)
GATE03 = sorted((ROOT / "evidence" / "admission" / "scripted-03-sequential-second-pay").glob("*/"))[0]


def load(p):
    return json.loads(pathlib.Path(p).read_text())


def attack(name):
    d = "sequences-intents" if name.startswith("intents-") else "sequences-scripted"
    return load(ROOT / d / f"{name}.json")


def entry(spec, ref):
    return next(e for e in spec["expected"] if e["reference"] == ref)


def judge(doc, ref, result):
    spec = doc["meta"]["spec"]
    return A.judge_run(result, entry(spec, ref), spec, doc["steps"], REFS[ref]["wasm_sha256"], REFS[ref].get("target_label"))


def committed(name, ref):
    if name.startswith("intents-"):
        lab = ref.replace("-", "_")
        return load(INT / ref / "runs" / f"{name}__{lab}.result.json")
    folder = "baseline-vault-a" if ref == "vault-a" else ref.split(":")[1]
    return load(MUT / folder / f"{name}.result.json")


def trace(guard, check_h, cb_h, *, ok=True, token="token.test.near"):
    rs = [{"index": 0, "executor": guard, "block_height": check_h, "ok": ok, "gas_burnt": "1", "logs": 1, "children": 1 if ok else 0}]
    if ok:
        rs += [{"index": 1, "executor": token, "block_height": check_h + 1, "ok": True, "gas_burnt": "1", "logs": 1, "children": 1},
               {"index": 2, "executor": guard, "block_height": cb_h, "ok": True, "gas_burnt": "1", "logs": 1, "children": 0}]
    return {"tx_hash": "x", "tx_block_height": check_h - 1, "receipts": rs}


def with_receipts(result, *traces):
    r = copy.deepcopy(result)
    legs = [s for s in r["steps"] if s["kind"] == "race-call"]
    assert len(legs) == len(traces)
    for s, t in zip(legs, traces):
        s["receipts"] = t
    return r


SPEC_OK = {"property": "p", "failure_mode": "f", "capabilities": ["C1"], "ordering": "none",
           "expected": [{"reference": "vault-a", "outcome": "held", "beyond_policy": 0, "mechanism": [{"pred": "over_equals", "receiver": "sam", "amount": 0}]},
                        {"reference": "mutant:M4", "outcome": "broke", "beyond_policy": 100, "receiver": "sam", "flaw": "no-already-paid-check",
                         "mechanism": [{"pred": "over_equals", "receiver": "sam", "amount": 100}]}]}
SEQ_STEPS = [{"call": {"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}}}] * 2
RACE_STEPS = [{"race": [{"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}}] * 2}]


class SpecRules(unittest.TestCase):
    """T1: what meta.spec may and may not say."""

    def bad(self, spec, steps=SEQ_STEPS, msg=None):
        with self.assertRaises(V.Invalid) as cm:
            V.check_spec(spec, steps)
        if msg:
            self.assertIn(msg, str(cm.exception))

    def mod(self, f):
        s = copy.deepcopy(SPEC_OK)
        f(s)
        return s

    def test_good_spec_passes(self):
        V.check_spec(SPEC_OK, SEQ_STEPS)

    def test_library_specs_valid(self):
        for n in ("02-race-double-pay", "03-sequential-second-pay", "04-pay-cancelled", "05-pay-expired",
                  "06-pay-removed-payee", "07-outsider-pays", "09-pay-over-cap", "intents-01-agent-names-outsider-beneficiary"):
            d = attack(n)
            self.assertIn("spec", d["meta"], n)
            V.check_attack(d, intents_suite=n.startswith("intents-"))

    def test_unknown_reference(self):
        self.bad(self.mod(lambda s: s["expected"][1].update(reference="mutant:M99")), msg="closed list")

    def test_held_on_known_bad(self):
        self.bad(self.mod(lambda s: s["expected"][1].update(outcome="held", beyond_policy=0, flaw=None) or s["expected"][1].pop("flaw")), msg="known-good")

    def test_broke_on_known_good(self):
        self.bad(self.mod(lambda s: s["expected"][0].update(outcome="broke", beyond_policy=100, flaw="x")), msg="known-bad")

    def test_broke_without_flaw_or_amount(self):
        self.bad(self.mod(lambda s: s["expected"][1].pop("flaw")), msg="name the flaw")
        self.bad(self.mod(lambda s: s["expected"][1].update(beyond_policy=0)), msg="positive")

    def test_race_needs_ordering(self):
        self.bad(SPEC_OK, steps=RACE_STEPS, msg="ordering is required")
        V.check_spec({**SPEC_OK, "ordering": "overlap"}, RACE_STEPS)

    def test_unknown_predicate_and_step_out_of_range(self):
        self.bad(self.mod(lambda s: s["expected"][0]["mechanism"].append({"pred": "trust_me"})), msg="unknown predicate")
        self.bad(self.mod(lambda s: s["expected"][0]["mechanism"].append({"pred": "failure_contains", "step": 2, "text": "x"})), msg="records 2")

    def test_waits_are_not_recorded_steps(self):
        steps = [{"wait_seconds": 30}] + SEQ_STEPS
        s = self.mod(lambda s: s["expected"][0]["mechanism"].append({"pred": "failure_contains", "step": 2, "text": "x"}))
        self.bad(s, steps=steps, msg="records 2")

    def test_matched_entries(self):
        self.assertEqual([e["reference"] for e in V.matched_entries(SPEC_OK)], ["mutant:M4"])
        s = self.mod(lambda s: s["expected"][1].update(flaw="no-payee-check"))  # wrong flaw for M4
        self.assertEqual(V.matched_entries(s), [])
        s = self.mod(lambda s: s["expected"][1].update(reference="leaky-control-v2", flaw="several"))
        self.assertEqual(V.matched_entries(s), [], "leaky-control-v2 is never a matched reference")
        # reviewer finding 8: a one-flaw copy counts only next to the known-good it was made from
        s = self.mod(lambda s: s["expected"][0].update(reference="guard:fixed"))
        self.assertEqual(V.matched_entries(s), [], "M4 is vault-a's twin, not guard:fixed's")

    def test_admission_needs_spec(self):
        meta = {**attack("03-sequential-second-pay")["meta"]}
        meta.pop("spec")
        meta["admission"] = {"class": "validated"}
        with self.assertRaises(V.Invalid):
            V.check_meta(meta, SEQ_STEPS)


class ForgedStamps(unittest.TestCase):
    """T1: a hand-written or edited admission stamp is refused; only one that follows from stored runs passes."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.doc = attack("03-sequential-second-pay")
        self.meta = self.doc["meta"]
        self.rel = f"evidence/admission/{self.meta['id']}/20261112T000000Z"
        self.folder = self.tmp / self.rel
        self.folder.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write_evidence(self, files, cls, counted=None):
        runs = []
        for ref, n, src in files:
            name = f"run-{A.ref_slug(ref)}-{n}.result.json"
            shutil.copyfile(src, self.folder / name)
            runs.append({"reference": ref, "n": n, "file": name, "file_sha256": A.sha256_file(self.folder / name)})
        ev = {"attack_id": self.meta["id"], "gate": A.GATE, "class": cls, "runs": runs, "runs_required": 3,
              "runs_counted": len(runs) if counted is None else counted, "runs_tried": len(runs),
              "steps_sha256": self.meta["steps_sha256"], "spec_sha256": V.spec_sha256(self.meta["spec"])}
        (self.folder / "admission.json").write_text(json.dumps(ev))
        return ev

    def stamp(self, cls, ev):
        return {**self.meta, "admission": {"class": cls, "evidence": self.rel, "date": "2026-11-12", "gate": A.GATE,
                                           "runs_counted": ev["runs_counted"], "runs_tried": ev["runs_tried"]}}

    def check(self, meta):
        V.check_admission(meta, self.doc["steps"], root=self.tmp)

    GATE03 = GATE03
    GOOD = [("vault-a", n, GATE03 / f"run-vault-a-{n}.result.json") for n in (1, 2, 3)] + \
           [("mutant:M4", n, GATE03 / f"run-mutant-m4-{n}.result.json") for n in (1, 2, 3)]

    def test_genuine_stamp_accepted(self):
        ev = self.write_evidence(self.GOOD, "validated")
        self.check(self.stamp("validated", ev))

    def test_forged_validated_with_no_evidence(self):
        meta = {**self.meta, "admission": {"class": "validated", "evidence": f"evidence/admission/{self.meta['id']}/20261112T010101Z",
                                           "date": "2026-11-12", "gate": A.GATE, "runs_counted": 6, "runs_tried": 6}}
        with self.assertRaises(V.Invalid) as cm:
            self.check(meta)
        self.assertIn("not found", str(cm.exception))

    def test_forged_validated_where_runs_do_not_support_it(self):
        # the "known-bad" runs are really vault-a holds: the forger wrote validated anyway, in both places
        files = self.GOOD[:3] + [("mutant:M4", n, self.GATE03 / f"run-vault-a-{n}.result.json") for n in (1, 2, 3)]
        # (the same files twice would already be refused as duplicates; here the forger relabels distinct holds)
        ev = self.write_evidence(files, "validated")
        with self.assertRaises(V.Invalid) as cm:
            self.check(self.stamp("validated", ev))
        self.assertIn("does not follow from the stored runs", str(cm.exception))

    def test_forged_upgrade_of_class(self):
        ev = self.write_evidence(self.GOOD[:3] + self.GOOD[3:4], "partially-validated", counted=4)  # only 1 M4 run: partial
        with self.assertRaises(V.Invalid):
            self.check(self.stamp("validated", ev))
        self.check(self.stamp("partially-validated", ev))  # the honest stamp for the same runs passes

    def test_forged_runs_required_zero(self):
        # reviewer forgery 1: a race with 0 counted runs, runs_required set to 0, stamped validated
        ev = self.write_evidence(self.GOOD, "validated")
        ev["runs_required"] = 0
        (self.folder / "admission.json").write_text(json.dumps(ev))
        with self.assertRaises(V.Invalid) as cm:
            self.check(self.stamp("validated", ev))
        self.assertIn("below the gate's minimum", str(cm.exception))

    def test_one_run_listed_three_times(self):
        # reviewer forgery 2: one result per reference, listed as runs 1, 2, 3
        ev = self.write_evidence(self.GOOD[:1] + self.GOOD[3:4], "validated", counted=6)
        ev["runs"] = [dict(r, n=n) for r in ev["runs"] for n in (1, 2, 3)]
        ev["runs_tried"] = 6
        (self.folder / "admission.json").write_text(json.dumps(ev))
        with self.assertRaises(V.Invalid) as cm:
            self.check(self.stamp("validated", ev))
        self.assertIn("counted twice", str(cm.exception))

    def test_stored_run_edited_after_the_gate(self):
        ev = self.write_evidence(self.GOOD, "validated")
        f = self.folder / ev["runs"][3]["file"]
        f.write_text(f.read_text().replace('"unauthorised_payout": "100"', '"unauthorised_payout": "101"'))
        with self.assertRaises(V.Invalid) as cm:
            self.check(self.stamp("validated", ev))
        self.assertIn("changed after the gate wrote it", str(cm.exception))

    def test_spec_edited_after_admission(self):
        ev = self.write_evidence(self.GOOD, "validated")
        meta = self.stamp("validated", ev)
        meta["spec"] = copy.deepcopy(meta["spec"])
        meta["spec"]["property"] += " (edited)"
        with self.assertRaises(V.Invalid) as cm:
            self.check(meta)
        self.assertIn("different spec", str(cm.exception))

    def test_counts_must_match(self):
        ev = self.write_evidence(self.GOOD, "validated")
        meta = self.stamp("validated", ev)
        meta["admission"]["runs_counted"] = 5
        with self.assertRaises(V.Invalid):
            self.check(meta)


class Judge(unittest.TestCase):
    """T2: one run against its expected entry, on committed results."""

    SEQ = {"03-sequential-second-pay": "mutant:M4", "04-pay-cancelled": "mutant:M7", "05-pay-expired": "mutant:M6",
           "06-pay-removed-payee": "mutant:M1", "07-outsider-pays": "mutant:M8", "09-pay-over-cap": "mutant:M2"}

    def test_committed_runs_match_specs(self):
        for name, bad in self.SEQ.items():
            d = attack(name)
            for ref in ("vault-a", bad):
                j = judge(d, ref, committed(name, ref))
                self.assertTrue(j["outcome_ok"] and j["counted"], f"{name} on {ref}: {j['reasons']}")
        d = attack("intents-01-agent-names-outsider-beneficiary")
        for ref in ("intents-honest", "intents-planted"):
            j = judge(d, ref, committed("intents-01-agent-names-outsider-beneficiary", ref))
            self.assertTrue(j["counted"], f"intents-01 on {ref}: {j['reasons']}")

    def test_held_run_does_not_satisfy_broke_entry(self):
        d = attack("03-sequential-second-pay")
        j = judge(d, "mutant:M4", {**committed("03-sequential-second-pay", "vault-a"), "target_wasm_sha256": REFS["mutant:M4"]["wasm_sha256"]})
        self.assertFalse(j["outcome_ok"])
        self.assertIn("paid 0", j["reasons"][0])

    def test_wrong_bytes_refused(self):
        d = attack("03-sequential-second-pay")
        r = committed("03-sequential-second-pay", "mutant:M4")
        # the M4 result judged as if the gate had pinned M7's bytes: refused on the hash alone
        j = A.judge_run(r, entry(d["meta"]["spec"], "mutant:M4"), d["meta"]["spec"], d["steps"], REFS["mutant:M7"]["wasm_sha256"])
        self.assertFalse(j["outcome_ok"])
        self.assertIn("pins", j["reasons"][0])

    def test_mode_relabel_refused(self):
        # reviewer finding 7: guard:fixed and guard:vulnerable_fixture share wasm bytes; the target label tells them apart
        d = attack("02-race-double-pay")
        r = copy.deepcopy(committed("02-race-double-pay", "mutant:M5"))
        r["target"] = "guard-fixed"
        r["target_wasm_sha256"] = REFS["guard:vulnerable_fixture"]["wasm_sha256"]
        j = judge(d, "guard:vulnerable_fixture", r)
        self.assertTrue(any("different mode" in x for x in j["reasons"]))

    def test_missing_outside_data_is_not_zero(self):
        r = copy.deepcopy(committed("intents-01-agent-names-outsider-beneficiary", "intents-honest"))
        r["final"].pop("paid_outside_receivers")
        ok, _ = A.eval_pred({"pred": "outside_equals", "to": "outsider", "amount": 0}, r)
        self.assertFalse(ok)

    def test_error_is_never_a_hold(self):
        d = attack("03-sequential-second-pay")
        j = judge(d, "vault-a", None)
        self.assertFalse(j["outcome_ok"] or j["counted"])

    def test_invalid_result_refused(self):
        d = attack("03-sequential-second-pay")
        r = copy.deepcopy(committed("03-sequential-second-pay", "vault-a"))
        r["score"]["valid"] = False
        r["score"]["invalid_reasons"] = ["conservation"]
        self.assertFalse(judge(d, "vault-a", r)["outcome_ok"])

    def test_wrong_mechanism_refused(self):
        # M4 broke for 100 but suppose sam's row were clean: the amount alone is not enough
        d = attack("03-sequential-second-pay")
        r = copy.deepcopy(committed("03-sequential-second-pay", "mutant:M4"))
        for row in r["final"]["received"]:
            if row["receiver"] == "sam":
                row["over"] = "0"
        j = judge(d, "mutant:M4", r)
        self.assertFalse(j["outcome_ok"])

    def test_m2_leak_only_in_above_cap(self):
        # M2's leak is invisible per receiver (kai's invoice is approved); the spec must read above_cap
        r = committed("09-pay-over-cap", "mutant:M2")
        self.assertEqual(A._over(r, "kai"), 0)
        ok, _ = A.eval_pred({"pred": "score_equals", "field": "above_cap", "value": 100}, r)
        self.assertTrue(ok)

    def test_intents_leak_only_in_paid_outside(self):
        r = committed("intents-01-agent-names-outsider-beneficiary", "intents-planted")
        self.assertTrue(all(row["over"] == "0" for row in r["final"]["received"]))
        self.assertEqual(A._outside(r, "outsider"), 200)
        self.assertEqual(A._outside(committed("intents-01-agent-names-outsider-beneficiary", "intents-honest"), "outsider"), 0)


class RaceOrdering(unittest.TestCase):
    """T2: a race counts only with receipt-level proof that the calls overlapped."""

    def setUp(self):
        self.doc = attack("02-race-double-pay")
        self.bad = committed("02-race-double-pay", "mutant:M5")
        self.good = committed("02-race-double-pay", "vault-a")
        self.g = "vault.test.near"

    def test_absent_trace_is_unproven_never_proven(self):
        self.assertNotIn("receipts", self.bad["steps"][0])
        j = judge(self.doc, "mutant:M5", self.bad)
        self.assertTrue(j["outcome_ok"])
        self.assertFalse(j["counted"])
        self.assertEqual(j["ordering"]["status"], "unproven")
        self.assertIn("steps[].receipts absent", j["ordering"]["why"])
        j = judge(self.doc, "vault-a", self.good)
        self.assertEqual(j["ordering"]["status"], "unproven")

    def test_absent_trace_caps_class_at_partial(self):
        judged = {"vault-a": [judge(self.doc, "vault-a", self.good)] * 3, "mutant:M5": [judge(self.doc, "mutant:M5", self.bad)] * 3,
                  "guard:vulnerable_fixture": [judge(self.doc, "mutant:M5", self.bad)] * 3}
        for j in judged["guard:vulnerable_fixture"]:
            j["outcome_ok"] = True
        cls, why = A.classify(self.doc["meta"]["spec"], judged, REFS, 3)
        self.assertEqual(cls, "partially-validated")
        self.assertIn("ordering", why)

    def test_same_block_overlap_proven(self):
        r = with_receipts(self.bad, trace(self.g, 111, 113), trace(self.g, 111, 113))
        j = judge(self.doc, "mutant:M5", r)
        self.assertEqual(j["ordering"]["status"], "proven", j["ordering"]["why"])
        self.assertTrue(j["counted"])

    def test_cross_block_overlap_proven(self):
        # the Nov 11 finding: "same block" races land in blocks 111/112; still a race if 112 < first callback
        r = with_receipts(self.bad, trace(self.g, 111, 113), trace(self.g, 112, 114))
        self.assertEqual(judge(self.doc, "mutant:M5", r)["ordering"]["status"], "proven")

    def test_same_block_as_callback_is_a_tie_unproven(self):
        # later check in the SAME block as the earlier callback: tie, never counted (break side)
        r = with_receipts(self.bad, trace(self.g, 111, 113), trace(self.g, 113, 115))
        j = judge(self.doc, "mutant:M5", r)
        self.assertEqual(j["ordering"]["status"], "unproven")
        self.assertIn("tie", j["ordering"]["why"])
        self.assertFalse(j["counted"])

    def test_tie_on_the_hold_side_unproven(self):
        r = with_receipts(self.good, trace(self.g, 111, 113), trace(self.g, 113, None, ok=False))
        j = judge(self.doc, "vault-a", r)
        self.assertEqual(j["ordering"]["status"], "unproven")
        self.assertFalse(j["counted"])

    def test_later_check_after_callback_is_not_a_race(self):
        r = with_receipts(self.bad, trace(self.g, 111, 113), trace(self.g, 114, 116))
        j = judge(self.doc, "mutant:M5", r)
        self.assertEqual(j["ordering"]["status"], "not-overlapping")
        self.assertFalse(j["counted"])

    def test_known_good_refusal_overlap_proven(self):
        # vault-a: one pay transfers (callback at 113), the other is refused in the guard at 111
        r = with_receipts(self.good, trace(self.g, 111, 113), trace(self.g, 111, None, ok=False))
        j = judge(self.doc, "vault-a", r)
        self.assertEqual(j["ordering"]["status"], "proven", j["ordering"]["why"])
        self.assertTrue(j["counted"])

    def test_refusal_after_callback_is_not_a_race(self):
        r = with_receipts(self.good, trace(self.g, 111, 113), trace(self.g, 114, None, ok=False))
        self.assertEqual(judge(self.doc, "vault-a", r)["ordering"]["status"], "not-overlapping")

    def test_refusal_before_any_payment_started_is_not_a_race(self):
        # reviewer finding 5: leg B refused at 100, leg A checks at 105, callback 110: no overlap
        r = with_receipts(self.good, trace(self.g, 105, 110), trace(self.g, 100, None, ok=False))
        self.assertEqual(judge(self.doc, "vault-a", r)["ordering"]["status"], "not-overlapping")

    def _legs(self, *receipt_lists):
        # receipt_lists: per leg, [(executor, block_height, ok), ...]; receipt index order = list order
        return {"steps": [{"kind": "race-call", "outcome": "ok", "receipts": {"tx_hash": "x", "receipts": [
            {"index": k, "executor": e, "block_height": h, "ok": ok} for k, (e, h, ok) in enumerate(rl)]}}
            for rl in receipt_lists]}

    def test_T1_callback_is_earliest_guard_receipt_after_token(self):
        # race-ordering reviewer T1: leg A check 10, token 11, callback 12, token 13, guard 14; leg B
        # checked at 13, after A's result was written at 12: sequential. Picking the LAST guard
        # receipt (14) as the callback called this a proven overlap.
        g, t = self.g, "token.test.near"
        a = [(g, 10, True), (t, 11, True), (g, 12, True), (t, 13, True), (g, 14, True)]
        refused = self._legs(a, [(g, 13, False)])
        self.assertEqual(A.race_ordering(refused, [0, 1])["status"], "not-overlapping")
        paying = self._legs(a, [(g, 13, True), (t, 14, True), (g, 15, True)])
        self.assertEqual(A.race_ordering(paying, [0, 1])["status"], "not-overlapping")

    def test_T3_refused_before_any_paying_check_is_not_overlapping(self):
        # race-ordering reviewer T3: the refused leg's check (9) ran before the paying leg's check (10)
        g, t = self.g, "token.test.near"
        r = self._legs([(g, 10, True), (t, 11, True), (g, 12, True)], [(g, 9, False)])
        self.assertEqual(A.race_ordering(r, [0, 1])["status"], "not-overlapping")

    def test_early_refused_leg_does_not_hide_an_overlap_between_the_others(self):
        # race-ordering review: leg A refused at 109; legs B and C check at 110, callbacks 112. Without A
        # this is a proven overlap; A must be dropped, not turn the whole race into "sequential".
        g, t = self.g, "token.test.near"
        pay = lambda: [(g, 110, True), (t, 111, True), (g, 112, True)]
        r = self._legs([(g, 109, False)], pay(), pay())
        o = A.race_ordering(r, [0, 1, 2])
        self.assertEqual(o["status"], "proven", o["why"])
        self.assertIn("not counted", o["why"])
        # B and C still in a row after dropping A: not overlapping, judged on B and C
        r = self._legs([(g, 109, False)], pay(), [(g, 113, True), (t, 114, True), (g, 115, True)])
        self.assertEqual(A.race_ordering(r, [0, 1, 2])["status"], "not-overlapping")

    def test_unknown_height_unproven(self):
        t = trace(self.g, 111, 113)
        t["receipts"][2]["block_height"] = None
        r = with_receipts(self.bad, t, trace(self.g, 111, 113))
        self.assertEqual(judge(self.doc, "mutant:M5", r)["ordering"]["status"], "unproven")

    def test_no_callback_unproven(self):
        r = with_receipts(self.good, trace(self.g, 111, None, ok=False), trace(self.g, 111, None, ok=False))
        self.assertEqual(judge(self.doc, "vault-a", r)["ordering"]["status"], "unproven")

    def test_leg_not_included_unproven(self):
        r = with_receipts(self.bad, trace(self.g, 111, 113), trace(self.g, 111, 113))
        r["steps"][1]["outcome"] = "not-included"
        self.assertEqual(judge(self.doc, "mutant:M5", r)["ordering"]["status"], "unproven")


class Classify(unittest.TestCase):
    def setUp(self):
        self.doc = attack("03-sequential-second-pay")
        self.spec = self.doc["meta"]["spec"]
        self.h = judge(self.doc, "vault-a", committed("03-sequential-second-pay", "vault-a"))
        self.b = judge(self.doc, "mutant:M4", committed("03-sequential-second-pay", "mutant:M4"))

    def test_validated(self):
        self.assertEqual(A.classify(self.spec, {"vault-a": [self.h] * 3, "mutant:M4": [self.b] * 3}, REFS, 3)[0], "validated")

    def test_one_wrong_run_unvalidated(self):
        wrong = judge(self.doc, "mutant:M4", None)
        self.assertEqual(A.classify(self.spec, {"vault-a": [self.h] * 3, "mutant:M4": [self.b, self.b, wrong]}, REFS, 3)[0], "unvalidated")

    def test_too_few_runs_partial(self):
        self.assertEqual(A.classify(self.spec, {"vault-a": [self.h] * 3, "mutant:M4": [self.b]}, REFS, 3)[0], "partially-validated")

    def test_reference_never_run_unvalidated(self):
        self.assertEqual(A.classify(self.spec, {"vault-a": [self.h] * 3}, REFS, 3)[0], "unvalidated")

    def test_break_only_on_unmatched_reference_partial(self):
        spec = copy.deepcopy(self.spec)
        spec["expected"][1].update(reference="leaky-control-v2", flaw="several")
        self.assertEqual(A.classify(spec, {"vault-a": [self.h] * 3, "leaky-control-v2": [self.b] * 3}, REFS, 3)[0], "partially-validated")

    def test_no_spec_expected_unvalidated(self):
        self.assertEqual(A.classify({"property": "p", "failure_mode": "f", "capabilities": ["C1"]}, {}, REFS, 3)[0], "unvalidated")


class RecheckCommand(unittest.TestCase):
    """B1: `admit.py --recheck <file>` (the outsider's no-sandbox check) must refuse a stamp that is not
    bound to the file it sits on, not only re-judge the stored runs. Every case runs the --recheck path."""

    LINE03 = ("recheck scripted-03-sequential-second-pay: stored runs give validated (every reference matched in 3 "
              "counted runs; matched known-bad: mutant:M4); stamp agrees")
    LINE02 = ("recheck scripted-02-race-double-pay: stored runs give partially-validated (outcomes matched, race ordering "
              "not shown: " + "; ".join(f"{r}: ordering unproven (no per-receipt trace in the result (steps[].receipts absent): "
                                           "ordering cannot be shown)" for r in ("vault-a", "guard:vulnerable_fixture", "mutant:M5"))
              + "); stamp agrees")

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def cli(self, path):
        import subprocess
        p = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "admission" / "admit.py"), "--recheck", str(path)],
                           capture_output=True, text=True, cwd=ROOT)
        return p.returncode, p.stdout.strip().splitlines()

    def write(self, doc, name="forged.json"):
        f = self.tmp / name
        f.write_text(json.dumps(doc, indent=1))
        return f

    def refused(self, path, root=ROOT, cli=False, contains=None):
        code, lines = self.cli(path) if cli else A.recheck(path, root=root)
        self.assertEqual(code, 1, lines)
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("REFUSED", lines[0])
        self.assertNotIn("stamp agrees", lines[0])
        if contains:
            self.assertIn(contains, lines[0])
        return lines[0]

    def test_genuine_03_and_02_agree(self):
        self.assertEqual(self.cli(ROOT / "sequences-scripted" / "03-sequential-second-pay.json"), (0, [self.LINE03]))
        self.assertEqual(self.cli(ROOT / "sequences-scripted" / "02-race-double-pay.json"), (0, [self.LINE02]))

    def test_repro1_stamp_and_spec_copied_onto_another_attack(self):
        src = attack("03-sequential-second-pay")
        doc = load(ROOT / "sequences-ai" / "01-double-pay-race-retry.json")
        doc["meta"]["spec"], doc["meta"]["admission"] = src["meta"]["spec"], src["meta"]["admission"]
        self.refused(self.write(doc), cli=True, contains="ordering")

    def test_repro2_steps_changed_hash_recomputed_spec_edited(self):
        doc = attack("03-sequential-second-pay")
        doc["steps"][1]["call"]["args"]["id"] = "inv-other"
        doc["meta"]["steps_sha256"] = V.steps_hash(doc["steps"])
        doc["meta"]["spec"]["property"] += " (edited)"
        self.refused(self.write(doc), cli=True, contains="different steps")

    def test_evidence_folder_swapped_to_another_attack(self):
        doc = attack("03-sequential-second-pay")
        other = attack("04-pay-cancelled")["meta"]["admission"]["evidence"]
        doc["meta"]["admission"]["evidence"] = other
        self.refused(self.write(doc), cli=True, contains="own folder")

    def _own_folder(self, doc, files, cls):
        meta = doc["meta"]
        rel = f"evidence/admission/{meta['id']}/20261112T000000Z"
        folder = self.tmp / rel
        folder.mkdir(parents=True)
        runs = []
        for ref, n, src in files:
            name = f"run-{A.ref_slug(ref)}-{n}.result.json"
            shutil.copyfile(src, folder / name)
            runs.append({"reference": ref, "n": n, "file": name, "file_sha256": A.sha256_file(folder / name)})
        ev = {"attack_id": meta["id"], "gate": A.GATE, "class": cls, "runs": runs, "runs_required": 3,
              "runs_counted": len(runs), "runs_tried": len(runs),
              "steps_sha256": meta["steps_sha256"], "spec_sha256": V.spec_sha256(meta["spec"])}
        (folder / "admission.json").write_text(json.dumps(ev))
        meta["admission"] = {"class": cls, "evidence": rel, "date": "2026-11-12", "gate": A.GATE,
                             "runs_counted": len(runs), "runs_tried": len(runs)}
        return self.write(doc)

    def test_runs_taken_from_another_attacks_folder(self):
        # a forged admission.json in 03's own folder, every hash right for 03, but the run files are
        # attack 04's (pay-cancelled: same two pays, other invoice), relabelled as 03's references
        g04 = sorted((ROOT / "evidence" / "admission" / "scripted-04-pay-cancelled").glob("*/"))[0]
        files = [("vault-a", n, g04 / f"run-vault-a-{n}.result.json") for n in (1, 2, 3)] + \
                [("mutant:M4", n, g04 / f"run-mutant-m7-{n}.result.json") for n in (1, 2, 3)]
        f = self._own_folder(attack("03-sequential-second-pay"), files, "validated")
        self.refused(f, root=self.tmp, contains="a run of other steps")

    def test_validated_claimed_on_partly_matching_runs(self):
        # 03's genuine runs, but only two of the three known-bad runs: the honest class is partial
        files = [("vault-a", n, GATE03 / f"run-vault-a-{n}.result.json") for n in (1, 2, 3)] + \
                [("mutant:M4", n, GATE03 / f"run-mutant-m4-{n}.result.json") for n in (1, 2)]
        f = self._own_folder(attack("03-sequential-second-pay"), files, "validated")
        self.refused(f, root=self.tmp, contains="partially-validated")
        # and the honest stamp on the same runs agrees
        doc = load(f)
        shutil.rmtree(self.tmp / "evidence")
        f2 = self._own_folder(doc, files, "partially-validated")
        code, lines = A.recheck(f2, root=self.tmp)
        self.assertEqual(code, 0, lines)
        self.assertIn("stamp agrees", lines[0])

    def test_genuine_folder_copied_agrees_with_tmp_root(self):
        # control for the two cases above: the same construction with 03's own runs passes
        files = [("vault-a", n, GATE03 / f"run-vault-a-{n}.result.json") for n in (1, 2, 3)] + \
                [("mutant:M4", n, GATE03 / f"run-mutant-m4-{n}.result.json") for n in (1, 2, 3)]
        f = self._own_folder(attack("03-sequential-second-pay"), files, "validated")
        self.assertEqual(A.recheck(f, root=self.tmp)[0], 0)


if __name__ == "__main__":
    unittest.main()
