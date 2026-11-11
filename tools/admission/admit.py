#!/usr/bin/env python3
"""The attack admission gate: an attack counts as Validated only if this script says so.

  python3 -I tools/admission/admit.py <attack.json> [--runs 3] [--jobs 4] [--stamp] [--out-root DIR]
      Run the attack on every reference its meta.spec names (fresh local sandbox per run, through
      tools/hunter/runner.py:run_one, the hunter's own path), judge each run, write an evidence
      folder evidence/admission/<id>/<UTC stamp>/, print the class. --stamp also writes
      meta.admission into the attack file (only the gate writes that block).
  python3 -I tools/admission/admit.py <attack.json> --stamp-from evidence/admission/<id>/<stamp>
      Write meta.admission from a gate folder written earlier (so several gate runs can all run on a
      clean tree first). Refused unless the stored runs re-judge to the class the folder records.
  python3 -I tools/admission/admit.py --recheck <attack.json>
      Re-judge the stored runs named by the file's meta.admission (no sandbox). Exit 1 if the
      stamp does not follow from the stored runs. tools/hunter/validate.py calls the same code.

Plain words. A reference is a guard whose behaviour is known in advance: known-good must hold,
known-bad must break by an exact amount through one named flaw (tools/admission/references.json,
pinned by wasm sha256). A run "counts" when its outcome matches the spec AND, for a race, the
harness can show the race really happened (ordering below). Classes:

  validated            every named reference matched in `runs` counted runs each, at least one
                       known-good held, at least one MATCHED known-bad broke (its one documented
                       flaw is the flaw the spec names), every run's wasm hash was the pinned one.
  partially-validated  every run that finished matched the spec, but something is missing: the
                       race ordering is unproven, or the only break is on an unmatched reference,
                       or fewer counted runs than asked.
  unvalidated          anything else (no spec, a wrong outcome, an error, a timeout).

Race ordering ("overlap"). Read from steps[].receipts (per-receipt block heights, added by the
harness on the universal-guards branch). For one race step, each leg's GUARD CHECK is its first
receipt (run by the guard account) and its CALLBACK is the last guard receipt after some other
account's receipt (the token transfer). Proven only if, for every leg X that reached a callback,
every other leg Y whose check ran in the same block or later ran its check in a block STRICTLY
BEFORE X's callback. A missing trace, a missing height, a leg not included, or no leg with a
callback = "unproven", never "proven". A later pay checked at or after an earlier callback =
"not-overlapping" (two payments in a row, not a race).

Everything that decides a class is in the pure functions below (judge_run, race_ordering,
classify); the tests in tools/admission/tests/ run them on committed result files.
"""
import argparse, datetime, hashlib, json, pathlib, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "hunter"))
import validate as V  # noqa: E402

GATE = "tools/admission/admit.py"
GATE_VERSION = 1
DEFAULT_RUNS = 3
MAX_RACE_TRIES = 5


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    return sha256_bytes(pathlib.Path(p).read_bytes())


def ref_slug(ref):
    return ref.replace(":", "-").replace("_", "-").lower()


# ---------------------------------------------------------------- pure: mapping and predicates

def recorded_layout(steps):
    """Attack steps -> (number of recorded result steps, [[result indexes of one race], ...]).
    The harness records one entry per call, view and add_key, one per race LEG, none for waits
    (harness/src/seq.rs execute)."""
    n, races = 0, []
    for st in steps:
        if "race" in st:
            races.append(list(range(n, n + len(st["race"]))))
            n += len(st["race"])
        elif any(k in st for k in ("call", "view", "add_key")):
            n += 1
    return n, races


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _over(result, receiver):
    for r in result.get("final", {}).get("received", []):
        if r.get("receiver") == receiver:
            return _int(r.get("over"))
    return None


def _outside(result, to):
    rows = result.get("final", {}).get("paid_outside_receivers") or []
    total, seen = 0, False
    for r in rows:
        label = str(r.get("to", ""))
        if label == f"the {to}" or label.startswith(f"the {to} "):
            total += _int(r.get("units", r.get("amount"))) or 0
            seen = True
    return total if seen else 0


def eval_pred(p, result):
    """One mechanism predicate (closed vocabulary, validate.PREDICATES) -> (ok, explanation)."""
    steps = result.get("steps", [])
    name = p["pred"]
    if name == "step_outcomes":
        got = [s.get("outcome") for s in steps if s.get("kind") in ("call", "race-call", "add_key")]
        return got == p["value"], f"call outcomes {got}, spec {p['value']}"
    if name == "failure_contains":
        i = p["step"]
        if i >= len(steps):
            return False, f"step {i} not recorded ({len(steps)} recorded)"
        f = steps[i].get("failure") or ""
        return p["text"] in f, f"step {i} failure {'contains' if p['text'] in f else 'lacks'} {p['text']!r}"
    if name == "over_equals":
        got = _over(result, p["receiver"])
        return got == p["amount"], f"{p['receiver']} over {got}, spec {p['amount']}"
    if name == "outside_equals":
        got = _outside(result, p["to"])
        return got == p["amount"], f"paid outside the receivers to {p['to']}: {got}, spec {p['amount']}"
    if name == "score_equals":
        raw = result.get("score", {}).get(p["field"])
        got = raw if isinstance(raw, int) and not isinstance(raw, bool) else _int(raw)
        return got == p["value"], f"score.{p['field']} {got}, spec {p['value']}"
    if name == "status_equals":
        got = next((s.get("status") for s in result.get("final", {}).get("invoice_statuses", []) if s.get("id") == p["invoice"]), None)
        return got == p["status"], f"{p['invoice']} status {got}, spec {p['status']}"
    if name == "credited_equals":
        got = next((_int(c.get("credited")) for c in result.get("final", {}).get("credited_by_invoice", []) if c.get("id") == p["invoice"]), None)
        return got == p["amount"], f"{p['invoice']} credited {got}, spec {p['amount']}"
    if name == "non_agent_pay":
        rows = result.get("final", {}).get("non_agent_pays", [])
        ok = any(r.get("id") == p["invoice"] and r.get("actor") == p["actor"] for r in rows)
        return ok, f"non-agent pay of {p['invoice']} by {p['actor']}: {'recorded' if ok else 'not recorded'}"
    if name == "view_equals":
        i = p["step"]
        if i >= len(steps) or steps[i].get("kind") != "view":
            return False, f"step {i} is not a recorded view"
        got = steps[i].get("view")
        want = p["value"]
        same = got == want or (isinstance(want, int) and not isinstance(want, bool) and _int(got) == want and isinstance(got, str))
        return same, f"view at step {i} = {got!r}, spec {want!r}"
    return False, f"unknown predicate {name}"


def race_ordering(result, idxs):
    """Ordering of ONE race (result step indexes) -> {"status": proven|unproven|not-overlapping, "why", "legs"}."""
    steps = result.get("steps", [])
    legs = []
    for i in idxs:
        if i >= len(steps):
            return {"status": "unproven", "why": f"race leg {i} not recorded", "legs": legs}
        st = steps[i]
        if st.get("outcome") in ("not-included", "protocol-rejected"):
            return {"status": "unproven", "why": f"race leg {i} {st.get('outcome')}: no receipts to order", "legs": legs}
        tr = st.get("receipts")
        rs = tr.get("receipts") if isinstance(tr, dict) else None
        if not rs:
            return {"status": "unproven", "why": "no per-receipt trace in the result (steps[].receipts absent): ordering cannot be shown", "legs": legs}
        guard, check = rs[0].get("executor"), rs[0].get("block_height")
        if not isinstance(check, int):
            return {"status": "unproven", "why": f"race leg {i}: guard check block height unknown", "legs": legs}
        cb, seen_other = None, False
        for r in rs[1:]:
            if r.get("executor") != guard:
                seen_other = True
            elif seen_other:
                cb = r
        if cb is not None and not isinstance(cb.get("block_height"), int):
            return {"status": "unproven", "why": f"race leg {i}: callback block height unknown", "legs": legs}
        legs.append({"step": i, "guard": guard, "check_height": check, "check_ok": bool(rs[0].get("ok")),
                     "callback_height": cb["block_height"] if cb else None, "callback_ok": bool(cb.get("ok")) if cb else None})
    if len({l["guard"] for l in legs}) != 1:
        return {"status": "unproven", "why": "race legs ran on different accounts", "legs": legs}
    with_cb = [l for l in legs if l["callback_height"] is not None]
    if not with_cb:
        return {"status": "unproven", "why": "no race leg reached a callback: nothing for the other calls to overlap", "legs": legs}
    for x in with_cb:
        for y in legs:
            if y is x or y["check_height"] < x["check_height"]:
                continue
            if not y["check_height"] < x["callback_height"]:
                return {"status": "not-overlapping", "legs": legs,
                        "why": f"leg {y['step']} checked in block {y['check_height']}, not strictly before leg {x['step']}'s callback in block {x['callback_height']}: calls in a row, not a race"}
    return {"status": "proven", "legs": legs,
            "why": "every later call's guard check ran in a block strictly before every earlier call's callback"}


def judge_run(result, entry, spec, attack_steps, ref_sha256):
    """One run on one reference -> {"outcome_ok", "reasons", "ordering", "counted"}.
    result None = the harness errored or timed out (never a hold)."""
    out = {"outcome_ok": False, "reasons": [], "ordering": None, "counted": False}
    if result is None:
        out["reasons"].append("no result: harness error or timeout (not validation)")
        return out
    r = out["reasons"]
    s = result.get("score", {})
    if result.get("target_wasm_sha256") != ref_sha256:
        r.append(f"ran wasm {result.get('target_wasm_sha256')}, reference pins {ref_sha256}")
    if s.get("valid") is not True:
        r.append("result invalid: " + "; ".join(s.get("invalid_reasons", []))[:300])
    oracle = spec.get("oracle", {"decides": "beyond_policy"})
    if oracle.get("decides") != "beyond_policy":
        r.append(f"oracle {oracle.get('decides')!r} is not supported by this gate version")
    paid = _int(s.get("unauthorised_payout"))
    if entry["outcome"] == "held" and paid != 0:
        r.append(f"spec says held, paid {paid} beyond policy")
    if entry["outcome"] == "broke" and paid != entry["beyond_policy"]:
        r.append(f"spec says broke for exactly {entry['beyond_policy']}, paid {paid}")
    if entry["outcome"] == "broke" and "receiver" in entry:
        got = _over(result, entry["receiver"])
        if got != entry["beyond_policy"]:
            r.append(f"spec names receiver {entry['receiver']} over by {entry['beyond_policy']}, got {got}")
    _, races = recorded_layout(attack_steps)
    if not races and any(st.get("outcome") == "not-included" for st in result.get("steps", [])):
        r.append("a call was not included in a block")
    for p in entry["mechanism"]:
        ok, why = eval_pred(p, result)
        if not ok:
            r.append(f"mechanism {p['pred']}: {why}")
    out["outcome_ok"] = not r
    if spec.get("ordering", "none") == "overlap":
        ords = [race_ordering(result, idx) for idx in races] or [{"status": "unproven", "why": "spec asks for overlap but the attack has no race step"}]
        worst = next((o for o in ords if o["status"] != "proven"), ords[0])
        out["ordering"] = {"status": worst["status"], "why": worst["why"], "races": ords}
        out["counted"] = out["outcome_ok"] and worst["status"] == "proven"
    else:
        out["ordering"] = {"status": "not-required", "why": "no race in this attack"}
        out["counted"] = out["outcome_ok"]
    return out


def classify(spec, judged, refs, runs_required):
    """judged: {reference: [judge_run output, ...]} -> (class, why).
    The rules in the module docstring, nothing else."""
    exp = spec.get("expected") or []
    if not exp:
        return "unvalidated", "the spec names no expected outcome on any reference"
    if (spec.get("oracle") or {}).get("decides", "beyond_policy") != "beyond_policy":
        return "unvalidated", "this gate version decides beyond_policy only"
    held = [e for e in exp if e["outcome"] == "held"]
    broke = [e for e in exp if e["outcome"] == "broke"]
    if not held or not broke:
        return "unvalidated", "needs at least one known-good that must hold and one known-bad that must break"
    wrong, short, unproven = [], [], []
    for e in exp:
        rs = judged.get(e["reference"], [])
        if not rs:
            wrong.append(f"{e['reference']}: never run")
            continue
        bad = [j for j in rs if not j["outcome_ok"]]
        if bad:
            wrong.append(f"{e['reference']}: {bad[0]['reasons'][0] if bad[0]['reasons'] else 'outcome differs'}")
            continue
        counted = sum(1 for j in rs if j["counted"])
        if counted < runs_required:
            un = [j for j in rs if not j["counted"]]
            if un and un[0]["ordering"] and un[0]["ordering"]["status"] != "proven":
                unproven.append(f"{e['reference']}: ordering {un[0]['ordering']['status']} ({un[0]['ordering']['why']})")
            short.append(f"{e['reference']}: {counted} counted of {runs_required} required")
    if wrong:
        return "unvalidated", "; ".join(wrong)
    matched = [e for e in V.matched_entries(spec, refs)]
    if not matched:
        return "partially-validated", "outcomes matched, but no break is on a matched reference (one documented flaw = the named flaw)"
    if unproven:
        return "partially-validated", "outcomes matched, race ordering not shown: " + "; ".join(unproven)
    if short:
        return "partially-validated", "outcomes matched, too few counted runs: " + "; ".join(short)
    return "validated", f"every reference matched in {runs_required} counted runs; matched known-bad: " + ", ".join(e["reference"] for e in matched)


# ---------------------------------------------------------------- recheck (pure over stored files)

def rederive(doc, root=ROOT, refs=None):
    """Re-judge the stored runs behind doc.meta.admission. Returns (class, why, problems).
    problems non-empty = the stamp does not follow from the stored evidence."""
    meta = doc["meta"]
    a = meta["admission"]
    refs = V.load_references() if refs is None else refs
    folder = root / a["evidence"]
    problems = []
    try:
        ev = json.loads((folder / "admission.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None, None, [f"{a['evidence']}/admission.json missing or not JSON"]
    spec = meta["spec"]
    judged = {}
    for run in ev.get("runs", []):
        ref = run.get("reference")
        if ref not in refs:
            problems.append(f"stored run names unknown reference {ref!r}")
            continue
        result = None
        if run.get("file"):
            p = folder / run["file"]
            if not p.is_file():
                problems.append(f"stored run file {run['file']} missing")
                continue
            if sha256_file(p) != run.get("file_sha256"):
                problems.append(f"stored run file {run['file']} changed after the gate wrote it")
                continue
            result = json.loads(p.read_text())
        entry = next((e for e in spec.get("expected", []) if e["reference"] == ref), None)
        if entry is None:
            problems.append(f"stored run on {ref}, which the spec does not name")
            continue
        judged.setdefault(ref, []).append(judge_run(result, entry, spec, doc["steps"], refs[ref]["wasm_sha256"]))
    cls, why = classify(spec, judged, refs, ev.get("runs_required", DEFAULT_RUNS))
    if ev.get("class") != cls:
        problems.append(f"admission.json says {ev.get('class')!r}, the stored runs give {cls!r} ({why})")
    if a.get("class") != cls:
        problems.append(f"meta.admission says {a.get('class')!r}, the stored runs give {cls!r} ({why})")
    counted = sum(1 for js in judged.values() for j in js if j["counted"])
    tried = sum(len(js) for js in judged.values())
    if (ev.get("runs_counted"), ev.get("runs_tried")) != (counted, tried):
        problems.append(f"admission.json run counts {ev.get('runs_counted')}/{ev.get('runs_tried')} differ from the stored runs {counted}/{tried}")
    return cls, why, problems


# ---------------------------------------------------------------- running (sandbox)

def git_head():
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        return head, not dirty
    except (OSError, subprocess.CalledProcessError):
        return None, None


def check_reference_bytes(names, refs):
    out = {}
    for n in names:
        p = ROOT / refs[n]["wasm"]
        got = sha256_file(p) if p.is_file() else None
        out[n] = got
        if got != refs[n]["wasm_sha256"]:
            raise SystemExit(f"A1: reference {n}: {refs[n]['wasm']} sha256 {got}, pinned {refs[n]['wasm_sha256']} (build it or fix the pin; the gate does not run on other bytes)")
        if "config_sha256" in refs[n]:
            cfg = refs[n]["harness_flags"][refs[n]["harness_flags"].index("--guard-config") + 1]
            if sha256_file(ROOT / cfg) != refs[n]["config_sha256"]:
                raise SystemExit(f"A1: reference {n}: guard config {cfg} differs from its pin")
    return out


def run_gate(attack_path, runs=DEFAULT_RUNS, jobs=4, stamp=False, out_root=None, timeout=None, quiet=False):
    import runner  # the hunter's runner: fresh sandbox per attempt, hard timeout, timeouts = error
    import concurrent.futures as cf
    attack_path = pathlib.Path(attack_path).resolve()
    raw = attack_path.read_bytes()
    doc = json.loads(raw)
    meta = doc.get("meta", {})
    intents = "sequences-intents" in attack_path.parts or any(c.get("call", {}).get("target") == "intents" for c in doc.get("steps", []))
    V.check_attack({**doc, "meta": {k: v for k, v in meta.items() if k != "admission"}}, intents_suite=intents)  # A0
    spec = meta.get("spec")
    if not spec or not spec.get("expected"):
        raise SystemExit("A0: no meta.spec.expected: nothing to admit against (the file stays unvalidated)")
    refs = V.load_references()
    names = [e["reference"] for e in spec["expected"]]
    before = check_reference_bytes(names, refs)  # A1
    stamp_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rel = f"evidence/admission/{meta['id']}/{stamp_utc}"
    folder = (pathlib.Path(out_root) if out_root else ROOT) / rel
    folder.mkdir(parents=True, exist_ok=False)
    head, clean = git_head()
    race = spec.get("ordering", "none") == "overlap"
    tries = MAX_RACE_TRIES if race else runs
    meta_line = f"admission gate {GATE} v{GATE_VERSION}, attack {meta['id']}, git {head}"
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="admit-"))

    def one(ref, n):
        d = tmp / f"{ref_slug(ref)}-{n}"
        d.mkdir()
        g = {"id": ref_slug(ref), "harness_flags": refs[ref]["harness_flags"]}
        cell = runner.run_one(attack_path, g, d, meta_line, **({"timeout": timeout} if timeout else {}))
        base = f"run-{ref_slug(ref)}-{n}"
        res_file = None
        rj = ROOT / cell["result_json"] if not pathlib.Path(cell["result_json"]).is_absolute() else pathlib.Path(cell["result_json"])
        if cell["status"] != "error" and rj.is_file():
            shutil.copyfile(rj, folder / f"{base}.result.json")
            res_file = f"{base}.result.json"
        lg = ROOT / cell["log"] if not pathlib.Path(cell["log"]).is_absolute() else pathlib.Path(cell["log"])
        if lg.is_file():
            shutil.copyfile(lg, folder / f"{base}.log")
        return ref, n, cell, res_file

    judged, runs_rec = {}, []
    work = [(e["reference"], n) for e in spec["expected"] for n in range(1, (runs if not race else runs) + 1)]
    extra_rounds = tries - runs
    entries = {e["reference"]: e for e in spec["expected"]}
    with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        while work:
            for ref, n, cell, res_file in ex.map(lambda t: one(*t), work):
                result = json.loads((folder / res_file).read_text()) if res_file else None
                j = judge_run(result, entries[ref], spec, doc["steps"], refs[ref]["wasm_sha256"])
                judged.setdefault(ref, []).append(j)
                runs_rec.append({"reference": ref, "n": n, "file": res_file,
                                 "file_sha256": sha256_file(folder / res_file) if res_file else None,
                                 "harness_status": cell["status"], "harness_why": cell.get("why", ""),
                                 "seconds": cell.get("seconds"), "outcome_ok": j["outcome_ok"], "counted": j["counted"],
                                 "reasons": j["reasons"], "ordering": j["ordering"]})
                if not quiet:
                    print(f"  {meta['id']:<44} {ref:<26} run {n}: {'counted' if j['counted'] else 'not counted'}"
                          f"{'' if j['outcome_ok'] else ' WRONG: ' + j['reasons'][0][:90]}"
                          f"{' ordering ' + j['ordering']['status'] if j['ordering']['status'] != 'not-required' else ''}", flush=True)
            # races: up to MAX_RACE_TRIES per reference to collect `runs` counted, but only while the
            # missing runs are ordering misses (an absent trace never improves with more tries)
            work = []
            if race and extra_rounds > 0:
                for ref, js in judged.items():
                    c = sum(1 for j in js if j["counted"])
                    retryable = all(j["outcome_ok"] for j in js) and any(j["ordering"]["status"] == "not-overlapping" for j in js)
                    if c < runs and retryable and len(js) < tries:
                        work.append((ref, len(js) + 1))
                extra_rounds -= 1
    shutil.rmtree(tmp, ignore_errors=True)
    after = check_reference_bytes(names, refs)
    cls, why = classify(spec, judged, refs, runs)
    harness = ROOT / "harness" / "target" / "release" / "arena-harness"
    ev = {"attack_id": meta["id"], "class": cls, "why": why, "gate": GATE, "gate_version": GATE_VERSION,
          "gate_sha256": sha256_file(__file__), "date": stamp_utc[:4] + "-" + stamp_utc[4:6] + "-" + stamp_utc[6:8], "stamp": stamp_utc,
          "git_head": head, "git_tree_clean": clean, "harness_sha256": sha256_file(harness) if harness.is_file() else None,
          "steps_sha256": meta["steps_sha256"], "spec_sha256": V.spec_sha256(spec), "attack_file_sha256": sha256_bytes(raw),
          "runs_required": runs, "runs_counted": sum(1 for r in runs_rec if r["counted"]), "runs_tried": len(runs_rec),
          "references": {n: {"wasm": refs[n]["wasm"], "pinned": refs[n]["wasm_sha256"], "before": before[n], "after": after[n],
                             "kind": refs[n]["kind"], "flaw": refs[n]["flaw"], "matchable": refs[n]["matchable"]} for n in names},
          "matched": [e["reference"] for e in V.matched_entries(spec, refs)],
          "runs": sorted(runs_rec, key=lambda r: (r["reference"], r["n"]))}
    (folder / "spec.json").write_text(json.dumps(spec, indent=1, sort_keys=True) + "\n")
    (folder / "references.json").write_text(json.dumps(ev["references"], indent=1, sort_keys=True) + "\n")
    (folder / "ordering.json").write_text(json.dumps([{"reference": r["reference"], "n": r["n"], "ordering": r["ordering"]} for r in ev["runs"]], indent=1) + "\n")
    (folder / "admission.json").write_text(json.dumps(ev, indent=1, sort_keys=True) + "\n")
    (folder / "ADMISSION.md").write_text(render_md(ev, spec))
    if stamp:
        if out_root:
            raise SystemExit("--stamp writes into the repo; it cannot be combined with --out-root")
        a = {"class": cls, "evidence": rel, "date": ev["date"], "gate": GATE,
             "runs_counted": ev["runs_counted"], "runs_tried": ev["runs_tried"], "why": why[:400]}
        doc["meta"]["admission"] = a
        ind = 1 if raw.startswith(b'{\n "') else 2
        attack_path.write_text(json.dumps(doc, indent=ind, ensure_ascii=False) + "\n")
    return cls, why, folder


def render_md(ev, spec):
    L = [f"# Admission: {ev['attack_id']}", "",
         f"**Class: {ev['class']}.** {ev['why']}", "",
         f"Property: {spec['property']}", "", f"Failure mode: {spec['failure_mode']}", "",
         f"Gate {ev['gate']} v{ev['gate_version']} (sha256 {ev['gate_sha256'][:16]}...), git {ev['git_head']} "
         f"(tree {'clean' if ev['git_tree_clean'] else 'NOT clean'}), harness sha256 {str(ev['harness_sha256'])[:16]}..., {ev['stamp']}.",
         f"Runs counted {ev['runs_counted']} of {ev['runs_tried']} tried; {ev['runs_required']} required per reference.", "",
         "| reference | kind | expected | run | counted | ordering | first problem |", "|---|---|---|---|---|---|---|"]
    exp = {e["reference"]: e for e in spec["expected"]}
    for r in ev["runs"]:
        e = exp[r["reference"]]
        want = "held" if e["outcome"] == "held" else f"broke {e['beyond_policy']}"
        L.append(f"| {r['reference']} | {ev['references'][r['reference']]['kind']} | {want} | {r['n']} | {'yes' if r['counted'] else 'no'} | "
                 f"{r['ordering']['status'] if r['ordering'] else '-'} | {(r['reasons'][0] if r['reasons'] else '').replace('|', '/')[:120]} |")
    L += ["", "What this does not show: that the guard is safe beyond these steps; for a race without a",
          "receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).", ""]
    return "\n".join(L)


def stamp_from(attack_path, rel):
    attack_path = pathlib.Path(attack_path)
    doc = json.loads(attack_path.read_text())
    meta = doc["meta"]
    ev = json.loads((ROOT / rel / "admission.json").read_text())
    if ev.get("attack_id") != meta["id"] or ev.get("steps_sha256") != meta["steps_sha256"] or ev.get("spec_sha256") != V.spec_sha256(meta["spec"]):
        raise SystemExit(f"{rel} is the gate's record for a different attack, steps or spec")
    a = {"class": ev["class"], "evidence": rel.rstrip("/"), "date": ev["date"], "gate": GATE,
         "runs_counted": ev["runs_counted"], "runs_tried": ev["runs_tried"], "why": ev["why"][:400]}
    cls, why, problems = rederive({"meta": {**meta, "admission": a}, "steps": doc["steps"]})
    if problems:
        raise SystemExit("refused: " + "; ".join(problems))
    doc["meta"]["admission"] = a
    ind = 1 if attack_path.read_bytes().startswith(b'{\n "') else 2
    attack_path.write_text(json.dumps(doc, indent=ind, ensure_ascii=False) + "\n")
    print(f"stamped {meta['id']}: {cls} ({why})")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("attack")
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--stamp", action="store_true", help="write meta.admission into the attack file")
    ap.add_argument("--out-root", help="write the evidence folder under this directory instead of the repo (private re-admission)")
    ap.add_argument("--recheck", action="store_true", help="re-judge the stored runs behind meta.admission; no sandbox")
    ap.add_argument("--stamp-from", help="write meta.admission from this existing gate folder (repo-relative)")
    a = ap.parse_args(argv)
    if a.stamp_from:
        return stamp_from(a.attack, a.stamp_from)
    if a.recheck:
        doc = json.loads(pathlib.Path(a.attack).read_text())
        if "admission" not in doc.get("meta", {}):
            print(f"{a.attack}: no meta.admission: unvalidated by definition")
            return 1
        cls, why, problems = rederive(doc)
        for p in problems:
            print("PROBLEM", p)
        print(f"recheck {doc['meta']['id']}: stored runs give {cls} ({why}); stamp {'agrees' if not problems else 'REFUSED'}")
        return 1 if problems else 0
    if not 1 <= a.runs <= 5:
        raise SystemExit("--runs must be 1-5")
    cls, why, folder = run_gate(a.attack, a.runs, a.jobs, a.stamp, a.out_root)
    print(f"ADMISSION {json.loads(pathlib.Path(a.attack).read_text())['meta']['id']}: {cls} ({why})")
    print(f"evidence: {folder}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
