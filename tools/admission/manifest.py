#!/usr/bin/env python3
"""One count manifest: every public count about the attack library, computed from the repo.

  python3 -I tools/admission/manifest.py            write evidence/MANIFEST.json and evidence/MANIFEST.md
  python3 -I tools/admission/manifest.py --check    exit 1 if the committed files differ from a fresh build

Never hand-edit the two files. README.md and EVALUATE.md quote the admission counts in one fixed
sentence each; tools/admission/tests/test_manifest.py fails if a quoted number differs.

Definitions (each a key in MANIFEST.json):
- attacks.library_token: what `arena check` runs on a guard that pays in tokens or NEAR: the
  attack files in sequences-scripted/ai/bypass/paper plus the prompt-injection scenarios in
  tools/injection/scenarios.json, minus duplicates (same steps) and minus the honest control
  (scripted-01). Computed by tools/check/check.py's own library() (imported, not edited).
- attacks.library_intents: the same for a guard that pays into NEAR Intents (adds sequences-intents/).
- attacks.classes: per attack in library_intents (the widest suite), its admission class from
  meta.admission, re-judged from the stored runs (tools/admission/admit.py rederive). An attack
  without a spec, or a scenario (not a file), is unvalidated by definition.
- hunts.*: sums of the per-hunt `counts` blocks in evidence/hunts/20*.json.
- mutants.*: from the latest evidence/mutation-*/summary.tsv (a mutant is caught if any attack
  paid > 0 on it).
- hidden_set: from hidden-set/COMMITMENT.json, if committed.
- attacks.rows[].why for an attack with no admission stamp: "no spec", or the reason recorded in
  tools/admission/unvalidated.json (a person's note on why no matched known-bad exists; closed list
  of reasons in that file). A recorded reason never changes a class: it is refused for any attack
  that carries a spec or a stamp (the gate decides those).
Deterministic: no clock, no git hash inside, so --check can compare byte for byte. Provenance is
the sha256 of every input file (inputs_sha256).
"""
import collections, hashlib, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "hunter"))
sys.path.insert(0, str(ROOT / "tools" / "check"))
sys.path.insert(0, str(ROOT / "tools" / "admission"))
import validate as V  # noqa: E402
import admit  # noqa: E402

OUT_JSON = ROOT / "evidence" / "MANIFEST.json"
OUT_MD = ROOT / "evidence" / "MANIFEST.md"
COMMITMENT = ROOT / "hidden-set" / "COMMITMENT.json"
CLASSES = ("validated", "partially-validated", "unvalidated")
REASONS_FILE = ROOT / "tools" / "admission" / "unvalidated.json"


def load_reasons():
    """{attack id: (reason, detail)} from tools/admission/unvalidated.json. Raises on a bad file."""
    if not REASONS_FILE.exists():
        return {}
    d = json.loads(REASONS_FILE.read_text())
    allowed = d["reasons"]
    out = {}
    for aid, e in d["attacks"].items():
        if set(e) != {"reason", "detail"} or e["reason"] not in allowed or not isinstance(e["detail"], str) or not 0 < len(e["detail"]) <= 300:
            raise SystemExit(f"{REASONS_FILE.name}: {aid}: needs reason (one of {sorted(allowed)}) and detail (1-300 chars)")
        out[aid] = (e["reason"], e["detail"])
    return out


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def library(pays_in):
    import check  # tools/check/check.py, read only
    uniq, problems, dups = check.library(pays_in)
    return [a for a in uniq if a["meta"]["id"] != check.CONTROL_ID], problems, dups, check.CONTROL_ID


def attack_class(a, reasons=None):
    m = a["meta"]
    rid = (reasons or {}).get(m["id"])
    if rid and ("spec" in m or "admission" in m):
        raise SystemExit(f"{REASONS_FILE.name}: {m['id']} has a spec or a stamp; the gate decides its class, a recorded reason may not")
    if "admission" not in m:
        if rid:
            return "unvalidated", f"{rid[0]}: {rid[1]}", None
        return "unvalidated", "no spec" if "spec" not in m else "spec, not yet run through the gate", None
    cls, why, problems = admit.rederive({"meta": m, "steps": a["steps"]})
    if problems:
        return "unvalidated", "stamp refused: " + "; ".join(problems), m["admission"]["evidence"]
    return cls, why, m["admission"]["evidence"]


def build():
    inputs = []
    tok, p1, d1, control = library("token")
    ints, p2, d2, _ = library("intents")
    files = [p for d in ("sequences-scripted", "sequences-ai", "sequences-bypass", "sequences-paper", "sequences-intents")
             for p in sorted((ROOT / d).glob("*.json"))]
    inputs += files + [ROOT / "tools/injection/scenarios.json"]
    by_folder = collections.Counter(p.parent.name for p in files)
    docs = [json.loads(p.read_text()) for p in files]
    rows = []
    reasons = load_reasons()
    if REASONS_FILE.exists():
        inputs.append(REASONS_FILE)
    unknown = sorted(set(reasons) - {a["meta"]["id"] for a in ints})
    if unknown:
        raise SystemExit(f"{REASONS_FILE.name} names attacks not in the library: {unknown}")
    for a in ints:
        cls, why, ev = attack_class(a, reasons)
        rows.append({"id": a["meta"]["id"], "path": a["path"], "kind": a["meta"]["kind"], "source": a["meta"]["source"],
                     "class": cls, "why": why, "evidence": ev, "in_token_suite": any(t["meta"]["id"] == a["meta"]["id"] for t in tok)})
    count = collections.Counter(r["class"] for r in rows)
    count_tok = collections.Counter(r["class"] for r in rows if r["in_token_suite"])
    hunts = sorted((ROOT / "evidence" / "hunts").glob("20*.json"))
    inputs += hunts
    hsum = collections.Counter()
    with_runs = 0
    for h in hunts:
        c = json.loads(h.read_text()).get("counts", {})
        for k in ("attacks_proposed", "attacks_rejected", "attacks_deduped", "attacks_run", "attacks_saved", "saved_broke", "saved_valid_nothing_broke", "papers_read"):
            hsum[k] += int(c.get(k) or 0)
        with_runs += int(c.get("attacks_run") or 0) > 0
    refs_file = ROOT / "tools" / "admission" / "references.json"
    inputs.append(refs_file)
    refs = V.load_references()
    mut_dirs = sorted(ROOT.glob("evidence/mutation-20*/summary.tsv"))
    mutants = None
    if mut_dirs:
        tsv = mut_dirs[-1]
        inputs.append(tsv)
        paid = collections.defaultdict(int)
        for line in tsv.read_text().splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0].startswith("M") and parts[0] != "M0":
                paid[parts[0]] = max(paid[parts[0]], int(parts[2]) if parts[2].isdigit() else 0)
        mutants = {"table": str(tsv.relative_to(ROOT)), "planted": len(paid), "caught": sorted((k for k, v in paid.items() if v > 0), key=lambda k: int(k[1:])),
                   "not_caught": sorted((k for k, v in paid.items() if v == 0), key=lambda k: int(k[1:]))}
    hidden = None
    if COMMITMENT.exists():
        inputs.append(COMMITMENT)
        c = json.loads(COMMITMENT.read_text())
        hidden = {k: c.get(k) for k in ("set_sha256", "attack_count", "capabilities_covered", "families_covered", "created_at", "disjoint_from_public_library")}
    m = {
        "about": "Generated by tools/admission/manifest.py. Never hand-edit. Definitions in that file's docstring.",
        "attacks": {
            "library_token": len(tok), "library_intents": len(ints), "control_not_counted": control,
            "duplicates_skipped": sorted([sorted(x["meta"]["id"] for x in grp) for grp in d2]) if d2 and isinstance(d2[0], (list, tuple)) else len(d2),
            "files_on_disk": len(files), "files_by_folder": dict(sorted(by_folder.items())),
            "files_by_source": dict(sorted(collections.Counter(d["meta"]["source"] for d in docs).items())),
            "files_by_kind": dict(sorted(collections.Counter(d["meta"]["kind"] for d in docs).items())),
            "injection_scenarios_counted": sum(1 for a in ints if a["path"].startswith("tools/injection/")),
            "classes": {k: count.get(k, 0) for k in CLASSES},
            "classes_token_suite": {k: count_tok.get(k, 0) for k in CLASSES},
            "with_spec": sum(1 for a in ints if "spec" in a["meta"]),
            "library_problems": p1 + p2,
            "rows": rows,
        },
        "hunts": {"runs": len(hunts), "runs_with_runnable_attacks": with_runs, **dict(sorted(hsum.items()))},
        "references": {k: {"kind": v["kind"], "flaw": v["flaw"], "matchable": v["matchable"], "wasm_sha256": v["wasm_sha256"]} for k, v in refs.items()},
        "mutants": mutants,
        "hidden_set": hidden,
        "inputs_sha256": {str(p.relative_to(ROOT)): _sha(p) for p in inputs},
    }
    return m


def render_md(m):
    a = m["attacks"]
    c = a["classes"]
    L = ["# Arena count manifest", "",
         "Generated by `tools/admission/manifest.py` from the repo. Never hand-edited. The JSON twin is `evidence/MANIFEST.json`.", "",
         "## Attacks", "",
         f"- **{a['library_intents']}** attacks in the widest suite (a guard paying into NEAR Intents); **{a['library_token']}** for a guard paying in tokens or NEAR.",
         f"- What the {a['library_token']} are: attack files in sequences-scripted, -ai, -bypass, -paper, plus {a['injection_scenarios_counted']} prompt-injection scenarios from `tools/injection/scenarios.json` (not files), minus same-steps duplicates and minus the honest control `{a['control_not_counted']}`. The intents suite adds `sequences-intents/`.",
         f"- Attack files on disk: {a['files_on_disk']} ({', '.join(f'{k} {v}' for k, v in a['files_by_folder'].items())}).", "",
         f"**Admission: {c['validated']} of {a['library_intents']} validated, {c['partially-validated']} partially validated, {c['unvalidated']} unvalidated.** "
         f"({a['with_spec']} carry a spec.)", "",
         "- Validated: the known-good reference held and the matched known-bad reference (one documented flaw, the one the attack names) broke by the exact amount, through the named mechanism, in every counted run, on pinned wasm bytes (`tools/admission/admit.py`).",
         "- Partially validated: every finished run matched, but something is missing (race ordering not shown, too few counted runs, or no matched known-bad).",
         "- Unvalidated: no spec, never run through the gate, or a run did not match. Unvalidated attacks still run on every guard; they are outside the validated count.", "",
         "| attack | class | why | evidence |", "|---|---|---|---|"]
    for r in sorted(a["rows"], key=lambda r: (CLASSES.index(r["class"]), r["id"])):
        if r["class"] != "unvalidated" or r["evidence"] or r["why"] != "no spec":
            L.append(f"| {r['id']} | {r['class']} | {r['why'].replace('|', '/')[:300]} | {r['evidence'] or '-'} |")
    n_nospec = sum(1 for r in a["rows"] if r["class"] == "unvalidated" and not r["evidence"] and r["why"] == "no spec")
    if n_nospec:
        L += [f"| the other {n_nospec} | unvalidated | no spec yet | - |"]
    L += [""]
    h = m["hunts"]
    L += ["## Hunts", "", f"- {h['runs']} hunt records (`evidence/hunts/20*.json`); {h['runs_with_runnable_attacks']} ran at least one attack.",
          f"- Summed: {h['attacks_proposed']} attacks proposed, {h['attacks_rejected']} rejected, {h['attacks_deduped']} duplicates, {h['attacks_run']} run, {h['attacks_saved']} saved ({h['saved_broke']} broke a guard, {h['saved_valid_nothing_broke']} broke nothing). Saved is not validated.", ""]
    if m["mutants"]:
        mu = m["mutants"]
        L += ["## Mutants", "", f"- {mu['planted']} planted-flaw copies of vault-a in `{mu['table']}`: caught {len(mu['caught'])} ({', '.join(mu['caught'])}), not caught {len(mu['not_caught'])} ({', '.join(mu['not_caught']) or 'none'}).", ""]
    L += ["## Hidden set", ""]
    if m["hidden_set"]:
        hs = m["hidden_set"]
        L += [f"- {hs['attack_count']} attacks, set sha256 `{hs['set_sha256']}`, committed {hs['created_at']}; capabilities {', '.join(hs['capabilities_covered'] or [])}; families {', '.join(hs['families_covered'] or [])}.",
              f"- Disjoint from the public library by steps hash: {hs['disjoint_from_public_library']}. The attacks themselves are not in the repo (`hidden-set/COMMITMENT.json`).", ""]
    else:
        L += ["- none committed.", ""]
    L += ["## References", "", "| reference | kind | flaw | matchable | wasm sha256 |", "|---|---|---|---|---|"]
    for k, v in m["references"].items():
        L.append(f"| {k} | {v['kind']} | {v['flaw'] or '-'} | {'yes' if v['matchable'] else 'no'} | `{v['wasm_sha256'][:16]}...` |")
    L.append("")
    return "\n".join(L)


def dump(m):
    return json.dumps(m, indent=1, sort_keys=True) + "\n"


def main(argv):
    m = build()
    js, md = dump(m), render_md(m)
    if argv[:1] == ["--check"]:
        bad = []
        if not OUT_JSON.exists() or OUT_JSON.read_text() != js:
            bad.append(str(OUT_JSON.relative_to(ROOT)))
        if not OUT_MD.exists() or OUT_MD.read_text() != md:
            bad.append(str(OUT_MD.relative_to(ROOT)))
        print("manifest: " + ("up to date" if not bad else "STALE: " + ", ".join(bad) + " (run tools/admission/manifest.py)"))
        return 1 if bad else 0
    OUT_JSON.write_text(js)
    OUT_MD.write_text(md)
    c = m["attacks"]["classes"]
    print(f"manifest: {c['validated']} of {m['attacks']['library_intents']} validated, {c['partially-validated']} partially, {c['unvalidated']} unvalidated -> evidence/MANIFEST.json, evidence/MANIFEST.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
