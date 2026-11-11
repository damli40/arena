#!/usr/bin/env python3
"""Hidden test set: attacks kept OUT of this repo, committed here by hash only, run by Arena's operator.

Why. A guard author can tune a guard to the public library. A hidden set they never saw cannot be
tuned to. The repo holds only hidden-set/COMMITMENT.json (the set's hash, size, families), committed
before any run, so a result that names the hash shows the set was fixed before the run.

  python3 -I tools/hidden/hidden.py commit --set <private dir> [--write]
      Check every file: valid attack, privately admitted as `validated` by tools/admission/admit.py
      (its meta.admission re-judged from the stored runs in <private dir>/..), not in the public
      library (steps hash). Print the commitment; --write writes hidden-set/COMMITMENT.json.
  python3 -I tools/hidden/hidden.py run --set <private dir> --reference <name> --private-out <dir> [--public-out evidence/hidden-set]
      Refuse unless the set's hash equals the committed one. Run every file once against one reference
      guard (tools/admission/references.json, pinned bytes) on a fresh local sandbox each, through
      tools/hunter/runner.py. Write the full results to --private-out (they name the attacks) and a
      public summary that does not: rows h-01..h-N (sorted by leaf hash), family, verdict, amount.

What it proves, and what it does not: see the `limits` field written into every public file.
Local sandbox only. Nothing here touches a network.
"""
import argparse, datetime, hashlib, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "hunter"))
sys.path.insert(0, str(ROOT / "tools" / "admission"))
import validate as V  # noqa: E402
import admit  # noqa: E402

COMMITMENT = ROOT / "hidden-set" / "COMMITMENT.json"
LIMITS = ("Proves: the set existed and was fixed when COMMITMENT.json was committed, and every hidden attack was admitted "
          "against a matched known-bad reference before commitment. Does not prove: that the operator ran it honestly "
          "(no hardware attestation; one key publishes), that the hidden attacks find flaws outside their public twins' "
          "families, or anything about a guard outside the local sandbox. Outsiders cannot re-run a hidden attack until it is revealed.")
POLICY = ("Revealed file by file (with its private admission evidence) when the set has been run against 5 distinct guard "
          "code hashes, or 30 days after commitment, whichever comes first; a new set is committed before the old one is "
          "revealed; never revealed early because of a result.")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def family(meta_id):
    # private ids are hidden-NN-<family>
    parts = meta_id.split("-", 2)
    return parts[2] if len(parts) == 3 and parts[0] == "hidden" else "unknown"


def is_intents(doc):
    return any((st.get("call") or st.get("view") or {}).get("target") == "intents" for st in doc["steps"])


def leaf(doc):
    """What binds one file: what it does (steps) and what it expects (spec). Not its name."""
    return f"{doc['meta']['steps_sha256']}:{V.spec_sha256(doc['meta']['spec'])}"


def load_set(d):
    files = sorted(pathlib.Path(d).glob("*.json"))
    docs = []
    for p in files:
        doc = json.loads(p.read_text())
        docs.append((p, doc))
    return docs


def set_sha256(docs):
    return sha("\n".join(sorted(leaf(doc) for _, doc in docs)).encode())


def check_file(p, doc, private_root):
    """Raises V.Invalid unless the file is a valid attack, privately validated by the gate."""
    meta = doc.get("meta", {})
    V.check_attack({**doc, "meta": {k: v for k, v in meta.items() if k != "admission"}}, intents_suite=is_intents(doc))
    V._need("admission" in meta, f"{p.name}: never run through the gate")
    V.check_admission(meta, doc["steps"], root=private_root)
    V._need(meta["admission"]["class"] == "validated", f"{p.name}: gate class {meta['admission']['class']}, not validated")


def public_hashes():
    import catalog
    attacks, _ = catalog.load()
    hs = {a["meta"]["steps_sha256"] for a in attacks}
    for p in sorted((ROOT / "sequences-intents").glob("*.json")):
        hs.add(json.loads(p.read_text())["meta"]["steps_sha256"])
    return hs


def cmd_commit(a):
    d = pathlib.Path(a.set).resolve()
    if d.is_relative_to(ROOT):
        sys.exit("the hidden set must live outside the repo")
    private_root = d.parent
    docs = load_set(d)
    if not docs:
        sys.exit("empty set")
    bad = 0
    for p, doc in docs:
        try:
            check_file(p, doc, private_root)
        except V.Invalid as e:
            bad += 1
            print("NOT ADMITTED", e)
    pub = public_hashes()
    overlap = [p.name for p, doc in docs if doc["meta"]["steps_sha256"] in pub]
    for n in overlap:
        print("IN PUBLIC LIBRARY", n)
    if bad or overlap:
        sys.exit(f"refused: {bad} not validated, {len(overlap)} also in the public library")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    c = {"about": "Hidden test set commitment. The attacks are NOT in this repo. Written by tools/hidden/hidden.py commit.",
         "set_sha256": set_sha256(docs),
         "set_sha256_definition": "sha256 of the sorted lines '<meta.steps_sha256>:<sha256 of meta.spec as compact sorted JSON>', one per file, joined by newline",
         "attack_count": len(docs),
         "capabilities_covered": sorted({c for _, doc in docs for c in doc["meta"]["spec"]["capabilities"]}),
         "families_covered": sorted({family(doc["meta"]["id"]) for _, doc in docs}),
         "per_family": {f: sum(1 for _, doc in docs if family(doc["meta"]["id"]) == f) for f in sorted({family(doc["meta"]["id"]) for _, doc in docs})},
         "admission": "every file privately admitted as validated by tools/admission/admit.py against the same closed reference list as the public library",
         "disjoint_from_public_library": True,
         "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "arena_commit_at_creation": head,
         "reveal_policy": POLICY, "limits": LIMITS}
    print(json.dumps(c, indent=1))
    if a.write:
        COMMITMENT.parent.mkdir(exist_ok=True)
        COMMITMENT.write_text(json.dumps(c, indent=1) + "\n")
        print(f"wrote {COMMITMENT.relative_to(ROOT)}")


def cmd_run(a):
    import runner
    d = pathlib.Path(a.set).resolve()
    docs = load_set(d)
    c = json.loads(COMMITMENT.read_text())
    got = set_sha256(docs)
    if got != c["set_sha256"]:
        sys.exit(f"refused: the set on disk hashes to {got}, the committed set is {c['set_sha256']}")
    refs = V.load_references()
    if a.reference not in refs:
        sys.exit(f"unknown reference {a.reference} (closed list: tools/admission/references.json)")
    ref = refs[a.reference]
    admit.check_reference_bytes([a.reference], refs)
    priv = pathlib.Path(a.private_out).resolve()
    if priv.is_relative_to(ROOT):
        sys.exit("--private-out must be outside the repo (its files name the hidden attacks)")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = priv / f"{stamp}-{admit.ref_slug(a.reference)}"
    run_dir.mkdir(parents=True)
    head, clean = admit.git_head()
    guard = {"id": admit.ref_slug(a.reference), "harness_flags": ref["harness_flags"]}
    order = sorted(docs, key=lambda x: leaf(x[1]))
    rows, private_rows = [], []
    for n, (p, doc) in enumerate(order, 1):
        hid = f"h-{n:02d}"
        if is_intents(doc) and not ref.get("intents_suite"):
            rows.append({"id": hid, "family": family(doc["meta"]["id"]), "verdict": "inapplicable", "beyond_policy": 0, "why": "needs a guard that pays into NEAR Intents"})
            private_rows.append({**rows[-1], "file": p.name})
            continue
        cell = runner.run_one(p, guard, run_dir, f"hidden set {c['set_sha256'][:16]} {hid} git {head}")
        verdict = {"held": "held", "broke": "broke"}.get(cell["status"], "could-not-finish")
        rows.append({"id": hid, "family": family(doc["meta"]["id"]), "verdict": verdict,
                     "beyond_policy": cell.get("unauthorised", 0) if verdict == "broke" else 0,
                     "why": "" if verdict != "could-not-finish" else cell["status"]})
        private_rows.append({**rows[-1], "file": p.name, "cell": cell})
        print(f"  {hid} {family(doc['meta']['id']):<24} {verdict:<16} {rows[-1]['beyond_policy']}", flush=True)
    admit.check_reference_bytes([a.reference], refs)
    harness = ROOT / "harness" / "target" / "release" / "arena-harness"
    pub = {"suite": "hidden-set", "set_sha256": c["set_sha256"], "attack_count": len(rows),
           "guard_reference": a.reference, "guard_wasm_sha256": ref["wasm_sha256"],
           "arena_commit": head, "arena_tree_clean": clean, "harness_sha256": admit.sha256_file(harness) if harness.is_file() else None,
           "ran_at": stamp, "rows": rows,
           "held": sum(r["verdict"] == "held" for r in rows), "broke": sum(r["verdict"] == "broke" for r in rows),
           "inapplicable": sum(r["verdict"] == "inapplicable" for r in rows), "could_not_finish": sum(r["verdict"] == "could-not-finish" for r in rows),
           "beyond_policy": sum(r["beyond_policy"] for r in rows), "limits": LIMITS}
    (run_dir / "private-summary.json").write_text(json.dumps({**pub, "rows": private_rows}, indent=1) + "\n")
    out = ROOT / a.public_out
    out.mkdir(parents=True, exist_ok=True)
    base = out / f"{stamp}-{admit.ref_slug(a.reference)}"
    base.with_suffix(".json").write_text(json.dumps(pub, indent=1) + "\n")
    L = [f"# Hidden set run: {a.reference}", "",
         f"Set `{c['set_sha256']}` ({len(rows)} attacks, committed in `hidden-set/COMMITMENT.json`), guard wasm `{ref['wasm_sha256']}`, "
         f"Arena {head} (tree {'clean' if clean else 'NOT clean'}), {stamp}. Local sandbox, one run per attack.", "",
         f"**held {pub['held']}, broke {pub['broke']}, inapplicable {pub['inapplicable']}, could not finish {pub['could_not_finish']}; beyond policy {pub['beyond_policy']}.**", "",
         "| id | family | verdict | beyond policy |", "|---|---|---|---|"]
    L += [f"| {r['id']} | {r['family']} | {r['verdict']} | {r['beyond_policy']} |" for r in rows]
    L += ["", LIMITS, ""]
    base.with_suffix(".md").write_text("\n".join(L))
    print(f"public: {base.with_suffix('.json').relative_to(ROOT)} (+ .md); private: {run_dir}")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("commit")
    c.add_argument("--set", required=True)
    c.add_argument("--write", action="store_true")
    r = sub.add_parser("run")
    r.add_argument("--set", required=True)
    r.add_argument("--reference", required=True)
    r.add_argument("--private-out", required=True)
    r.add_argument("--public-out", default="evidence/hidden-set")
    a = ap.parse_args(argv)
    return {"commit": cmd_commit, "run": cmd_run}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
