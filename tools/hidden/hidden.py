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

  python3 -I tools/hidden/hidden.py check-public
      For outsiders (no private files, no network): every public run file in evidence/hidden-set/ names
      the committed set hash (or a set committed earlier and kept in hidden-set/previous/), has one row
      per attack of that set, and its totals add up.

A new set replaces the old one by a new `commit --write`: the old COMMITMENT.json is moved, unchanged,
to hidden-set/previous/<its set sha256>.json, so run files made on the old set still check against
the commitment they name. Only the current set can be run or published.

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
PREVIOUS = ROOT / "hidden-set" / "previous"
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


def tracked_json(root=ROOT):
    """Every tracked .json file in the repo (git ls-files); every .json file on disk if this copy has no git."""
    r = subprocess.run(["git", "ls-files", "-z", "--", "*.json"], cwd=root, capture_output=True)
    if r.returncode == 0:
        return [root / n for n in r.stdout.decode().split("\0") if n]
    return [p for p in root.rglob("*.json") if not {"runs", "target", "node_modules", ".git"} & set(p.relative_to(root).parts)]


def public_hashes(root=ROOT):
    """The steps hash of every attack-shaped file the repo tracks: the library, the intents suite, and every
    hunt proposal under evidence/hunts/**/attacks/ (or anywhere else). Both the hash of the steps as written
    and any meta.steps_sha256 are counted, so a stale meta cannot hide a match."""
    hs = set()
    for p in tracked_json(root):
        try:
            if p.stat().st_size > 1_000_000:
                continue
            d = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if not (isinstance(d, dict) and isinstance(d.get("steps"), list)):
            continue
        try:
            hs.add(V.steps_hash(d["steps"]))
        except Exception:  # not valid steps: nothing to match against
            pass
        m = d.get("meta")
        if isinstance(m, dict) and isinstance(m.get("steps_sha256"), str):
            hs.add(m["steps_sha256"])
    return hs


def public_overlap(docs, root=ROOT):
    """Names of the hidden files whose steps (as written, or as their meta claims) equal any tracked file's."""
    pub = public_hashes(root)
    return [p.name for p, doc in docs if {V.steps_hash(doc["steps"]), doc["meta"]["steps_sha256"]} & pub]


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
    overlap = public_overlap(docs)
    for n in overlap:
        print("IN A TRACKED FILE", n)
    if bad or overlap:
        sys.exit(f"refused: {bad} not validated, {len(overlap)} with the same steps as a file this repo tracks")
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
        if COMMITMENT.exists():
            old = json.loads(COMMITMENT.read_text())
            if old["set_sha256"] == c["set_sha256"]:
                sys.exit("refused: this set is already the committed one (a re-commit would only move created_at)")
            PREVIOUS.mkdir(exist_ok=True)
            keep = PREVIOUS / f"{old['set_sha256']}.json"
            if keep.exists():
                sys.exit(f"refused: {keep.relative_to(ROOT)} already exists")
            keep.write_bytes(COMMITMENT.read_bytes())
            print(f"kept the previous commitment unchanged as {keep.relative_to(ROOT)}")
        COMMITMENT.write_text(json.dumps(c, indent=1) + "\n")
        print(f"wrote {COMMITMENT.relative_to(ROOT)}")


def cmd_run(a):
    import runner
    d = pathlib.Path(a.set).resolve()
    docs = load_set(d)
    c = json.loads(COMMITMENT.read_text())
    for p, doc in docs:  # steps must match their own hash, and each file must still be privately validated
        try:
            V._need(V.steps_hash(doc["steps"]) == doc["meta"]["steps_sha256"], f"{p.name}: steps differ from meta.steps_sha256")
            check_file(p, doc, d.parent)
        except V.Invalid as e:
            sys.exit(f"refused: {e}")
    got = set_sha256(docs)
    if got != c["set_sha256"]:
        sys.exit(f"refused: the set on disk hashes to {got}, the committed set is {c['set_sha256']}")
    overlap = public_overlap(docs)
    if overlap:
        sys.exit(f"refused: {len(overlap)} hidden attack(s) now have the same steps as a file this repo tracks; commit a new set without them")
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


def commitments(root=ROOT):
    """{set sha256: commitment} for the current set and every earlier one kept in hidden-set/previous/."""
    cur = json.loads((root / "hidden-set" / "COMMITMENT.json").read_text())
    out = {cur["set_sha256"]: cur}
    prev = root / "hidden-set" / "previous"
    for f in sorted(prev.glob("*.json")) if prev.is_dir() else []:
        old = json.loads(f.read_text())
        if f.stem != old.get("set_sha256") or old["set_sha256"] == cur["set_sha256"]:
            raise SystemExit(f"{f.relative_to(root)}: file name is not its set_sha256, or it repeats the current set")
        out[old["set_sha256"]] = old
    return cur, out


def order_problems(p, root=ROOT):
    """The run must come after its commitment, judged only by git parent order (commit dates can be set by
    anyone, so they are not used): the run's arena_commit is an ancestor of HEAD, the tree was clean, and
    hidden-set/COMMITMENT.json AT that commit already names this run's set. This trusts git history,
    which whoever controls the repo can rewrite before publishing; it does not prove a wall-clock time."""
    probs = []
    c = p.get("arena_commit")
    if not (isinstance(c, str) and len(c) == 40):
        return ["no arena_commit"]
    if p.get("arena_tree_clean") is not True:
        probs.append("run made on a dirty tree")
    git = lambda *a: subprocess.run(["git", *a], cwd=root, capture_output=True, text=True)
    if git("cat-file", "-e", f"{c}^{{commit}}").returncode != 0:
        return probs + [f"arena_commit {c[:12]} is not in this repository's history (a copy without git history cannot check the order)"]
    if git("merge-base", "--is-ancestor", c, "HEAD").returncode != 0:
        return probs + [f"arena_commit {c[:12]} is not an ancestor of HEAD"]
    r = git("show", f"{c}:hidden-set/COMMITMENT.json")
    try:
        named = json.loads(r.stdout).get("set_sha256") if r.returncode == 0 else None
    except ValueError:
        named = None
    if named != p.get("set_sha256"):
        probs.append(f"at arena_commit {c[:12]} hidden-set/COMMITMENT.json does not name this set (commitment not committed before the run)")
    return probs


def cmd_check_public(a, root=ROOT):
    cur, known = commitments(root)
    files = sorted((root / "evidence" / "hidden-set").glob("*.json"))
    bad = 0
    per_set = {}
    for f in files:
        p = json.loads(f.read_text())
        rows = p["rows"]
        probs = []
        c = known.get(p.get("set_sha256"))
        if c is None:
            probs.append("names a set that was never committed")
            c = cur
        per_set[c["set_sha256"]] = per_set.get(c["set_sha256"], 0) + 1
        if len(rows) != c["attack_count"] or [r["id"] for r in rows] != [f"h-{i:02d}" for i in range(1, c["attack_count"] + 1)]:
            probs.append("rows do not match the committed count")
        for k in ("held", "broke", "inapplicable"):
            if p[k] != sum(r["verdict"] == k for r in rows):
                probs.append(f"{k} total wrong")
        if p["beyond_policy"] != sum(r["beyond_policy"] for r in rows) or any(r["verdict"] != "broke" and r["beyond_policy"] for r in rows):
            probs.append("beyond-policy total wrong")
        if sorted({r["family"] for r in rows}) != c["families_covered"]:
            probs.append("families differ from the commitment")
        probs += order_problems(p, root)
        bad += bool(probs)
        print(f"{'ok ' if not probs else 'BAD'} {f.relative_to(root)}: {p['guard_reference']} held {p['held']} broke {p['broke']} inapplicable {p['inapplicable']}" + (f" ({'; '.join(probs)})" if probs else ""))
    sets = "; ".join(f"{n} on {'current' if h == cur['set_sha256'] else 'earlier'} set {h[:16]}... ({known[h]['attack_count']} attacks)" for h, n in sorted(per_set.items(), key=lambda x: x[0] != cur["set_sha256"]))
    print(f"hidden-set public files: {len(files) - bad} of {len(files)} consistent with the set each names ({sets})")
    return 1 if bad or not files else 0


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
    sub.add_parser("check-public")
    a = ap.parse_args(argv)
    return {"commit": cmd_commit, "run": cmd_run, "check-public": cmd_check_public}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
