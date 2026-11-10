#!/usr/bin/env python3
"""`arena check`: run the whole Arena attack library against YOUR guard, on a local sandbox.

  ./arena check <guard.wasm> [--config guard.json] [--mapping mapping.json] [--out arena-report]
                [--fail-on beyond-policy|against-intent|never] [--jobs 4] [--no-muse] [--label NAME]

What it does, in order:
 1. reads the method names your wasm exports (no wasm code runs here);
 2. loads your config and mapping (data only; see guard_config.py), or asks Muse to PROPOSE a
    mapping when your method names differ and you gave none (checked before use);
 3. preflight: one honest payment on a fresh local sandbox. If that does not work, it stops and
    says what to fix, instead of reporting "held";
 4. every attack in the library, each on its own fresh local sandbox, through the existing runner
    (tools/hunter/runner.py) and scorer (harness/src/scorer.rs);
 5. writes the report: report.html, report.json, badge.svg, shields.json, summary.md, the
    resolved config, and each attempt's log and result.

Exit codes: 0 = ran, under the --fail-on line; 1 = ran, over the --fail-on line; 2 = could not
finish (config, setup or preflight problem, or an attempt errored). The report is written in
every case.
"""
import argparse, datetime, hashlib, importlib.util, json, os, pathlib, shutil, subprocess, sys, time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "hunter"))
sys.path.insert(0, str(HERE))
import catalog, runner, validate as V  # noqa: E402  (tools/hunter, imported, never edited)
import guard_config as C, muse_map, report as R, explain, wasm_exports  # noqa: E402

CONTROL_ID = "scripted-01-control-pay-valid"
TOKEN_WASM = ROOT / "contracts/target/wasm32-unknown-unknown/release/test_token.wasm"
FAIL_ON = ("beyond-policy", "against-intent", "never")


def _score_intent():
    spec = importlib.util.spec_from_file_location("arena_injection_run", ROOT / "tools/injection/run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.score_intent


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def arena_version():
    head = git("rev-parse", "HEAD") or "unknown (not a git checkout)"
    dirty = git("status", "--porcelain", "--untracked-files=no")
    return {"commit": head, "dirty": bool(dirty), "dirty_files": len(dirty.splitlines()) if dirty else 0}


def ensure_built(log):
    """Build the harness and the test token if missing or older than their source."""
    src_newest = max(p.stat().st_mtime for p in (ROOT / "harness/src").glob("*.rs"))
    stale = not runner.HARNESS.exists() or runner.HARNESS.stat().st_mtime < src_newest
    steps = []
    if not TOKEN_WASM.exists():
        steps.append(("test token", ["cargo", "build", "--release", "--target", "wasm32-unknown-unknown", "-p", "test-token"], ROOT / "contracts"))
    if stale:
        steps.append(("harness", ["cargo", "build", "--release"], ROOT / "harness"))
    for what, cmd, cwd in steps:
        print(f"building the {what} (first run only; a few minutes) ...", flush=True)
        with open(log, "a") as f:
            r = subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)
        if r.returncode != 0:
            raise explain.CheckError(f"Building the {what} failed. Is Rust installed through rustup? The build log is {log}.")


def library():
    attacks, problems = catalog.load()
    uniq, dups = catalog.unique(attacks)
    # Owner intent is written down only for the prompt-injection scenarios ("pay Sam 100,
    # nothing else"). Any attack whose steps equal a scenario's steps carries that intent.
    inj = {V.steps_hash(a["steps"]) for a in attacks if a["meta"].get("kind") == "injection"}
    for a in uniq:
        a["has_intent"] = V.steps_hash(a["steps"]) in inj
    uniq.sort(key=lambda a: (a["meta"]["id"] != CONTROL_ID, a["path"]))
    return uniq, problems, dups


def write_attack_file(a, d):
    p = d / f"{a['meta']['id']}.json"
    p.write_text(json.dumps({"name": a["name"], "steps": a["steps"], "meta": a["meta"]}, indent=1))
    return p


def main(argv=None):
    ap = argparse.ArgumentParser(prog="arena check", description="Run Arena's attack library against your guard on a local NEAR sandbox.")
    ap.add_argument("wasm")
    ap.add_argument("--config")
    ap.add_argument("--mapping")
    ap.add_argument("--out", default="arena-report")
    ap.add_argument("--fail-on", default="beyond-policy", choices=FAIL_ON)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--no-muse", action="store_true", help="never ask Muse for a mapping")
    ap.add_argument("--label", default=None, help="a short name for the guard in logs (default: the wasm file name)")
    ap.add_argument("--only", nargs="*", help=argparse.SUPPRESS)  # attack ids (for debugging; the report says so)
    a = ap.parse_args(argv)

    t0 = time.time()
    started = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = pathlib.Path(a.out).resolve()
    if out.exists():
        shutil.rmtree(out / "runs", ignore_errors=True)
    (out / "runs").mkdir(parents=True, exist_ok=True)
    rep = {"tool": "arena check", "started_utc": started, "arena": arena_version(), "fail_on": a.fail_on,
           "status": "not-run", "errors": [], "command": " ".join(["./arena", "check", *(argv if argv is not None else sys.argv[1:])])}

    def finish(code):
        rep["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rep["wall_seconds"] = round(time.time() - t0, 1)
        R.write_all(rep, out)
        print(R.console(rep, out))
        return code

    try:
        wasm = pathlib.Path(a.wasm).resolve()
        if not wasm.is_file():
            raise explain.CheckError(f"{a.wasm}: file not found. Pass the path to your built guard .wasm.")
        data = wasm.read_bytes()
        try:
            methods = wasm_exports.methods(data)
        except wasm_exports.WasmError as e:
            raise explain.CheckError(f"{a.wasm}: {e}. Pass the .wasm your build produced (e.g. target/wasm32-unknown-unknown/release/<name>.wasm).")
        label = (a.label or wasm.stem).lower()
        label = "".join(c if c.isalnum() or c in "-_" else "-" for c in label)[:40] or "guard"
        rep["guard"] = {"wasm": str(wasm), "label": label, "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data), "exported_methods": methods}

        config = C.check_config(C.load_json(a.config, "config")) if a.config else None
        mapping, source = None, "none needed (names match the interface)"
        if a.mapping:
            mapping, source = C.check_mapping(C.load_json(a.mapping, "mapping")), f"--mapping {a.mapping}"
        resolved, problems = C.resolve(config, mapping, methods)
        if problems and not a.mapping and not a.no_muse:
            print("your guard's method names differ from the interface; asking Muse to PROPOSE a mapping (checked before use) ...", flush=True)
            proposal, mlog = muse_map.propose(methods, config or {})
            rep["muse"] = mlog
            if proposal:
                mapping, source = proposal, "Muse proposal (checked against the closed lists and your wasm's exports; review mapping.json)"
                resolved, problems = C.resolve(config, mapping, methods)
            else:
                problems.append(f"Muse could not supply a usable mapping ({mlog['result']}). Write one by hand: see docs/CHECK-YOUR-GUARD.md.")
        rep["config"] = {"file": a.config, "name": (config or {}).get("name"), "policy": (config or {}).get("policy")}
        rep["mapping"] = {"source": source, "renamed": C.renamed_roles(resolved), "shapes": resolved["shapes"],
                          "deposits": resolved["deposits"], "features": resolved["features"], "init": resolved["init"]}
        if mapping:
            (out / "mapping.json").write_text(json.dumps(mapping, indent=2) + "\n")
        if problems:
            raise explain.CheckError("Your guard's methods do not line up with what Arena calls:\n  - " + "\n  - ".join(problems))
        cfg_path = out / "guard-config.resolved.json"
        cfg_path.write_text(json.dumps(resolved, indent=2) + "\n")

        ensure_built(out / "build.log")
        attacks, lib_problems, dups = library()
        if a.only:
            attacks = [x for x in attacks if x["meta"]["id"] in set(a.only) | {CONTROL_ID}]
            rep["only"] = a.only
        rep["library"] = {"attacks": len(attacks), "problems": lib_problems,
                          "duplicates_skipped": [[d["meta"]["id"], o["meta"]["id"]] for d, o in dups]}
        adir = out / "runs" / "attacks"
        adir.mkdir(parents=True, exist_ok=True)
        guard = {"id": label, "harness_flags": ["--wasm", str(wasm), "--wasm-label", label, "--guard-config", str(cfg_path)]}
        meta_line = f"arena check {rep['guard']['sha256'][:16]} arena={rep['arena']['commit'][:12]} {started}"

        # Preflight: one honest payment. A guard that cannot pay honestly would "hold" every attack.
        control = next(x for x in attacks if x["meta"]["id"] == CONTROL_ID)
        print("preflight: one honest payment on a fresh local sandbox ...", flush=True)
        cell = runner.run_one(write_attack_file(control, adir), guard, out / "runs", meta_line)
        why = explain.preflight(cell, out, resolved)
        if why:
            rep["preflight"] = {"ok": False, "cell": cell}
            raise explain.CheckError(why)
        rep["preflight"] = {"ok": True, "seconds": cell["seconds"]}
        print(f"preflight ok ({cell['seconds']} s). Running {len(attacks)} attacks, {a.jobs} at a time ...", flush=True)

        rest = [(write_attack_file(x, adir), x["meta"]["id"], None) for x in attacks if x["meta"]["id"] != CONTROL_ID]
        matrix = runner.run_matrix(rest, [guard], out / "runs", meta_line, jobs=a.jobs)
        matrix[CONTROL_ID] = {label: cell}
        score_intent = _score_intent()
        intended = json.loads((ROOT / "tools/injection/scenarios.json").read_text())["intended"]
        rows = []
        for x in attacks:
            c = matrix[x["meta"]["id"]][label]
            row = {"id": x["meta"]["id"], "title": x["meta"]["title"], "source": x["meta"]["source"],
                   "kind": x["meta"]["kind"], "breaks": x["meta"]["breaks"], "path": x["path"],
                   "status": c["status"], "why": c.get("why", ""), "beyond_policy": c.get("unauthorised", 0),
                   "honest_settled": c.get("honest_settled"), "should_pay": c.get("should_pay"),
                   "seconds": c.get("seconds"), "log": _rel(c.get("log"), out), "result_json": _rel(c.get("result_json"), out),
                   "has_intent": x["has_intent"], "against_intent": None}
            rj = ROOT / c["result_json"] if c.get("result_json") and not pathlib.Path(c["result_json"]).is_absolute() else pathlib.Path(c.get("result_json") or "/nonexistent")
            if rj.exists():
                r = json.loads(rj.read_text())
                row["steps"] = r.get("steps", [])
                row["final"] = r.get("final", {})
                if x["has_intent"] and c["status"] in ("held", "broke"):
                    received = {e["receiver"]: int(e["received"]) for e in r["final"]["received"]}
                    si = score_intent(received, intended)
                    row["against_intent"] = si["wrongful_total"]
                    row["intent_detail"] = {"wrongful": si["wrongful"], "missed": si["missed"]}
            rows.append(row)
        rep["attacks"] = rows
        rep["intended"] = intended
        bad = [r for r in rows if r["status"] not in ("held", "broke")]
        rep["totals"] = {
            "attacks": len(rows),
            "ran": len(rows) - len(bad),
            "broke": sum(r["status"] == "broke" for r in rows),
            "held": sum(r["status"] == "held" for r in rows),
            "errors": len(bad),
            "beyond_policy": sum(r["beyond_policy"] or 0 for r in rows if r["status"] in ("held", "broke")),
            "against_intent": sum(r["against_intent"] or 0 for r in rows),
            "intent_attacks": sum(r["against_intent"] is not None for r in rows),
            # by who wrote the attack: "hand" = the 5 scenarios in tools/injection/scenarios.json
            # (the README's 450 on vault-a), "paper"/"news" = written by Muse from a paper or news item.
            "against_intent_by_source": {src: sum(r["against_intent"] or 0 for r in rows if r["source"] == src and r["against_intent"] is not None)
                                         for src in sorted({r["source"] for r in rows if r["against_intent"] is not None})},
        }
        rep["status"] = "incomplete" if bad else ("broke" if rep["totals"]["broke"] else "held")
        for r in bad:
            rep["errors"].append(f"{r['id']}: {explain.attempt_error(r['why'], out / 'runs' / pathlib.Path(r['log'] or 'x').name)}")
    except (explain.CheckError, C.ConfigError) as e:
        rep["status"] = "not-run"
        rep["errors"].append(str(e))
        return finish(2)

    t = rep["totals"]
    if rep["status"] == "incomplete":
        return finish(2)
    over = (a.fail_on == "beyond-policy" and t["beyond_policy"] > 0) or \
           (a.fail_on == "against-intent" and (t["beyond_policy"] > 0 or t["against_intent"] > 0))
    rep["fail_on_tripped"] = bool(over)
    return finish(1 if over else 0)


def _rel(p, out):
    """Path of a run file relative to the report folder (the report links to it)."""
    if not p:
        return None
    q = pathlib.Path(p)
    q = q if q.is_absolute() else ROOT / q
    try:
        return str(q.resolve().relative_to(out))
    except ValueError:
        return str(q)


if __name__ == "__main__":
    sys.exit(main())
