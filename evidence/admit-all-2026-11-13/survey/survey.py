"""Survey: run attacks (and their sequential twins) once each on chosen guards, serially. Usage: survey.py <repo> <outdir> <attack.json>..."""
import json, sys, pathlib, copy
repo = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2]); sys.path.insert(0, str(repo / "tools/hunter"))
import runner
import os
def flags(g):
    if g == "vault-a": return ["--target", "vault"]
    if g == "guard-vulnerable": return ["--target", "guard-vulnerable"]
    if g == "guard-fixed": return ["--target", "guard-fixed"]
    return ["--wasm", f"mutants/{g}/vault_a.wasm", "--wasm-label", g]
G = {g: flags(g) for g in os.environ.get("GUARDS", "vault-a,race-m3,M3").split(",")}
for a in sys.argv[3:]:
    doc = json.loads(pathlib.Path(a).read_text()); aid = doc["meta"]["id"]
    seq = copy.deepcopy(doc); seq["meta"].pop("spec", None); seq["meta"].pop("admission", None)
    steps = []
    for st in doc["steps"]:
        if "race" in st:
            steps += [{"call": (leg["call"] if "call" in leg else leg)} for leg in st["race"]]
        else:
            steps.append(st)
    seq["steps"] = steps; seq["meta"]["id"] = aid + "-seqtwin"
    seq["meta"].pop("steps_sha256", None)
    d = out / aid; d.mkdir(parents=True, exist_ok=True)
    tw = d / f"{aid}-seqtwin.json"; tw.write_text(json.dumps(seq, indent=1))
    for variant, path in (("race", pathlib.Path(a).resolve()), ("sequential", tw)):
        for g, flags in G.items():
            c = runner.run_one(path, {"id": g, "harness_flags": flags}, d, "survey admit-all")
            r = json.loads(pathlib.Path(repo / c["result_json"] if not pathlib.Path(c["result_json"]).is_absolute() else c["result_json"]).read_text()) if c["status"] != "error" else {}
            sc = r.get("score", {})
            outs = [s.get("outcome") for s in r.get("steps", []) if s.get("kind") in ("call", "race-call")]
            print(f"{aid[:40]:<40} {variant:<10} {g:<8} {c['status']:<7} unauth={sc.get('unauthorised_payout')} above_cap={sc.get('above_cap')} outcomes={outs} {c.get('why','')[:120]}", flush=True)
