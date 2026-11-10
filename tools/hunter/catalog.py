"""The attack library: every attack the bench knows, in one list, with dedupe.

Sources:
- sequences-scripted/, sequences-ai/, sequences-bypass/, sequences-paper/  (files with a meta block)
- tools/injection/scenarios.json  (prompt-injection scenarios; turned into the pays a fully
  fooled agent makes, with metadata derived from the scenario; scenarios.json is not edited)

"Same steps means the same attack": two attacks are duplicates when their canonical steps
(validate.canonical_steps: views dropped, defaults filled in) hash the same.
"""
import json, pathlib
import validate as V

ROOT = pathlib.Path(__file__).resolve().parents[2]
SEQ_DIRS = ("sequences-scripted", "sequences-ai", "sequences-bypass", "sequences-paper")
SCENARIOS = ROOT / "tools" / "injection" / "scenarios.json"


def _injection_attacks():
    out = []
    if not SCENARIOS.exists():
        return out
    d = json.loads(SCENARIOS.read_text())
    for s in d.get("scenarios", []):
        steps = V.injection_steps(s["injected_pays"])
        email = s.get("email") or json.dumps(s.get("memo_override", {}))
        meta = {
            "id": f"injection-{s['id']}",
            "title": s["label"][:120],
            "source": "hand",
            "kind": "injection",
            "breaks": "Prompt injection: attacker text makes the agent ask for pays the owner never meant "
                      f"({', '.join(s['injected_pays'])}). Run as the pays a fully fooled agent makes.",
            "expected_safe_result": "the guard refuses whatever its policy forbids; pays its policy allows still go through (that is intent leak, not a guard failure)",
            "added": "2026-11-09",
            "author": "hand-written scenario (tools/injection/scenarios.json)",
            "steps_sha256": V.steps_hash(steps),
            "injection": {"email": email[:V.MAX_EMAIL], "injected_pays": s["injected_pays"], "scenario_id": s["id"]},
        }
        out.append({"name": f"injection-{s['id']}", "steps": steps, "meta": meta,
                    "path": f"tools/injection/scenarios.json#{s['id']}"})
    return out


def load(root=ROOT):
    """Return (attacks, problems). Each attack: {name, steps, meta, path}. Invalid files are
    reported in problems and left out, never silently fixed."""
    attacks, problems = [], []
    for d in SEQ_DIRS:
        for p in sorted((root / d).glob("*.json")):
            if p.name.endswith(".result.json"):
                continue
            err = V.validate_path(p)
            if err:
                problems.append(err)
                continue
            doc = json.loads(p.read_text())
            attacks.append({**doc, "path": str(p.relative_to(root))})
    if root == ROOT:
        attacks += _injection_attacks()
    ids = {}
    for a in attacks:
        if a["meta"]["id"] in ids:
            problems.append(f"duplicate meta.id {a['meta']['id']} in {a['path']} and {ids[a['meta']['id']]}")
        ids[a["meta"]["id"]] = a["path"]
    return attacks, problems


def index_by_hash(attacks):
    """steps hash -> first attack with those steps."""
    idx = {}
    for a in attacks:
        idx.setdefault(V.steps_hash(a["steps"]), a)
    return idx


def unique(attacks):
    """Attacks with distinct steps, plus the list of (duplicate, original) pairs."""
    seen, out, dups = {}, [], []
    for a in attacks:
        h = V.steps_hash(a["steps"])
        if h in seen:
            dups.append((a, seen[h]))
        else:
            seen[h] = a
            out.append(a)
    return out, dups
