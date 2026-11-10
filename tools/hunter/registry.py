"""guards/registry.json: load, check, fingerprint.

  python3 -I tools/hunter/registry.py      check the registry and print each guard's fingerprint

Refuses: any wasm under targets/entrant-* (never attacked), any path outside the repo, harness
flags outside the two allowed forms, a non-identity method mapping (not supported yet), and a
guard whose bytes (frozen-wasm) or source (built-from-source) no longer match.
"""
import hashlib, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "guards" / "registry.json"
BUILTIN_TARGETS = {"vault", "control", "native-control", "native-fixed", "guard-fixed", "guard-vulnerable"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
GUARD_KEYS = {"id", "name", "role", "owner", "opt_in", "policy", "interface", "scoring", "wasm", "fingerprint",
              "harness_flags", "methods", "runnable", "not_runnable_reason"}
ROLES = {"subject", "positive-control", "negative-control"}
INTERFACES = {"vault-a", "contracts-guard"}
METHOD_ROLES = {"pay", "get_invoice"}


class RegistryError(ValueError):
    pass


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def _inside_repo(rel):
    p = (ROOT / rel).resolve()
    if ROOT.resolve() not in p.parents:
        raise RegistryError(f"{rel}: outside the repo")
    if any(part.startswith("entrant-") for part in p.relative_to(ROOT.resolve()).parts):
        raise RegistryError(f"{rel}: targets/entrant-* is never attacked by the hunter")
    return p


def check_guard(g):
    def need(c, why):
        if not c:
            raise RegistryError(f"guard {g.get('id', '?')}: {why}")
    need(isinstance(g, dict), "must be an object")
    need(not (set(g) - GUARD_KEYS), f"unknown keys {sorted(set(g) - GUARD_KEYS)}")
    for k in GUARD_KEYS - {"not_runnable_reason"}:
        need(k in g, f"missing {k}")
    need(ID_RE.match(g["id"]) is not None, "bad id")
    need(not g["id"].startswith("entrant"), "entrant-* guards are never in the registry")
    need(g["role"] in ROLES, f"role must be one of {sorted(ROLES)}")
    need(g["interface"] in INTERFACES, f"interface must be one of {sorted(INTERFACES)}")
    need(g["scoring"] in ("token", "native"), "scoring must be token or native")
    need(isinstance(g["opt_in"], str) and len(g["opt_in"].strip()) >= 10, "opt_in line missing")
    _inside_repo(g["wasm"])
    f = g["harness_flags"]
    need(isinstance(f, list) and all(isinstance(x, str) for x in f), "harness_flags must be a list of strings")
    if f[:1] == ["--target"]:
        need(len(f) == 2 and f[1] in BUILTIN_TARGETS, f"--target must be one of {sorted(BUILTIN_TARGETS)}")
    elif f[:1] == ["--wasm"]:
        need(len(f) in (4, 5) and f[2] == "--wasm-label" and f[3] == g["id"] and (len(f) == 4 or f[4] == "--native"),
             "--wasm form is [--wasm, <path>, --wasm-label, <id>] plus optional --native")
        need(f[1] == g["wasm"], "--wasm path must equal the wasm field")
        need((len(f) == 5) == (g["scoring"] == "native"), "--native must match scoring")
        need(g["interface"] == "vault-a", "--wasm guards must implement targets/vault-a/INTERFACE.md")
    else:
        raise RegistryError(f"guard {g['id']}: harness_flags must start with --target or --wasm")
    need(isinstance(g["methods"], dict) and all(k in METHOD_ROLES for k in g["methods"]), f"methods keys must be among {sorted(METHOD_ROLES)}")
    need(all(g["methods"].get(k, k) == k for k in METHOD_ROLES),
         "method renaming is not supported by the harness yet; wrap the guard in an adapter contract (docs/REGISTER-A-GUARD.md)")
    if not g["runnable"]:
        need(isinstance(g.get("not_runnable_reason"), str) and g["not_runnable_reason"], "not_runnable_reason required when runnable is false")
    fp = g["fingerprint"]
    need(isinstance(fp, dict) and fp.get("kind") in ("frozen-wasm", "built-from-source"), "fingerprint.kind must be frozen-wasm or built-from-source")


def fingerprint(g):
    """Check the guard's bytes/source against the registry. Returns {wasm_sha256, ok, why}."""
    fp = g["fingerprint"]
    wasm = _inside_repo(g["wasm"])
    if not wasm.exists():
        return {"wasm_sha256": None, "ok": False, "why": f"{g['wasm']} missing" + (f" (build: {fp.get('build')})" if fp.get("build") else "")}
    actual = sha256(wasm)
    if fp["kind"] == "frozen-wasm":
        ok = actual == fp["wasm_sha256"]
        return {"wasm_sha256": actual, "ok": ok, "why": "" if ok else f"wasm sha256 {actual} != registry {fp['wasm_sha256']}"}
    for rel, want in fp["source_sha256"].items():
        got = sha256(_inside_repo(rel))
        if got != want:
            return {"wasm_sha256": actual, "ok": False, "why": f"{rel} sha256 {got} != registry {want} (source changed; re-register)"}
    return {"wasm_sha256": actual, "ok": True, "why": "source matches; wasm built from it"}


def load(path=REGISTRY):
    d = json.loads(pathlib.Path(path).read_text())
    if d.get("version") != 1 or not isinstance(d.get("guards"), list):
        raise RegistryError("registry must be {version: 1, guards: [...]}")
    ids = set()
    for g in d["guards"]:
        check_guard(g)
        if g["id"] in ids:
            raise RegistryError(f"duplicate guard id {g['id']}")
        ids.add(g["id"])
    return d["guards"]


def main():
    try:
        guards = load()
    except (RegistryError, json.JSONDecodeError, OSError) as e:
        print(f"REGISTRY INVALID: {e}")
        return 1
    bad = 0
    for g in guards:
        fp = fingerprint(g)
        state = "runnable" if g["runnable"] else "not runnable"
        print(f"{g['id']:<18} {g['role']:<17} {state:<13} fingerprint {'ok ' if fp['ok'] else 'BAD'} {fp['wasm_sha256']}  {fp['why']}")
        bad += 0 if fp["ok"] else 1
    print(f"registry: {len(guards)} guards, {bad} fingerprint problems")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
