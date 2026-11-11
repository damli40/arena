"""guards/registry.json: load, check, fingerprint.

  python3 -I tools/hunter/registry.py      check the registry and print each guard's fingerprint

Refuses: any wasm under targets/entrant-* (never attacked), any path outside the repo, harness
flags outside the two allowed forms, a non-identity method mapping (not supported yet), and a
guard whose bytes (frozen-wasm) or source (built-from-source) no longer match.

Outside guards (added 2026-11-11). guards/registry.json holds Arena's own local fixtures. A guard
from outside opts in ON CHAIN instead: its account (or its parent account) signs `opt_in` on the
Arena contract on NEAR testnet, naming the guard's code hash. `outside_guards()` reads those opt-ins
and, at test time, checks the guard's CURRENT code against the opted-in hash. Rules:
  - any RPC error while listing opt-ins -> no outside guards at all (never assumed opted in);
  - any RPC error for one guard, an expired opt-in, a changed code hash, or fetched bytes that do
    not hash to the opted-in value -> that guard is refused, with one plain log line;
  - code that matches one of Arena's local guards, or a targets/entrant-* guard, is not added.

  python3 -I tools/hunter/registry.py --outside     also list the on-chain opt-ins (reads testnet)
"""
import base64, hashlib, json, pathlib, re, sys, time, urllib.error, urllib.request

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


# ---------------------------------------------------------------- outside guards, from chain

OPT_IN_CONTRACT = "receipts.dev-20261109195231-98743803426969.testnet"
RPC_URL = "https://rpc.testnet.fastnear.com"
OUTSIDE_DIR = ROOT / "guards" / "outside"   # fetched wasm lands here (git-ignored)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
PAGE = 100


class ChainError(Exception):
    pass


def base58_to_hex(s):
    """NEAR's view_account code_hash is base58 of the sha256. Returns 64 lowercase hex or raises ChainError."""
    if not isinstance(s, str) or not s or any(c not in B58 for c in s):
        raise ChainError(f"code_hash is not base58: {s!r}")
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    lead = len(s) - len(s.lstrip("1"))
    h = ("00" * lead) + (format(n, "x") if n else "")
    h = ("0" + h) if len(h) % 2 else h
    if len(h) != 64:
        raise ChainError(f"code_hash is {len(h) // 2} bytes, not 32")
    return h


def rpc_query(params, url=RPC_URL, timeout=15):
    """One NEAR JSON-RPC `query`. Any failure (network, HTTP, JSON, RPC error) raises ChainError."""
    body = json.dumps({"jsonrpc": "2.0", "id": "arena-registry", "method": "query", "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ChainError(f"RPC {url}: {e}") from e
    if not isinstance(d, dict) or "error" in d or not isinstance(d.get("result"), dict):
        raise ChainError(f"RPC error: {str(d.get('error') if isinstance(d, dict) else d)[:300]}")
    if "error" in d["result"]:
        raise ChainError(f"RPC error: {str(d['result']['error'])[:300]}")
    return d["result"]


def view_fn(rpc, account, method, args):
    r = rpc({"request_type": "call_function", "finality": "final", "account_id": account, "method_name": method,
             "args_base64": base64.b64encode(json.dumps(args).encode()).decode()})
    try:
        return json.loads(bytes(r["result"]).decode())
    except (KeyError, TypeError, ValueError) as e:
        raise ChainError(f"{method}: result is not JSON ({e})") from e


def chain_opt_ins(rpc=rpc_query, contract=OPT_IN_CONTRACT):
    """Every opt-in on the contract (all pages). Raises ChainError on any problem, including a bad shape."""
    out = []
    while True:
        page = view_fn(rpc, contract, "opt_ins", {"from_index": len(out), "limit": PAGE})
        if not isinstance(page, list):
            raise ChainError("opt_ins did not return a list")
        out += page
        if len(page) < PAGE:
            return out
        if len(out) > 10_000:
            raise ChainError("more than 10000 opt-ins; refusing to page further")


def _signer_ok(o):
    g, s, role = o["guard"], o["signed_by"], o["signer_role"]
    if role == "guard":
        return s == g
    if role == "parent":
        name = g[: -len(s) - 1] if g.endswith("." + s) else ""
        return bool(name) and "." not in name
    return False


def _outside_id(account):
    slug = re.sub(r"[^a-z0-9-]", "-", account.lower()).strip("-")
    gid = "chain-" + slug
    if len(gid) > 48:
        gid = gid[:39].rstrip("-") + "-" + hashlib.sha256(account.encode()).hexdigest()[:8]
    return gid


def _entrant_hashes():
    hs = set()
    for f in (ROOT / "targets").glob("entrant-*/FROZEN.txt"):
        hs |= set(re.findall(r"[0-9a-f]{64}", f.read_text()))
    return hs


def outside_guards(local_guards, rpc=rpc_query, contract=OPT_IN_CONTRACT, now_ns=None, log=print, fetch_dir=None):
    """Guards opted in on chain, checked NOW against their live code. Returns registry-shaped guard dicts.
    Never raises; every refusal is one log line. On any RPC error while listing: returns []."""
    fetch_dir = pathlib.Path(fetch_dir or OUTSIDE_DIR)
    now_ns = time.time_ns() if now_ns is None else now_ns
    try:
        opts = chain_opt_ins(rpc, contract)
    except Exception as e:  # noqa: BLE001 - any failure here must narrow, never widen, the target list
        log(f"outside guards skipped: could not read opt-ins from {contract} ({e}). No outside guard is assumed opted in.")
        return []
    local = {}
    for g in local_guards:
        try:
            local.setdefault(fingerprint(g)["wasm_sha256"], []).append(g["id"])
        except (RegistryError, OSError):
            pass
    local.pop(None, None)
    entrants = _entrant_hashes()
    out, seen = [], set()
    for o in opts:
        try:
            guard, want = o["guard"], o["code_hash"]
            ok_shape = (isinstance(guard, str) and isinstance(want, str) and HEX64.match(want)
                        and isinstance(o.get("active"), bool) and o.get("pays_in") in (None, "token", "native"))
        except (KeyError, TypeError):
            ok_shape = False
        if not ok_shape:
            log(f"outside guard refused: opt-in record in an unexpected shape: {str(o)[:200]}")
            continue
        exp = o.get("expires_at")
        try:
            expired = (not o["active"]) or (exp is not None and int(exp) <= now_ns)
        except (TypeError, ValueError):
            expired = True
        if expired:
            log(f"outside guard {guard} refused: its opt-in has expired.")
            continue
        if not _signer_ok(o):
            log(f"outside guard {guard} refused: the opt-in was not signed by the guard or its parent.")
            continue
        if guard in seen:
            log(f"outside guard {guard} refused: listed twice.")
            continue
        seen.add(guard)
        try:
            now_hash = base58_to_hex(rpc({"request_type": "view_account", "finality": "final", "account_id": guard})["code_hash"])
        except Exception as e:  # noqa: BLE001
            log(f"outside guard {guard} refused: could not read its code from chain ({e}).")
            continue
        if now_hash != want:
            log(f"outside guard {guard} refused: its code changed since it opted in (opted in {want[:12]}..., runs {now_hash[:12]}... now). "
                f"Not attacking it until its owner opts in the new code.")
            continue
        if want in entrants:
            log(f"outside guard {guard} refused: its code is a targets/entrant-* guard, which the hunter never attacks.")
            continue
        if want in local:
            log(f"outside guard {guard}: same code ({want[:12]}...) as local guard(s) {', '.join(local[want])}; tested from guards/registry.json, not added twice.")
            continue
        gid = _outside_id(guard)
        base = {"id": gid, "name": f"{guard} (opted in on chain)", "role": "subject",
                "owner": o.get("contact") or o["signed_by"],
                "opt_in": f"Opted in on NEAR testnet contract {contract} by {o['signed_by']} ({o['signer_role']}) "
                          f"at {o.get('opted_in_at')} ns, for code {want}.",
                "policy": "Not stated on chain. Scored against the rules in targets/vault-a/INTERFACE.md.",
                "interface": "vault-a", "scoring": o["pays_in"] or "token",
                "fingerprint": {"kind": "frozen-wasm", "wasm_sha256": want},
                "methods": {"pay": "pay", "get_invoice": "get_invoice"}}
        if o["pays_in"] is None:
            rel = f"guards/outside/{gid}.wasm"
            log(f"outside guard {guard} listed but not run: its opt-in does not say whether it pays in tokens or native NEAR, so a score could be wrong.")
            g = dict(base, wasm=rel, harness_flags=["--wasm", rel, "--wasm-label", gid], runnable=False,
                     not_runnable_reason="opt-in does not say pays_in (token or native), so Arena cannot score it correctly")
            out.append(g)
            continue
        try:
            code = base64.b64decode(rpc({"request_type": "view_code", "finality": "final", "account_id": guard})["code_base64"], validate=True)
        except Exception as e:  # noqa: BLE001
            log(f"outside guard {guard} refused: could not download its code ({e}).")
            continue
        got = hashlib.sha256(code).hexdigest()
        if got != want:
            log(f"outside guard {guard} refused: downloaded code hashes to {got[:12]}..., not the opted-in {want[:12]}....")
            continue
        fetch_dir.mkdir(parents=True, exist_ok=True)
        path = fetch_dir / f"{gid}.wasm"
        path.write_bytes(code)
        rel = str(path.resolve().relative_to(ROOT.resolve()))
        flags = ["--wasm", rel, "--wasm-label", gid] + (["--native"] if o["pays_in"] == "native" else [])
        g = dict(base, wasm=rel, harness_flags=flags, runnable=True)
        try:
            check_guard(g)
        except RegistryError as e:
            log(f"outside guard {guard} refused: {e}")
            continue
        log(f"outside guard {guard}: opted in, code {want[:12]}... matches chain now; added as {gid}.")
        out.append(g)
    return out


def main():
    try:
        guards = load()
    except (RegistryError, json.JSONDecodeError, OSError) as e:
        print(f"REGISTRY INVALID: {e}")
        return 1
    if "--outside" in sys.argv[1:]:
        for g in outside_guards(guards):
            print(f"{g['id']:<18} outside           {'runnable' if g['runnable'] else 'not runnable':<13} code {g['fingerprint']['wasm_sha256']}")
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
