#!/usr/bin/env python3
"""Validator for Arena attack files (a sequence plus its `meta` block).

  python3 -I tools/hunter/validate.py [files or dirs ...]   validate; exit 1 if any is bad
  python3 -I tools/hunter/validate.py --self-test            check this file agrees with schema/attack.schema.json
  python3 -I tools/hunter/validate.py --intents-suite        validate sequences-intents/ (the "intents" target allowed)
  python3 -I tools/hunter/validate.py --chainsig-suite       validate sequences-chainsig/ (the "signer" target allowed)

Why hand-written: the hunter must reject anything an AI or a paper slips in, with a reason a
person can read, using only the Python standard library (no pip install in CI). The JSON schema
in schema/attack.schema.json documents the same rules for outside people; --self-test checks the
two agree on every enum and bound.

Every rule here is a bound on DATA. Nothing in an attack file is ever executed except through the
harness's fixed step actions (harness/src/seq.rs): call, view, race, wait_blocks, wait_seconds,
add_key.
"""
import hashlib, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schema" / "attack.schema.json"

# ---- bounds (keep in sync with schema/attack.schema.json; --self-test checks) ----
MAX_STEPS = 12
RACE_MIN, RACE_MAX = 2, 4
MAX_WAIT_BLOCKS = 200
MAX_WAIT_SECONDS = 30
MAX_TOTAL_WAIT_SECONDS = 60
GAS_MIN, GAS_MAX = 1, 300
MAX_DEPOSIT_YOCTO = 10**18
MAX_ARG_STRING = 128
MAX_ARGS_BYTES = 1024
MAX_ARG_DEPTH = 2
MAX_INT = 2**63 - 1
ACTORS = ("agent", "outsider")
TARGETS = ("vault", "token")
# "intents" (2026-11-11): the NEAR Intents contract, deployed only for a guard that pays into it.
# Allowed ONLY in the intents suite (sequences-intents/, loaded by tools/check/check.py for
# "pays_in": "intents"); every other attack file keeps TARGETS, so the main library cannot change.
INTENTS_TARGETS = TARGETS + ("intents",)
# "signer" (2026-11-11): Arena's Chain Signatures stand-in, deployed only for a guard whose config
# says "signs_via": "chain-signatures". Allowed ONLY in the chain-signatures suite (sequences-chainsig/).
CHAINSIG_TARGETS = TARGETS + ("signer",)
ADD_KEY_PERMISSIONS = ("full_access", "function_call_token")
SOURCES = ("hand", "ai", "paper", "combined", "news")
VALIDATION = ("broke", "valid-nothing-broke")
KINDS = ("sequence", "injection")
STEP_KEYS = ("call", "view", "race", "wait_blocks", "wait_seconds", "add_key")
CALL_KEYS = ("actor", "target", "method", "args", "gas_tgas", "deposit_yocto")
VIEW_KEYS = ("target", "method", "args")
ADD_KEY_KEYS = ("actor", "permission")
META_KEYS = ("id", "title", "source", "kind", "paper", "news", "breaks", "expected_safe_result",
             "added", "author", "steps_sha256", "injection", "found_in_hunt", "broke_guards", "held_guards",
             "parents", "validation", "spec", "admission")
META_REQUIRED = ("id", "title", "source", "kind", "breaks", "expected_safe_result", "added", "author", "steps_sha256")
PAPER_KEYS = ("arxiv_id", "title", "url")
NEWS_KEYS = ("item_id", "date", "links")
MAX_NEWS_LINKS = 3
INJECTION_KEYS = ("email", "injected_pays", "scenario_id")
MAX_INJECTED_PAYS = 6
MAX_EMAIL = 4000
TEXT_LIMITS = {"title": 120, "breaks": 400, "expected_safe_result": 300, "author": 120}

# ---- attack admission (2026-11-12): meta.spec (written by a person) and meta.admission (written
# only by tools/admission/admit.py). The rules a JSON schema cannot say are checked here.
REFERENCES = ROOT / "tools" / "admission" / "references.json"
SPEC_KEYS = ("property", "failure_mode", "capabilities", "preconditions", "oracle", "ordering", "expected")
SPEC_REQUIRED = ("property", "failure_mode", "capabilities")
CAPABILITIES = ("C1", "C2", "C3", "C4", "C5", "C6")
ORACLE_KEYS = ("decides", "receiver", "also")
ORACLE_DECIDES = ("beyond_policy", "against_intent")
ORACLE_ALSO = ("honest_settled", "conservation")
ORDERINGS = ("none", "overlap")
EXPECTED_KEYS = ("reference", "outcome", "beyond_policy", "receiver", "flaw", "mechanism", "note")
EXPECTED_REQUIRED = ("reference", "outcome", "beyond_policy", "mechanism")
OUTCOMES = ("held", "broke")
STEP_OUTCOMES = ("ok", "contract-failure", "protocol-rejected", "not-included")
SCORE_FIELDS = ("unauthorised_payout", "beyond_authorised", "above_cap", "paid_outside_receivers", "honest_settled", "should_pay")
# predicate name -> {param: kind}; kinds: steps (list of STEP_OUTCOMES), idx, text, name, amount, field, status, actor, scalar
PREDICATES = {
    "step_outcomes": {"value": "steps"},
    "failure_contains": {"step": "idx", "text": "text"},
    "over_equals": {"receiver": "name", "amount": "amount"},
    "outside_equals": {"to": "name", "amount": "amount"},
    "score_equals": {"field": "field", "value": "amount"},
    "status_equals": {"invoice": "name", "status": "status"},
    "credited_equals": {"invoice": "name", "amount": "amount"},
    "non_agent_pay": {"invoice": "name", "actor": "actor"},
    "view_equals": {"step": "idx", "value": "scalar"},
}
ADMISSION_KEYS = ("class", "evidence", "date", "gate", "runs_counted", "runs_tried", "why")
ADMISSION_REQUIRED = ("class", "evidence", "date", "gate", "runs_counted", "runs_tried")
ADMISSION_CLASSES = ("validated", "partially-validated", "unvalidated")
ADMISSION_GATE = "tools/admission/admit.py"
EVIDENCE_RE = re.compile(r"^evidence/admission/[a-z0-9][a-z0-9-]{0,95}/[0-9]{8}T[0-9]{6}Z$")
STATUS_RE = re.compile(r"^[A-Za-z]{1,32}$")

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,95}$")
METHOD_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
ARG_KEY_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
ARXIV_RE = re.compile(r"^\d{4}\.\d{4,5}(v\d+)?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
INVOICE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# A news item's post links: recorded as text, never fetched. Only plain https post links survive.
NEWS_LINK_RE = re.compile(r"^https://(x\.com|twitter\.com|t\.me)/[A-Za-z0-9_./?=&%-]{1,200}$")
NEWS_ID_RE = re.compile(r"^n-[0-9a-f]{10}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # \t and \n allowed


class Invalid(ValueError):
    pass


def _need(cond, why):
    if not cond:
        raise Invalid(why)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _text(v, field, limit, allow_newlines=False):
    _need(isinstance(v, str), f"{field} must be a string")
    _need(0 < len(v.strip()) and len(v) <= limit, f"{field} must be 1-{limit} characters (got {len(v)})")
    _need(not CONTROL_RE.search(v), f"{field} contains control characters")
    if not allow_newlines:
        _need("\n" not in v and "\r" not in v, f"{field} must be one line")
    return v


def _check_args(args, where, depth=0):
    if depth == 0:
        _need(isinstance(args, dict), f"{where}: args must be an object")
        _need(len(json.dumps(args)) <= MAX_ARGS_BYTES, f"{where}: args longer than {MAX_ARGS_BYTES} bytes")
    if isinstance(args, dict):
        _need(depth <= MAX_ARG_DEPTH, f"{where}: args nested deeper than {MAX_ARG_DEPTH}")
        for k, v in args.items():
            _need(isinstance(k, str) and ARG_KEY_RE.fullmatch(k), f"{where}: bad arg name {k!r}")
            _check_args(v, where, depth + 1)
    elif isinstance(args, list):
        _need(depth <= MAX_ARG_DEPTH, f"{where}: args nested deeper than {MAX_ARG_DEPTH}")
        _need(len(args) <= 8, f"{where}: arg list longer than 8")
        for v in args:
            _check_args(v, where, depth + 1)
    elif isinstance(args, str):
        _need(len(args) <= MAX_ARG_STRING, f"{where}: arg string longer than {MAX_ARG_STRING}")
        _need(not CONTROL_RE.search(args) and "\n" not in args, f"{where}: arg string has control characters")
    elif isinstance(args, bool) or args is None:
        pass
    elif _is_int(args):
        _need(0 <= args <= MAX_INT, f"{where}: arg number out of range 0..2^63-1")
    else:
        raise Invalid(f"{where}: arg values must be strings, whole numbers, booleans, null, lists or objects")


def _check_call(c, where, targets=TARGETS):
    _need(isinstance(c, dict), f"{where}: call must be an object")
    extra = set(c) - set(CALL_KEYS)
    _need(not extra, f"{where}: unknown call keys {sorted(extra)}")
    _need(c.get("actor") in ACTORS, f"{where}: actor must be one of {ACTORS} (the owner is never available)")
    _need(c.get("target", "vault") in targets, f"{where}: target must be one of {targets}")
    _need(isinstance(c.get("method"), str) and METHOD_RE.fullmatch(c["method"]), f"{where}: bad method name {c.get('method')!r}")
    _check_args(c.get("args", {}), where)
    if "gas_tgas" in c:
        _need(_is_int(c["gas_tgas"]) and GAS_MIN <= c["gas_tgas"] <= GAS_MAX, f"{where}: gas_tgas must be {GAS_MIN}-{GAS_MAX}")
    if "deposit_yocto" in c:
        _need(_is_int(c["deposit_yocto"]) and 0 <= c["deposit_yocto"] <= MAX_DEPOSIT_YOCTO,
              f"{where}: deposit_yocto must be 0-{MAX_DEPOSIT_YOCTO}")


def check_steps(steps, targets=TARGETS):
    """Validate a steps list. Returns None; raises Invalid with a reason."""
    _need(isinstance(steps, list) and steps, "steps must be a non-empty list")
    _need(len(steps) <= MAX_STEPS, f"at most {MAX_STEPS} steps (got {len(steps)})")
    total_wait_s = 0
    state_changing = 0
    for i, st in enumerate(steps):
        w = f"step {i}"
        _need(isinstance(st, dict) and len(st) == 1, f"{w}: each step is an object with exactly one of {STEP_KEYS}")
        (k, v), = st.items()
        _need(k in STEP_KEYS, f"{w}: unknown step kind {k!r}")
        if k == "call":
            _check_call(v, w, targets); state_changing += 1
        elif k == "view":
            _need(isinstance(v, dict), f"{w}: view must be an object")
            extra = set(v) - set(VIEW_KEYS)
            _need(not extra, f"{w}: unknown view keys {sorted(extra)}")
            _need(v.get("target", "vault") in targets, f"{w}: target must be one of {targets}")
            _need(isinstance(v.get("method"), str) and METHOD_RE.fullmatch(v["method"]), f"{w}: bad view method {v.get('method')!r}")
            _check_args(v.get("args", {}), w)
        elif k == "race":
            _need(isinstance(v, list) and RACE_MIN <= len(v) <= RACE_MAX, f"{w}: race must list {RACE_MIN}-{RACE_MAX} calls")
            for j, el in enumerate(v):
                inner = el["call"] if isinstance(el, dict) and set(el) == {"call"} else el
                _check_call(inner, f"{w} race call {j}", targets)
            state_changing += 1
        elif k == "wait_blocks":
            _need(_is_int(v) and 1 <= v <= MAX_WAIT_BLOCKS, f"{w}: wait_blocks must be 1-{MAX_WAIT_BLOCKS}")
        elif k == "wait_seconds":
            _need(_is_int(v) and 1 <= v <= MAX_WAIT_SECONDS, f"{w}: wait_seconds must be 1-{MAX_WAIT_SECONDS}")
            total_wait_s += v
        elif k == "add_key":
            _need(isinstance(v, dict), f"{w}: add_key must be an object")
            extra = set(v) - set(ADD_KEY_KEYS)
            _need(not extra, f"{w}: unknown add_key keys {sorted(extra)}")
            _need(v.get("actor") in ACTORS, f"{w}: actor must be one of {ACTORS}")
            _need(v.get("permission", "full_access") in ADD_KEY_PERMISSIONS, f"{w}: permission must be one of {ADD_KEY_PERMISSIONS}")
            state_changing += 1
    _need(total_wait_s <= MAX_TOTAL_WAIT_SECONDS, f"wait_seconds add up to {total_wait_s}; at most {MAX_TOTAL_WAIT_SECONDS}")
    _need(state_changing > 0, "an attack must contain at least one call, race or add_key (views alone change nothing)")


# ---- canonical form: "same steps means the same attack" ----

def _canon_call(c):
    out = {"actor": c["actor"], "target": c.get("target", "vault"), "method": c["method"],
           "args": c.get("args", {}), "gas_tgas": c.get("gas_tgas", 300)}  # harness default = max gas = 300 TGas
    if c.get("deposit_yocto"):
        out["deposit_yocto"] = c["deposit_yocto"]
    return out


def canonical_steps(steps):
    """What the attack DOES. Views are dropped (they change no state); a race element wrapped in
    {"call": ...} is unwrapped; defaults are filled in (target=vault, gas=300 TGas)."""
    out = []
    for st in steps:
        (k, v), = st.items()
        if k == "view":
            continue
        if k == "call":
            out.append({"call": _canon_call(v)})
        elif k == "race":
            out.append({"race": [_canon_call(el["call"] if isinstance(el, dict) and set(el) == {"call"} else el) for el in v]})
        elif k == "add_key":
            out.append({"add_key": {"actor": v["actor"], "permission": v.get("permission", "full_access")}})
        else:
            out.append({k: v})
    return out


def steps_hash(steps):
    return hashlib.sha256(json.dumps(canonical_steps(steps), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def injection_steps(pays):
    """The steps a fully fooled agent takes: one agent `pay` per invoice the injection asks for."""
    return [{"call": {"actor": "agent", "method": "pay", "args": {"id": p}}} for p in pays]


def check_meta(meta, steps):
    _need(isinstance(meta, dict), "meta must be an object")
    extra = set(meta) - set(META_KEYS)
    _need(not extra, f"unknown meta keys {sorted(extra)}")
    for k in META_REQUIRED:
        _need(k in meta, f"meta.{k} is required")
    _need(isinstance(meta["id"], str) and ID_RE.fullmatch(meta["id"]), f"meta.id must match {ID_RE.pattern}")
    for k, lim in TEXT_LIMITS.items():
        _text(meta[k], f"meta.{k}", lim)
    _need(meta["source"] in SOURCES, f"meta.source must be one of {SOURCES}")
    _need(meta["kind"] in KINDS, f"meta.kind must be one of {KINDS}")
    _need(isinstance(meta["added"], str) and DATE_RE.fullmatch(meta["added"]), "meta.added must be YYYY-MM-DD")
    _need(isinstance(meta["steps_sha256"], str) and HEX64_RE.fullmatch(meta["steps_sha256"]), "meta.steps_sha256 must be 64 hex chars")
    _need(meta["steps_sha256"] == steps_hash(steps), "meta.steps_sha256 does not match the steps (steps changed?)")
    if meta["source"] == "paper":
        p = meta.get("paper")
        _need(isinstance(p, dict), "meta.paper is required when source is paper")
        _need(not (set(p) - set(PAPER_KEYS)) and all(k in p for k in PAPER_KEYS), f"meta.paper needs exactly {PAPER_KEYS}")
        _need(isinstance(p["arxiv_id"], str) and ARXIV_RE.fullmatch(p["arxiv_id"]), "meta.paper.arxiv_id is not an arXiv id")
        _text(p["title"], "meta.paper.title", 300)
        base = p["arxiv_id"].split("v")[0]
        _need(p["url"] in (f"https://arxiv.org/abs/{p['arxiv_id']}", f"https://arxiv.org/abs/{base}"),
              "meta.paper.url must be https://arxiv.org/abs/<arxiv_id>")
    else:
        _need("paper" not in meta, "meta.paper only belongs on source=paper")
    if meta["source"] == "news":
        n = meta.get("news")
        _need(isinstance(n, dict), "meta.news is required when source is news")
        _need(not (set(n) - set(NEWS_KEYS)) and all(k in n for k in NEWS_KEYS), f"meta.news needs exactly {NEWS_KEYS}")
        _need(isinstance(n["item_id"], str) and NEWS_ID_RE.fullmatch(n["item_id"]), "meta.news.item_id must look like n-<10 hex>")
        _need(isinstance(n["date"], str) and DATE_RE.fullmatch(n["date"]), "meta.news.date must be YYYY-MM-DD")
        _need(isinstance(n["links"], list) and len(n["links"]) <= MAX_NEWS_LINKS
              and all(isinstance(x, str) and NEWS_LINK_RE.fullmatch(x) for x in n["links"]),
              f"meta.news.links must be at most {MAX_NEWS_LINKS} https post links (x.com, twitter.com, t.me)")
    else:
        _need("news" not in meta, "meta.news only belongs on source=news")
    if meta["source"] == "combined":
        par = meta.get("parents")
        _need(isinstance(par, list) and 2 <= len(par) <= 4 and len(set(par)) == len(par)
              and all(isinstance(x, str) and ID_RE.fullmatch(x) for x in par),
              "meta.parents must list 2-4 distinct library attack ids when source is combined")
    else:
        _need("parents" not in meta, "meta.parents only belongs on source=combined")
    if "validation" in meta:
        _need(meta["validation"] in VALIDATION, f"meta.validation must be one of {VALIDATION}")
    if meta["kind"] == "injection":
        inj = meta.get("injection")
        _need(isinstance(inj, dict), "meta.injection is required when kind is injection")
        _need(not (set(inj) - set(INJECTION_KEYS)), f"meta.injection keys must be among {INJECTION_KEYS}")
        _text(inj.get("email"), "meta.injection.email", MAX_EMAIL, allow_newlines=True)
        pays = inj.get("injected_pays")
        _need(isinstance(pays, list) and 1 <= len(pays) <= MAX_INJECTED_PAYS
              and all(isinstance(x, str) and INVOICE_RE.fullmatch(x) for x in pays),
              f"meta.injection.injected_pays must list 1-{MAX_INJECTED_PAYS} invoice ids")
        _need(canonical_steps(steps) == canonical_steps(injection_steps(pays)),
              "an injection attack's steps must be exactly one agent pay per injected_pays entry")
    for k in ("broke_guards", "held_guards"):
        if k in meta:
            _need(isinstance(meta[k], list) and all(isinstance(x, str) and ID_RE.fullmatch(x) for x in meta[k]), f"meta.{k} must list guard ids")
    if "found_in_hunt" in meta:
        _need(isinstance(meta["found_in_hunt"], str) and ID_RE.fullmatch(meta["found_in_hunt"]), "meta.found_in_hunt must be a hunt id")
    if "spec" in meta:
        check_spec(meta["spec"], steps)
    if "admission" in meta:
        check_admission(meta, steps)


def load_references():
    return json.loads(REFERENCES.read_text())["references"]


def spec_sha256(spec):
    return hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _check_predicate(p, where):
    _need(isinstance(p, dict) and isinstance(p.get("pred"), str), f"{where}: a mechanism entry is an object with a 'pred'")
    params = PREDICATES.get(p["pred"])
    _need(params is not None, f"{where}: unknown predicate {p['pred']!r} (one of {sorted(PREDICATES)})")
    _need(set(p) == {"pred", *params}, f"{where}: predicate {p['pred']} needs exactly {sorted(params)}")
    for k, kind in params.items():
        v = p[k]
        if kind == "steps":
            _need(isinstance(v, list) and 1 <= len(v) <= 16 and all(x in STEP_OUTCOMES for x in v), f"{where}.{k}: list of {STEP_OUTCOMES}")
        elif kind == "idx":
            _need(_is_int(v) and 0 <= v <= 15, f"{where}.{k}: step index 0-15")
        elif kind == "text":
            _text(v, f"{where}.{k}", 120)
        elif kind == "name":
            _need(isinstance(v, str) and INVOICE_RE.fullmatch(v), f"{where}.{k}: bad name {v!r}")
        elif kind == "amount":
            _need(_is_int(v) and 0 <= v <= MAX_INT, f"{where}.{k}: whole number >= 0")
        elif kind == "field":
            _need(v in SCORE_FIELDS, f"{where}.{k}: one of {SCORE_FIELDS}")
        elif kind == "status":
            _need(isinstance(v, str) and STATUS_RE.fullmatch(v), f"{where}.{k}: a status word")
        elif kind == "actor":
            _need(v == "outsider", f"{where}.{k}: only 'outsider' (the agent's pays are not non-agent pays)")
        elif kind == "scalar":
            _need(v is None or isinstance(v, (str, bool)) or _is_int(v), f"{where}.{k}: string, whole number, boolean or null")
            if isinstance(v, str):
                _need(len(v) <= MAX_ARG_STRING, f"{where}.{k}: at most {MAX_ARG_STRING} characters")


def check_spec(spec, steps, refs=None):
    """Structure and cross-field rules of meta.spec. Raises Invalid."""
    _need(isinstance(spec, dict), "meta.spec must be an object")
    extra = set(spec) - set(SPEC_KEYS)
    _need(not extra, f"unknown meta.spec keys {sorted(extra)}")
    for k in SPEC_REQUIRED:
        _need(k in spec, f"meta.spec.{k} is required")
    _text(spec["property"], "meta.spec.property", 300)
    _text(spec["failure_mode"], "meta.spec.failure_mode", 300)
    caps = spec["capabilities"]
    _need(isinstance(caps, list) and 1 <= len(caps) <= 6 and len(set(caps)) == len(caps) and all(c in CAPABILITIES for c in caps),
          f"meta.spec.capabilities must list distinct values from {CAPABILITIES}")
    if "preconditions" in spec:
        pc = spec["preconditions"]
        _need(isinstance(pc, list) and len(pc) <= 8, "meta.spec.preconditions: at most 8")
        for i, x in enumerate(pc):
            _text(x, f"meta.spec.preconditions[{i}]", 200)
    if "oracle" in spec:
        o = spec["oracle"]
        _need(isinstance(o, dict) and not (set(o) - set(ORACLE_KEYS)) and o.get("decides") in ORACLE_DECIDES,
              f"meta.spec.oracle needs decides in {ORACLE_DECIDES}; keys among {ORACLE_KEYS}")
        if "receiver" in o:
            _need(isinstance(o["receiver"], str) and INVOICE_RE.fullmatch(o["receiver"]), "meta.spec.oracle.receiver: bad name")
        if "also" in o:
            _need(isinstance(o["also"], list) and len(set(o["also"])) == len(o["also"]) and all(x in ORACLE_ALSO for x in o["also"]),
                  f"meta.spec.oracle.also: distinct values from {ORACLE_ALSO}")
    has_race = any("race" in st for st in steps)
    if "ordering" in spec:
        _need(spec["ordering"] in ORDERINGS, f"meta.spec.ordering must be one of {ORDERINGS}")
    if has_race:
        _need(spec.get("ordering") not in (None, "none"), "meta.spec.ordering is required (not 'none') when any step is a race: a race is proved only by the ordering")
    if "expected" in spec:
        exp = spec["expected"]
        _need(isinstance(exp, list) and 1 <= len(exp) <= 12, "meta.spec.expected: 1-12 entries")
        refs = load_references() if refs is None else refs
        seen = set()
        for i, e in enumerate(exp):
            w = f"meta.spec.expected[{i}]"
            _need(isinstance(e, dict), f"{w} must be an object")
            extra = set(e) - set(EXPECTED_KEYS)
            _need(not extra, f"{w}: unknown keys {sorted(extra)}")
            for k in EXPECTED_REQUIRED:
                _need(k in e, f"{w}.{k} is required")
            _need(e["reference"] in refs, f"{w}.reference {e['reference']!r} is not in the closed list (tools/admission/references.json)")
            _need(e["reference"] not in seen, f"{w}.reference {e['reference']!r} named twice")
            seen.add(e["reference"])
            _need(e["outcome"] in OUTCOMES, f"{w}.outcome must be one of {OUTCOMES}")
            _need(_is_int(e["beyond_policy"]) and 0 <= e["beyond_policy"] <= MAX_INT, f"{w}.beyond_policy: whole number >= 0")
            if "receiver" in e:
                _need(isinstance(e["receiver"], str) and INVOICE_RE.fullmatch(e["receiver"]), f"{w}.receiver: bad name")
            if "note" in e:
                _text(e["note"], f"{w}.note", 200)
            ref = refs[e["reference"]]
            if e["outcome"] == "held":
                _need(e["beyond_policy"] == 0, f"{w}: a held entry has beyond_policy 0")
                _need("flaw" not in e, f"{w}: a held entry names no flaw")
                _need(ref["kind"] == "known-good", f"{w}: {e['reference']} is a {ref['kind']} reference; held entries name known-good references")
            else:
                _need(e["beyond_policy"] > 0, f"{w}: a broke entry needs a positive beyond_policy")
                _need(isinstance(e.get("flaw"), str), f"{w}: a broke entry must name the flaw it expects to fire")
                _need(ref["kind"] == "known-bad", f"{w}: {e['reference']} is a {ref['kind']} reference; broke entries name known-bad references")
            ms = e["mechanism"]
            _need(isinstance(ms, list) and 1 <= len(ms) <= 10, f"{w}.mechanism: 1-10 predicates")
            for j, p in enumerate(ms):
                _check_predicate(p, f"{w}.mechanism[{j}]")
            n_rec = recorded_step_count(steps)
            for p in ms:
                if p["pred"] in ("failure_contains", "view_equals"):
                    _need(p["step"] < n_rec, f"{w}: predicate {p['pred']} names recorded step {p['step']}, the harness records {n_rec} for this attack (one per call, view, add_key and race leg; none for waits)")


def recorded_step_count(steps):
    """How many entries the harness writes to a result's `steps` for these attack steps:
    one per call, view and add_key, one per race leg, none for waits (harness/src/seq.rs execute)."""
    return sum(len(st["race"]) if "race" in st else (1 if any(k in st for k in ("call", "view", "add_key")) else 0) for st in steps)


def matched_entries(spec, refs=None):
    """The broke entries whose reference has exactly the flaw the entry names AND is the one-flaw copy
    (twin_of) of a known-good the same spec expects to hold: the matched positive controls."""
    refs = load_references() if refs is None else refs
    held = {e["reference"] for e in spec.get("expected", []) if e["outcome"] == "held"}
    return [e for e in spec.get("expected", []) if e["outcome"] == "broke"
            and refs[e["reference"]]["matchable"] and refs[e["reference"]]["flaw"] == e.get("flaw")
            and refs[e["reference"]].get("twin_of") in held]


def check_admission(meta, steps, root=ROOT):
    """meta.admission must agree with the gate's own evidence: a hand-written 'validated' fails here."""
    a = meta["admission"]
    _need("spec" in meta, "meta.admission is only allowed next to meta.spec (the gate admits against a spec)")
    _need(isinstance(a, dict), "meta.admission must be an object")
    extra = set(a) - set(ADMISSION_KEYS)
    _need(not extra, f"unknown meta.admission keys {sorted(extra)}")
    for k in ADMISSION_REQUIRED:
        _need(k in a, f"meta.admission.{k} is required")
    _need(a["class"] in ADMISSION_CLASSES, f"meta.admission.class must be one of {ADMISSION_CLASSES}")
    _need(a["gate"] == ADMISSION_GATE, f"meta.admission.gate must be {ADMISSION_GATE}")
    _need(isinstance(a["date"], str) and DATE_RE.fullmatch(a["date"]), "meta.admission.date must be YYYY-MM-DD")
    _need(_is_int(a["runs_counted"]) and _is_int(a["runs_tried"]) and 0 <= a["runs_counted"] <= a["runs_tried"], "meta.admission runs: 0 <= counted <= tried")
    if "why" in a:
        _text(a["why"], "meta.admission.why", 400)
    _need(isinstance(a["evidence"], str) and EVIDENCE_RE.fullmatch(a["evidence"]), "meta.admission.evidence must be evidence/admission/<id>/<UTC stamp>")
    _need(a["evidence"].split("/")[2] == meta["id"], "meta.admission.evidence must be this attack's own folder")
    f = root / a["evidence"] / "admission.json"
    _need(f.is_file(), f"meta.admission.evidence: {a['evidence']}/admission.json not found")
    try:
        ev = json.loads(f.read_text())
    except json.JSONDecodeError:
        raise Invalid(f"{a['evidence']}/admission.json is not JSON")
    for k in ("class", "runs_counted", "runs_tried"):
        _need(ev.get(k) == a[k], f"meta.admission.{k} ({a[k]!r}) differs from the gate's evidence ({ev.get(k)!r})")
    _need(ev.get("steps_sha256") == meta["steps_sha256"], "the gate admitted different steps than this file has")
    _need(ev.get("spec_sha256") == spec_sha256(meta["spec"]), "the gate admitted a different spec than this file has (spec edited after admission?)")
    _need(ev.get("attack_id") == meta["id"] and ev.get("gate") == ADMISSION_GATE, "the evidence folder is not the gate's record for this attack")
    # The class must FOLLOW from the stored raw runs, not just be copied: re-judge them (pure, no sandbox).
    sys.path.insert(0, str(root / "tools" / "admission"))
    import admit  # noqa: E402  (lazy: admit imports this module)
    cls, why, problems = admit.rederive({"meta": meta, "steps": steps}, root=root)
    _need(not problems, "meta.admission does not follow from the stored runs: " + "; ".join(problems)[:600])


def check_attack(doc, require_meta=True, intents_suite=False, chainsig_suite=False):
    """Validate a whole attack file (already parsed). Raises Invalid."""
    _need(isinstance(doc, dict), "an attack file is a JSON object")
    extra = set(doc) - {"name", "steps", "meta"}
    _need(not extra, f"unknown top-level keys {sorted(extra)}")
    _need(isinstance(doc.get("name"), str) and NAME_RE.fullmatch(doc["name"]), f"name must match {NAME_RE.pattern}")
    check_steps(doc.get("steps"), CHAINSIG_TARGETS if chainsig_suite else INTENTS_TARGETS if intents_suite else TARGETS)
    if require_meta or "meta" in doc:
        _need("meta" in doc, "meta block missing")
        check_meta(doc["meta"], doc["steps"])


def validate_path(p, require_meta=True, intents_suite=False, chainsig_suite=False):
    try:
        doc = json.loads(pathlib.Path(p).read_text())
    except (OSError, json.JSONDecodeError) as e:
        return f"{p}: not readable JSON ({type(e).__name__})"
    try:
        check_attack(doc, require_meta, intents_suite, chainsig_suite)
    except Invalid as e:
        return f"{p}: {e}"
    return None


def self_test():
    s = json.loads(SCHEMA.read_text())
    d = s["$defs"]
    problems = []

    def same(label, a, b):
        if a != b:
            problems.append(f"{label}: validator {a!r} vs schema {b!r}")
    same("max steps", MAX_STEPS, s["properties"]["steps"]["maxItems"])
    same("actors", list(ACTORS), d["call"]["properties"]["actor"]["enum"])
    same("targets", list(INTENTS_TARGETS) + ["signer"], d["call"]["properties"]["target"]["enum"])
    same("gas min", GAS_MIN, d["call"]["properties"]["gas_tgas"]["minimum"])
    same("gas max", GAS_MAX, d["call"]["properties"]["gas_tgas"]["maximum"])
    same("deposit max", MAX_DEPOSIT_YOCTO, d["call"]["properties"]["deposit_yocto"]["maximum"])
    same("method pattern", METHOD_RE.pattern, d["call"]["properties"]["method"]["pattern"])
    same("race min", RACE_MIN, d["step"]["oneOf"][2]["properties"]["race"]["minItems"])
    same("race max", RACE_MAX, d["step"]["oneOf"][2]["properties"]["race"]["maxItems"])
    same("wait_blocks max", MAX_WAIT_BLOCKS, d["step"]["oneOf"][3]["properties"]["wait_blocks"]["maximum"])
    same("wait_seconds max", MAX_WAIT_SECONDS, d["step"]["oneOf"][4]["properties"]["wait_seconds"]["maximum"])
    same("add_key permissions", list(ADD_KEY_PERMISSIONS), d["step"]["oneOf"][5]["properties"]["add_key"]["properties"]["permission"]["enum"])
    same("sources", list(SOURCES), d["meta"]["properties"]["source"]["enum"])
    same("validation", list(VALIDATION), d["meta"]["properties"]["validation"]["enum"])
    same("kinds", list(KINDS), d["meta"]["properties"]["kind"]["enum"])
    same("meta required", sorted(META_REQUIRED), sorted(d["meta"]["required"]))
    same("meta keys", sorted(META_KEYS), sorted(d["meta"]["properties"]))
    same("name pattern", NAME_RE.pattern, s["properties"]["name"]["pattern"])
    same("arxiv pattern", ARXIV_RE.pattern, d["paper"]["properties"]["arxiv_id"]["pattern"])
    same("news keys", sorted(NEWS_KEYS), sorted(d["news"]["properties"]))
    same("news id pattern", NEWS_ID_RE.pattern, d["news"]["properties"]["item_id"]["pattern"])
    same("news link pattern", NEWS_LINK_RE.pattern, d["news"]["properties"]["links"]["items"]["pattern"])
    same("news links max", MAX_NEWS_LINKS, d["news"]["properties"]["links"]["maxItems"])
    for k, lim in TEXT_LIMITS.items():
        same(f"{k} maxLength", lim, d["meta"]["properties"][k]["maxLength"])
    same("spec keys", sorted(SPEC_KEYS), sorted(d["spec"]["properties"]))
    same("spec required", sorted(SPEC_REQUIRED), sorted(d["spec"]["required"]))
    same("capabilities", list(CAPABILITIES), d["spec"]["properties"]["capabilities"]["items"]["enum"])
    same("oracle decides", list(ORACLE_DECIDES), d["spec"]["properties"]["oracle"]["properties"]["decides"]["enum"])
    same("oracle also", list(ORACLE_ALSO), d["spec"]["properties"]["oracle"]["properties"]["also"]["items"]["enum"])
    same("orderings", list(ORDERINGS), d["spec"]["properties"]["ordering"]["enum"])
    same("expected keys", sorted(EXPECTED_KEYS), sorted(d["expected"]["properties"]))
    same("expected required", sorted(EXPECTED_REQUIRED), sorted(d["expected"]["required"]))
    same("outcomes", list(OUTCOMES), d["expected"]["properties"]["outcome"]["enum"])
    same("predicates", sorted(PREDICATES), sorted(x["properties"]["pred"]["const"] for x in d["predicate"]["oneOf"]))
    for x in d["predicate"]["oneOf"]:
        name = x["properties"]["pred"]["const"]
        same(f"predicate {name} params", sorted(["pred", *PREDICATES.get(name, {})]), sorted(x["required"]))
    same("step outcomes", list(STEP_OUTCOMES), d["predicate"]["oneOf"][0]["properties"]["value"]["items"]["enum"])
    same("score fields", list(SCORE_FIELDS), d["predicate"]["oneOf"][4]["properties"]["field"]["enum"])
    same("admission keys", sorted(ADMISSION_KEYS), sorted(d["admission"]["properties"]))
    same("admission required", sorted(ADMISSION_REQUIRED), sorted(d["admission"]["required"]))
    same("admission classes", list(ADMISSION_CLASSES), d["admission"]["properties"]["class"]["enum"])
    same("admission evidence pattern", EVIDENCE_RE.pattern, d["admission"]["properties"]["evidence"]["pattern"])
    return problems


def main(argv):
    if argv[:1] == ["--self-test"]:
        problems = self_test()
        for p in problems:
            print("MISMATCH", p)
        print(f"self-test: {'ok' if not problems else str(len(problems)) + ' mismatches'} (validator vs {SCHEMA.relative_to(ROOT)})")
        return 1 if problems else 0
    # --intents-suite: the attack files run only for a guard that pays into NEAR Intents, where the
    # "intents" target is allowed (default folder sequences-intents/).
    intents_suite = argv[:1] == ["--intents-suite"]
    if intents_suite:
        argv = argv[1:] or [str(ROOT / "sequences-intents")]
    # --chainsig-suite: the attack files run only for a guard that signs via Chain Signatures, where
    # the "signer" target is allowed (default folder sequences-chainsig/).
    chainsig_suite = argv[:1] == ["--chainsig-suite"]
    if chainsig_suite:
        argv = argv[1:] or [str(ROOT / "sequences-chainsig")]
    paths = []
    for a in argv or [str(ROOT / d) for d in ("sequences-scripted", "sequences-ai", "sequences-bypass", "sequences-paper")]:
        p = pathlib.Path(a)
        if p.is_dir():
            paths += sorted(x for x in p.glob("*.json") if not x.name.endswith(".result.json"))
        elif p.exists():
            paths.append(p)
    bad = 0
    for p in paths:
        err = validate_path(p, intents_suite=intents_suite, chainsig_suite=chainsig_suite)
        if err:
            bad += 1
            print("INVALID", err)
    print(f"validated {len(paths)} attack files: {len(paths) - bad} valid, {bad} invalid")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
