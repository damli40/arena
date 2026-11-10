"""Guard config + method mapping for `arena check`: load, check, explain, resolve.

Two data files, both optional:
- the CONFIG (`--config guard.json`): how to start the guard and which rules it claims;
- the MAPPING (`--mapping mapping.json`, or proposed by Muse): which of the guard's methods plays
  each role of targets/vault-a/INTERFACE.md, and a few argument-shape choices.

Every value is either a method name that must exist in the guard's wasm, or one choice from a
closed list below. Nothing in either file is compiled or run. The harness checks the merged file
again on its own side (harness/src/adapter.rs); `test_check.py` checks the two lists agree.
"""
import json, math, pathlib, re

# Used with fullmatch only (re.match + "$" would let a trailing newline through).
NAME_RE = re.compile(r"[a-z_][a-z0-9_]{0,63}")


def name_ok(v):
    return isinstance(v, str) and NAME_RE.fullmatch(v) is not None


def _is_int(v, *allowed):
    """An exact JSON integer (not true/false, not 1.0), optionally one of `allowed`."""
    return type(v) is int and (not allowed or v in allowed)

# Mirrors harness/src/adapter.rs (ROLES, DEPOSIT_ROLES, CHOICES, PLACEHOLDERS).
ROLES = ["pay", "approve_invoice", "add_payee", "remove_payee", "cancel_invoice", "set_daily_cap", "set_agent",
         "get_invoice", "get_config", "is_payee", "paid_today"]
DEPOSIT_ROLES = ["approve_invoice", "add_payee", "remove_payee", "cancel_invoice", "set_daily_cap"]
CHOICES = {
    "invoice_id_field": ["id", "invoice_id"],
    "receiver_field": ["receiver", "receiver_id", "account_id"],
    "payee_field": ["account", "account_id", "payee"],
    "expiry_field": ["expires_at_ns", "expires_at", "expiry"],
    "expiry_unit": ["ns", "ms", "s"],
    "amount_encoding": ["u128_string", "number"],
    "daily_cap_field": ["daily_cap", "cap", "limit"],
    "status_field": ["status", "state"],
    "paid_value": ["Paid", "paid", "PAID"],
}
PLACEHOLDERS = ["$owner", "$agent", "$token", "$daily_cap", "$daily_cap_number"]
FEATURES = ["payees", "cancel", "expiry", "daily_cap"]

# What each role does, in plain words (shown in errors and given to Muse).
ROLE_HELP = {
    "pay": "the agent calls it with an invoice id; it pays that invoice by calling ft_transfer on the NEP-141 token",
    "approve_invoice": "the owner approves an invoice with an id, a receiver, an amount, and an expiry if the guard has one",
    "get_invoice": "a view that returns one invoice, including whether it is paid",
    "add_payee": "the owner adds an account to the payee list",
    "remove_payee": "the owner removes an account from the payee list",
    "cancel_invoice": "the owner cancels an approved invoice",
    "set_daily_cap": "the owner changes the daily spending cap",
    "set_agent": "the owner changes which account is the agent",
    "get_config": "a view of the owner, agent, token and daily cap",
    "is_payee": "a view: is this account a payee",
    "paid_today": "a view: how much was paid today",
}

DEFAULT_DEPOSITS = {"approve_invoice": 1, "add_payee": 1, "remove_payee": 0, "cancel_invoice": 0, "set_daily_cap": 1}
DEFAULT_INIT = {"method": "new", "args": {"owner": "$owner", "agent": "$agent", "token": "$token", "daily_cap": "$daily_cap"}}

CONFIG_KEYS = {"arena_guard_config", "_about", "name", "policy", "init", "features", "methods", "shapes", "deposits"}
MAPPING_KEYS = {"arena_mapping", "_about", "methods", "shapes", "deposits"}


class ConfigError(ValueError):
    """A problem in a config or mapping file, worded so the reader knows what to change."""


def _need(cond, msg):
    if not cond:
        raise ConfigError(msg)


def required_roles(features):
    roles = ["pay", "approve_invoice", "get_invoice"]
    if features["payees"]:
        roles += ["add_payee", "remove_payee"]
    if features["cancel"]:
        roles.append("cancel_invoice")
    return roles


def _check_mapping_part(d, where):
    """methods / shapes / deposits, shared by both files."""
    if "methods" in d:
        m = d["methods"]
        _need(isinstance(m, dict), f"{where}: \"methods\" must be an object like {{\"pay\": \"your_pay_method\"}}")
        for role, name in m.items():
            _need(role in ROLES, f"{where}: \"methods\" has an unknown role {role!r}. Roles are: {', '.join(ROLES)}")
            _need(name_ok(name),
                  f"{where}: methods.{role} = {name!r} is not a NEAR method name (lowercase letters, digits, _)")
    if "shapes" in d:
        s = d["shapes"]
        _need(isinstance(s, dict), f"{where}: \"shapes\" must be an object")
        for k, v in s.items():
            _need(k in CHOICES, f"{where}: unknown shape {k!r}. Shapes are: {', '.join(CHOICES)}")
            _need(isinstance(v, str) and v in CHOICES[k], f"{where}: shapes.{k} = {v!r} is not allowed; pick one of {CHOICES[k]}")
    if "deposits" in d:
        dep = d["deposits"]
        _need(isinstance(dep, dict), f"{where}: \"deposits\" must be an object")
        for k, v in dep.items():
            _need(k in DEPOSIT_ROLES, f"{where}: deposits.{k}: only these owner methods take a deposit choice: {', '.join(DEPOSIT_ROLES)}")
            _need(_is_int(v, 0, 1), f"{where}: deposits.{k} must be 0 or 1 (yoctoNEAR attached to the call)")


def _no_constant(name):
    raise ValueError(f"{name} is not a JSON number")


def _finite_float(text):
    f = float(text)
    if not math.isfinite(f):
        raise ValueError(f"{text} is too large for a JSON number")
    return f


def loads(text):
    """Strict JSON, as the harness (serde_json) reads it: no NaN / Infinity, no number too
    large to be a float, no lone UTF-16 surrogate in a string."""
    v = json.loads(text, parse_constant=_no_constant, parse_float=_finite_float)

    def walk(x):
        if isinstance(x, str):
            x.encode("utf-8")  # a lone surrogate (e.g. "\\ud800") raises here
        elif isinstance(x, dict):
            for k, y in x.items():
                walk(k)
                walk(y)
        elif isinstance(x, list):
            for y in x:
                walk(y)
    walk(v)
    return v


def load_json(path, what):
    p = pathlib.Path(path)
    _need(p.is_file(), f"{what} file {path} not found")
    _need(p.stat().st_size <= 64 * 1024, f"{what} file {path} is larger than 64 KiB")
    try:
        return loads(p.read_text())
    except (ValueError, UnicodeError) as e:
        raise ConfigError(f"{what} file {path} is not valid JSON: {e}")


def check_config(d, where="config"):
    _need(isinstance(d, dict), f"{where}: must be a JSON object")
    extra = set(d) - CONFIG_KEYS
    _need(not extra, f"{where}: unknown keys {sorted(extra)}; allowed: {sorted(CONFIG_KEYS)}")
    _need(_is_int(d.get("arena_guard_config"), 1), f"{where}: add \"arena_guard_config\": 1 at the top")
    for k in ("name", "policy", "_about"):
        if k in d:
            _need(isinstance(d[k], str) and len(d[k]) <= 400, f"{where}: {k} must be a string of at most 400 characters")
    if "init" in d:
        i = d["init"]
        _need(isinstance(i, dict) and not (set(i) - {"method", "args"}), f"{where}: init must be {{\"method\": ..., \"args\": {{...}}}}")
        if "method" in i:
            _need(name_ok(i["method"]), f"{where}: init.method {i['method']!r} is not a NEAR method name")
        if "args" in i:
            a = i["args"]
            _need(isinstance(a, dict) and len(a) <= 16, f"{where}: init.args must be an object with at most 16 arguments")
            for k, v in a.items():
                _need(name_ok(k), f"{where}: init.args key {k!r} is not a valid argument name")
                if isinstance(v, str) and v.startswith("$"):
                    _need(v in PLACEHOLDERS, f"{where}: init.args.{k} = {v!r}: unknown placeholder. Arena fills in only {PLACEHOLDERS}")
                elif isinstance(v, str):
                    try:
                        size = len(v.encode("utf-8"))
                    except UnicodeError:
                        size = None
                    _need(size is not None and size <= 64, f"{where}: init.args.{k}: literal strings are at most 64 bytes (UTF-8)")
                else:
                    _need(isinstance(v, (bool, int)) or (isinstance(v, float) and math.isfinite(v)),
                          f"{where}: init.args.{k} must be a placeholder, a short string, a number or true/false")
    if "features" in d:
        f = d["features"]
        _need(isinstance(f, dict), f"{where}: features must be an object")
        for k, v in f.items():
            _need(k in FEATURES, f"{where}: unknown feature {k!r}; features are {FEATURES}")
            _need(isinstance(v, bool), f"{where}: features.{k} must be true or false")
    # A guard that claims the daily cap is scored against Arena's cap (500), so its init must
    # take that cap from Arena. A literal cap would be enforced by the guard but not scored.
    claims_cap = d.get("features", {}).get("daily_cap", True)
    args = d.get("init", {}).get("args", DEFAULT_INIT["args"])
    _need(not claims_cap or any(v in ("$daily_cap", "$daily_cap_number") for v in args.values() if isinstance(v, str)),
          f"{where}: your config says the guard has a daily cap, but init.args does not pass Arena's cap. Arena scores "
          "the cap as 500 tokens, so pass it in with \"$daily_cap\" (a string, \"500\") or \"$daily_cap_number\" (the number 500). "
          "If your guard has no daily cap, set \"features\": {\"daily_cap\": false}.")
    _check_mapping_part(d, where)
    return d


def check_mapping(d, where="mapping"):
    _need(isinstance(d, dict), f"{where}: must be a JSON object")
    extra = set(d) - MAPPING_KEYS
    _need(not extra, f"{where}: unknown keys {sorted(extra)}; allowed: {sorted(MAPPING_KEYS)}")
    _need(_is_int(d.get("arena_mapping"), 1), f"{where}: add \"arena_mapping\": 1 at the top")
    _check_mapping_part(d, where)
    return d


def resolve(config, mapping, wasm_methods):
    """Merge config + mapping into the one file the harness reads. Checks every method name
    against the guard's exports. Returns (resolved, problems): problems are plain-words lines
    about required roles the guard does not have; empty means ready to run."""
    config = config or {"arena_guard_config": 1}
    features = {k: True for k in FEATURES}
    features.update(config.get("features", {}))
    init = {"method": config.get("init", {}).get("method", DEFAULT_INIT["method"]),
            "args": config.get("init", {}).get("args", DEFAULT_INIT["args"])}
    methods = {r: r for r in ROLES}
    shapes = {k: v[0] for k, v in CHOICES.items()}
    deposits = dict(DEFAULT_DEPOSITS)
    for src in (config, mapping or {}):
        methods.update(src.get("methods", {}))
        shapes.update(src.get("shapes", {}))
        deposits.update(src.get("deposits", {}))
    exported = set(wasm_methods)
    problems = []
    if init["method"] not in exported:
        problems.append(f"init: the guard has no method `{init['method']}`. Set init.method in your config to your init method's name.")
    explicit = set((mapping or {}).get("methods", {})) | set(config.get("methods", {}))
    for role in ROLES:
        name = methods[role]
        if name in exported:
            continue
        if role in required_roles(features):
            problems.append(f"{role}: the guard has no method `{name}`. Arena needs the method for this role ({ROLE_HELP[role]}). "
                            f"Map it with \"methods\": {{\"{role}\": \"<your method>\"}}.")
        elif role in explicit:
            problems.append(f"{role}: the mapping names `{name}`, but the guard has no such method.")
    seen = {}
    for role, name in methods.items():
        if name in seen:
            problems.append(f"methods: `{name}` is mapped to both {seen[name]} and {role}; each role needs its own method.")
        seen[name] = role
    if init["method"] in seen:
        problems.append(f"methods: the init method `{init['method']}` cannot also be the {seen[init['method']]} method.")
    if problems:
        problems.append("Methods your wasm exports: " + (", ".join(sorted(exported)) or "none"))
    resolved = {"arena_guard_config": 1, "init": init, "features": features, "methods": methods,
                "shapes": shapes, "deposits": deposits}
    return resolved, problems


def renamed_roles(resolved):
    return {r: n for r, n in resolved["methods"].items() if r != n}


def missing_roles(resolved, wasm_methods):
    """Optional roles whose method the guard does not export. Arena still sends calls by the
    default name (an attack may try them); a call answered "no such method" tests nothing, so
    such attacks are counted as not applicable and the list is shown in every output."""
    exported = set(wasm_methods)
    return [r for r in ROLES if resolved["methods"][r] not in exported]
