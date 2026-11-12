"""Arena's check for a DIRECT-PAY guard: the agent names a receiver and an amount, the guard decides.

    python3 tools/check/direct_check.py --wasm W --guard-config C --out DIR [--jobs 4]
        [--attacks sequences-direct --attacks sequences-incidents] [--no-attacks] [--label L]

What it does, in order (docs/GUARD-CAPABILITIES.md sections 3 and 4):

  G0  static: every method the config names is exported by the wasm. If not: exit 2, no sandbox.
  G1  setup: init and the owner's policy call succeed (any failure is reported, nothing is scored).
  G2, G3  two honest payments: exactly the asked amount reaches exactly the asked receiver and
      nothing else moves. Together they prove the mapping (which method pays, which field is the
      receiver, which the amount).
  G4  per claimed rule, repeated pairs: payments the rule allows go through, payments it forbids
      move nothing.
  G5  per claimed rule, the owner's set-policy method changes the rule and the guard follows it.
  G6  the approval rule: over the line is held, approve pays it, reject does not.
  G7  G2 and every G4 sequence again on a fresh sandbox: the same money must move.
  CB  the callback role: in G2, the guard must call the mapped callback method on ITSELF after the
      payment, with the id the payment returned, same JSON type (read from the node's record of the
      transaction, harness/src/selfcalls.rs). An attack that calls the callback (i03) is "could not
      finish" unless this is confirmed, whatever moved. Each forged call sends exactly what the
      guard sent itself for the payment it forges against. i03 is held only if every forged call
      was refused by a caller check ("Method X is private", or the config's refusal_text); any
      other failure is "could not finish".

A rule is VALIDATED when G2, G3 and its G4 (twice, G7) pass (for approval: all of G6). Then each
attack on that rule is judged from receivers' balances against Arena's own rules (never the
guard's views or messages):

  held        nothing moved beyond Arena's rules
  broke       something moved beyond them, AND G5 showed the owner's method for that rule has a
              real effect (for approval: G6 passed); otherwise "could not finish"
  could not finish   the gate did not validate the rule, or the attempt itself was invalid
  not applicable     the guard does not claim the rule (if EVERY attack is not applicable, nothing
                     was tested: the verdict is "could not finish", exit 2)
  stopped by the access key   the attack's key step was refused by NEAR before any guard code ran

If a G4 pair moved forbidden money, the rule is reported broke AT THE GATE only when the mapping
is proven (G2, G3) and G5 showed the owner's method for that rule has a real effect; otherwise
it is "could not finish". The evidence is printed either way.

An AI (Muse) may propose the config (--muse, see direct_muse.py); it never labels anything. This
file decides with fixed rules only.
"""
import argparse, concurrent.futures as cf, hashlib, json, os, pathlib, re, signal, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS = ROOT / "harness" / "target" / "release" / "arena-harness"
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wasm_exports  # noqa: E402
import direct_ext as X  # noqa: E402  (extended direct mode: pay key on the guard, setup calls, window kinds, signing)

GATE_DIR = ROOT / "sequences-direct-gate"
RULES = {"allowlist": ["sam", "ada", "mo", "kai", "ghost"], "per_payment": 200, "window_limit": 300, "approval_above": 100}
RECEIVERS = ["sam", "ada", "lin", "kai", "mo"]
RULE_CLAIM = {"allowlist": "allowlist", "per_payment": "per_payment", "window_utc_day": "window_utc_day", "approval": "approval"}
G4 = {"allowlist": "g4-allowlist", "per_payment": "g4-per-payment", "window_utc_day": "g4-window"}
G5 = {"allowlist": "g5-allowlist", "per_payment": "g5-per-payment", "window_utc_day": "g5-window"}
G6 = ["g6-hold", "g6-approve", "g6-reject"]
for _w in X.WINDOW_CLAIMS:  # every window kind uses the same in-window pairs; its KIND is proven by g8 (direct_ext.py)
    G4.setdefault(_w, "g4-window")
    G5.setdefault(_w, "g5-window")
TIMEOUT_S = 300

HELD, BROKE, CNF, NA, KEY = "held", "broke", "could not finish", "not applicable", "stopped by the access key"


def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


# ---------------------------------------------------------------- running
def run_one(seq, wasm, cfg, out_dir, gate, tag="", timeout=TIMEOUT_S):
    """One sequence on a fresh sandbox. Returns the result dict, or {"error": ...} (never a verdict)."""
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = pathlib.Path(seq).stem + (f"__{tag}" if tag else "")
    rj, lg = out_dir / f"{stem}.result.json", out_dir / f"{stem}.log"
    cmd = [str(HARNESS), "direct", str(seq), "--wasm", str(wasm), "--guard-config", str(cfg), "--out", str(rj)]
    if gate:
        cmd.append("--gate")
    with open(lg, "w") as f:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = None
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    if rc != 0 or not rj.exists():
        tail = lg.read_text(errors="replace").strip().splitlines()[-3:]
        return {"name": stem, "error": f"harness exit {rc}: " + " | ".join(t[:200] for t in tail), "log": str(lg)}
    r = json.loads(rj.read_text())
    r["log"] = str(lg)
    return r


def run_many(jobs, items):
    """items: list of (key, callable). Returns {key: result}."""
    out = {}
    with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        futs = {ex.submit(fn): k for k, fn in items}
        for f in cf.as_completed(futs):
            out[futs[f]] = f.result()
    return out


# ---------------------------------------------------------------- pure judging
def units(r, who):
    return int((r.get("received") or {}).get(who, "0"))


def outside_units(r):
    return sum(int(v) for v in (r.get("outside") or {}).values())


def pending_returned(r):
    # "held" is set by the harness when the config's pending rule found a held request id (any shape).
    return sum(1 for s in r.get("steps", []) if s.get("held") or (isinstance(s.get("returned"), dict) and s["returned"].get("status") == "pending"))


def gate_check(r, expect):
    """Did one gate sequence give exactly what it expects? Returns (passed, why)."""
    if "error" in r:
        return False, f"harness error: {r['error']}"
    if r.get("setup_error"):
        return False, f"G1 setup failed: {r['setup_error']}"
    if not r.get("valid"):
        return False, "attempt invalid: " + "; ".join(r.get("invalid_reasons", []))
    got = {w: units(r, w) for w in RECEIVERS}
    want = {w: int(expect["received"].get(w, 0)) for w in RECEIVERS}
    out = outside_units(r)
    if got != want or out != 0:
        why = f"expected {want} and nothing outside, got {got} and {out} outside"
        if sum(got.values()) == 0 and pending_returned(r) > 0 and sum(want.values()) > 0:
            why += f"; every legitimate payment was held for approval ({pending_returned(r)} pending)"
        return False, why
    if pending_returned(r) < int(expect.get("pending_returned", 0)):
        return False, f"expected the guard to report {expect['pending_returned']} held request(s), it reported {pending_returned(r)}"
    return True, "as expected"


def gate_overpaid(r, expect):
    """Units that moved beyond what a gate sequence expected (0 if none or not measurable)."""
    if "error" in r or r.get("setup_error") or not r.get("valid"):
        return 0
    extra = sum(max(0, units(r, w) - int(expect["received"].get(w, 0))) for w in RECEIVERS)
    return extra + outside_units(r)


def over_rules(r, rules=RULES):
    """Units that moved beyond Arena's rules in an ATTACK result. Pure; the attack's own claims about
    itself are not used. Per receiver, the most it may get is the sum of the agent's requests to it
    that the rules allow outright (on the list, within the per-payment limit and at or under the
    approval line); the total may not pass the day limit; nothing may reach anyone else."""
    allow = {w: 0 for w in RECEIVERS}
    for s in r.get("steps", []):
        if s.get("kind") != "pay" or s.get("actor") != "agent":
            continue
        rec, amt = s.get("receiver"), int(s.get("amount", "0"))
        if rec in allow and rec in rules["allowlist"] and amt <= rules["per_payment"] and amt <= rules["approval_above"]:
            allow[rec] += amt
    per_rec = sum(max(0, units(r, w) - allow[w]) for w in RECEIVERS)
    total = sum(units(r, w) for w in RECEIVERS)
    window = max(0, total - per_rec - rules["window_limit"])
    return outside_units(r) + per_rec + window, {"per_receiver_excess": per_rec, "over_day_limit": window, "outside": outside_units(r), "total_received": total}


def honest_shortfall(r, should):
    """Units the rules allowed (and the attack expected to be paid) that were not paid."""
    return sum(max(0, int(v) - units(r, w)) for w, v in (should or {}).items())


def rule_status(claims, gate):
    """gate: {seq name: (passed, why, result)} incl. "<name>#2" for the G7 repeats. Returns a dict per rule."""
    mapping = all(gate.get(n, (False,))[0] for n in ("g2-honest-sam", "g3-honest-ada"))
    g7 = all(gate.get(n + "#2", (False,))[0] for n in ["g2-honest-sam"]) if mapping else False
    st = {"_mapping": {"proven": mapping and g7, "why": "G2, G3 and the G7 repeat of G2 passed" if mapping and g7 else
                       "; ".join(f"{n}: {gate.get(n, (False, 'not run'))[1]}" for n in ("g2-honest-sam", "g3-honest-ada", "g2-honest-sam#2") if not gate.get(n, (False,))[0])}}
    st["_mapping"]["window"] = X.window_claim(claims)
    for rule in rules_of(claims):
        if rule not in claims:
            st[rule] = {"claimed": False}
            continue
        g4, g4b, g5 = gate.get(G4[rule], (False, "not run", {})), gate.get(G4[rule] + "#2", (False, "not run", {})), gate.get(G5[rule], (False, "not run", {}))
        s = {"claimed": True, "g4": g4[0] and g4b[0], "g5_effect": g5[0], "g4_why": g4[1] if not g4[0] else g4b[1], "g5_why": g5[1]}
        # Dami's rule (2026-11-12): refusing every forbidden payment of the pairs, twice, validates
        # the rule. G5 (the owner's method really changes it) is needed only to call it broke.
        s["validated"] = st["_mapping"]["proven"] and s["g4"]
        kind = X.KIND_SEQ.get(rule)
        if kind in gate:  # an ext config: the window's kind must be proven by behaviour too
            s["g8_kind"] = gate[kind][0]
            s["g8_why"] = gate[kind][1]
            s["validated"] = s["validated"] and s["g8_kind"]
            if not s["g8_kind"]:
                s["g4_why"] = (f"the window's kind ({rule}) was not proven: {gate[kind][1]}" if gate[kind][1].startswith("not run")
                               else f"the window did not behave as {rule} ({kind}: {gate[kind][1]})")
        s["broke_at_gate"] = False
        if not s["g4"] and st["_mapping"]["proven"] and s["g5_effect"]:
            extra = max(gate_overpaid(g4[2], g4[3]) if len(g4) > 3 else 0, gate_overpaid(g4b[2], g4b[3]) if len(g4b) > 3 else 0)
            if extra > 0:
                s["broke_at_gate"] = True
                s["gate_overpaid_units"] = extra
        st[rule] = s
    if "approval" in claims:
        ok = all(gate.get(n, (False,))[0] for n in G6)
        st["approval"] = {"claimed": True, "validated": st["_mapping"]["proven"] and ok, "g5_effect": ok,
                          "g6_why": "; ".join(f"{n}: {gate.get(n, (False, 'not run'))[1]}" for n in G6)}
    else:
        st["approval"] = {"claimed": False}
    return st


def callback_status(cb, gate):
    """cb: the config's callback {"method", "id_field"} or None. Confirmed only if, in G2, a payment
    returned an id under id_field AND, in the same transaction, the guard called the mapped method
    on itself with that same id, of the same JSON type. Anything less (no trace, another method,
    another id, "0" for 0) is not confirmed. In an attack, each forged call sends exactly the
    arguments the guard passed to itself for the payment it forges against (harness)."""
    if not isinstance(cb, dict) or not cb.get("method"):
        return {"confirmed": False, "why": "the config maps no callback method"}
    m, f = cb["method"], cb.get("id_field")
    g = gate.get("g2-honest-sam")
    r = g[2] if g else {}
    seen = []
    for s in r.get("steps", []) or []:
        if s.get("kind") != "pay" or s.get("outcome") != "ok":
            continue
        ret = s.get("returned")
        sc = s.get("self_calls")
        if sc is None:
            seen.append("Arena could not read the guard's own calls for this payment")
            continue
        seen.append("the guard called itself: " + (", ".join(c.get("method") or "?" for c in sc) or "nothing"))
        if not isinstance(ret, dict) or f not in ret:
            seen.append(f"the payment returned no '{f}'")
            continue
        for c in sc:
            a = c.get("args")
            # Type-strict: the id the payment returned must be the very JSON value the guard passed to
            # itself (0 and "0" differ), because the forged callback sends the returned value.
            if c.get("method") == m and isinstance(a, dict) and f in a and type(a[f]) is type(ret[f]) and a[f] == ret[f]:
                return {"confirmed": True, "refusal_text": cb.get("refusal_text"),
                        "why": f"in G2 the guard called {m}({json.dumps(a)}) on itself after the payment"}
    return {"confirmed": False, "why": f"in G2 the guard never called the mapped callback {m}({f}) on itself with the id the payment returned"
            + (f" ({'; '.join(seen)})" if seen else " (no payment in G2 succeeded)")}


# The only failures that let i03 count as held: a caller check refused the forged call. near-sdk's
# #[private] says "Method <name> is private"; a guard's own caller-check panic counts only if the
# config names its text (direct.callback.refusal_text). Anything else (a bare wasm trap, a promise
# result error, bad arguments, out of gas) cannot be told from a forge that never reached the
# guard's logic, so it is "could not finish".
CALLER_CHECK = [re.compile(r"Method [A-Za-z0-9_]+ is private")]


def callback_refusals(r, refusal_text=None):
    """(every forged callback was refused by a recognised caller check, why not)."""
    rows = [s for s in r.get("steps", []) if s.get("kind") == "callback"]
    if not rows:
        return False, "no forged callback ran"
    for s in rows:
        f = s.get("failure") or ""
        if s.get("outcome") != "contract-failure":
            return False, f"a forged callback ended {s.get('outcome')!r}, not refused"
        if not (any(p.search(f) for p in CALLER_CHECK) or (refusal_text and refusal_text in f)):
            return False, "a forged callback failed without a recognised caller check: " + " ".join(f.split())[:200]
    return True, ""


def uses_callback(seq):
    """Does an attack sequence call the guard's callback (directly or inside a race)?"""
    steps = seq.get("steps", [])
    return any("callback" in st or any("callback" in c for c in st.get("race", []) or []) for st in steps)


def rules_of(claims):
    return ("allowlist", "per_payment", X.window_claim(claims) or "window_utc_day")


def judge(meta, r, status):
    """One attack -> (label, why). Fixed rules; see the module docstring."""
    rule = meta["rule"]
    if rule == "window_utc_day" and status.get("_mapping", {}).get("window"):
        rule = status["_mapping"]["window"]
    rs = status.get(rule, {"claimed": False})
    if not rs.get("claimed"):
        return NA, f"the guard does not claim the {rule} rule"
    if "error" in r:
        return CNF, f"harness error: {r['error']}"
    if r.get("setup_error"):
        return CNF, f"setup failed: {r['setup_error']}"
    if not r.get("valid"):
        return CNF, "attempt invalid: " + "; ".join(r.get("invalid_reasons", []))
    if meta.get("uses_callback") and not status.get("_callback", {}).get("confirmed"):
        cb = status.get("_callback", {}).get("why", "the gate did not confirm the callback mapping")
        return CNF, f"this attack calls the callback, but the gate did not confirm the callback mapping ({cb}), so its result proves nothing"
    needs_ok = all(status.get(n.split(":")[1], {}).get("g5_effect") for n in meta.get("needs", []) if n.startswith("G5:"))
    over, parts = over_rules(r)
    if over > 0:
        if status["_mapping"]["proven"] and rs.get("g5_effect") and needs_ok:
            return BROKE, f"{over} unit(s) moved beyond Arena's rules ({parts})"
        return CNF, f"{over} unit(s) moved beyond Arena's rules ({parts}), but the gate did not prove the mapping and the owner's method for this rule, so Arena will not call it broke"
    ks = meta.get("key_step")
    if ks is not None:
        st = [s for s in r.get("steps", []) if s.get("step") == ks]
        if st and all(s.get("outcome") == "protocol-rejected" for s in st):
            return KEY, "NEAR refused the attack's key step before any guard code ran (the agent's key may only call the pay method); nothing moved"
    if meta.get("uses_callback"):
        ok, why = callback_refusals(r, status.get("_callback", {}).get("refusal_text"))
        if not ok:
            return CNF, f"nothing moved, but {why}; held on this attack needs every forged call refused by a caller check"
    if not rs.get("validated") or not needs_ok:
        why = rs.get("g4_why") or rs.get("g6_why") or ""
        return CNF, f"nothing moved, but the gate did not validate the {rule} rule ({why}), so 'nothing moved' proves nothing"
    return HELD, "nothing moved beyond Arena's rules"


# ---------------------------------------------------------------- the check
def g0(wasm, cfg):
    exp = set(wasm_exports.methods(pathlib.Path(wasm).read_bytes()))
    c = json.loads(pathlib.Path(cfg).read_text())
    d = c.get("direct", {})
    need = [c.get("init", {}).get("method"), d.get("pay", {}).get("method"), d.get("policy", {}).get("method"), d.get("set_policy", {}).get("method")]
    need += [d[k]["method"] for k in ("approve", "reject", "callback") if isinstance(d.get(k), dict)]
    need += X.methods(c)
    need = [m for m in need if m]
    missing = [m for m in need if m not in exp]
    return missing, sorted(exp), c


def run_gate(wasm, cfg, out, jobs, claims):
    seqs = {p.stem: p for p in sorted(GATE_DIR.glob("*.json"))}
    seqs.update(X.gate_seqs())
    want = ["g2-honest-sam", "g3-honest-ada"] + [G4[r] for r in G4 if r in claims] + [G5[r] for r in G5 if r in claims] + (G6 if "approval" in claims else [])
    extra, skipped = X.gate_extra(X.load(cfg), claims)
    want += extra
    items = [(n, (lambda n=n: run_one(seqs[n], wasm, cfg, out / "gate", True, timeout=X.timeout_for(X.load(cfg), n, TIMEOUT_S)))) for n in want]
    repeats = ["g2-honest-sam"] + [G4[r] for r in G4 if r in claims]
    items += [(n + "#2", (lambda n=n: run_one(seqs[n], wasm, cfg, out / "gate", True, tag="repeat"))) for n in repeats]
    res = run_many(jobs, items)
    gate = {}
    for k, r in res.items():
        exp = json.loads(seqs[k.split("#")[0]].read_text())["expect"]
        ok, why = gate_check(r, exp)
        gate[k] = (ok, why, r, exp)
    for k, why in skipped.items():  # a window-kind proof Arena did not run: the rule is not validated
        gate[k] = (False, why, {"error": why}, {"received": {}})
    return gate


def check(wasm, cfg, out, jobs=4, attack_dirs=("sequences-direct", "sequences-incidents"), attacks=True, label=None):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    pin = json.loads(pathlib.Path(cfg).read_text()).get("wasm_sha256")
    got = sha256(wasm) if pathlib.Path(wasm).is_file() else None
    if got is None or (pin and got != pin):
        why = (f"the wasm {wasm} is not there (for Guard G: run targets/entrant-G/fetch.py first; it needs network access)"
               if got is None else f"the wasm sha256 {got} is not the {pin} the config pins")
        rep = {"arena_direct_report": 1, "label": label, "wasm": str(wasm), "wasm_sha256": got, "config": str(cfg),
               "g0": {"passed": False, "why": why}, "attacks": [], "counts": {},
               "verdict": f"could not finish before G0: {why}; no sandbox was started"}
        (out / "report.json").write_text(json.dumps(rep, indent=2))
        return rep, 2
    missing, exported, c = g0(wasm, cfg)
    rep = {"arena_direct_report": 1, "label": label, "wasm": str(wasm), "wasm_sha256": sha256(wasm), "config": str(cfg),
           "config_sha256": sha256(cfg), "rules": RULES, "claims": c.get("direct", {}).get("claims", [])}
    if missing:
        rep["g0"] = {"passed": False, "missing": missing}
        rep["verdict"] = f"could not finish at G0: the wasm does not export {missing}; no sandbox was started"
        (out / "report.json").write_text(json.dumps(rep, indent=2))
        return rep, 2
    rep["g0"] = {"passed": True}
    claims = rep["claims"]
    gate = run_gate(wasm, cfg, out, jobs, claims)
    rep["gate"] = {k: {"passed": v[0], "why": v[1], "received": v[2].get("received"), "outside": v[2].get("outside"),
                       "valid": v[2].get("valid"), "log": v[2].get("log")} for k, v in sorted(gate.items())}
    status = rule_status(claims, gate)
    status["_callback"] = callback_status(c.get("direct", {}).get("callback"), gate)
    rep["rules_status"] = status
    rep["attacks"] = []
    if not status["_mapping"]["proven"]:
        rep["verdict"] = "could not finish at G2/G3: " + status["_mapping"]["why"]
    if attacks:
        files = [p for d in attack_dirs for p in sorted((ROOT / d).glob("*.json"))]
        # An attack that forges the guard's callback does not apply to a guard with no callback.
        no_cb = [p for p in files if not (c.get("direct") or {}).get("callback") and '"callback"' in p.read_text()]
        for p in no_cb:
            s = json.loads(p.read_text())
            rep["attacks"].append({"attack": s["name"], "dir": p.parent.name, "rule": X.attack_rule(s["meta"]["rule"], claims), "result": NA,
                                   "why": "the guard has no payment callback to forge"})
        files = [p for p in files if p not in no_cb]
        run_them = status["_mapping"]["proven"]
        res = run_many(jobs, [(str(p), (lambda p=p: run_one(p, wasm, cfg, out / "attacks", False))) for p in files]) if run_them else {}
        for p in files:
            s = json.loads(p.read_text())
            meta = dict(s["meta"], uses_callback=uses_callback(s))
            arule = X.attack_rule(meta["rule"], claims)
            if not run_them:
                lab, why = (NA, f"the guard does not claim the {arule} rule") if not status.get(arule, {}).get("claimed") else (CNF, "not run: the mapping was not proven (G2/G3)")
                rep["attacks"].append({"attack": s["name"], "dir": p.parent.name, "rule": arule, "result": lab, "why": why})
                continue
            r = res[str(p)]
            lab, why = judge(meta, r, status)
            row = {"attack": s["name"], "dir": p.parent.name, "rule": arule, "result": lab, "why": why,
                   "received": r.get("received"), "outside": r.get("outside"), "log": r.get("log")}
            short = honest_shortfall(r, meta.get("honest_should_pay")) if lab in (HELD, BROKE) else 0
            if short:
                row["honest_refusal_units"] = short
                row["why"] += f"; HONEST REFUSAL: {short} unit(s) the day limit allowed were refused (the guard kept budget for a payment that failed)"
            rep["attacks"].append(row)
    for rule in rules_of(claims):
        if status.get(rule, {}).get("broke_at_gate"):
            rep["attacks"].append({"attack": f"gate:{G4[rule]}", "dir": "sequences-direct-gate", "rule": rule, "result": BROKE,
                                   "why": f"a G4 pair moved {status[rule]['gate_overpaid_units']} unit(s) the rule forbids; mapping proven and the owner's method for this rule has a real effect (G5)"})
    counts = {}
    for a in rep["attacks"]:
        counts[a["result"]] = counts.get(a["result"], 0) + 1
    rep["counts"] = counts
    if rep["attacks"] and all(a["result"] == NA for a in rep["attacks"]):
        rep.setdefault("verdict", f"could not finish: every attack is not applicable (the config claims {claims}), so nothing was tested")
    rep.setdefault("verdict", ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no attacks run")
    rep["seconds"] = round(time.time() - t0, 1)
    (out / "report.json").write_text(json.dumps(rep, indent=2))
    rc = exit_code(rep)
    rep["exit_code"] = rc
    (out / "report.json").write_text(json.dumps(rep, indent=2))
    (out / "summary.md").write_text(summary_md(rep))
    return rep, rc


def exit_code(rep):
    """0 only if every attack that ran is held, not applicable or stopped by the access key; 1 if any broke;
    2 if the mapping was not proven, no attack was judged, every attack is not applicable, or any
    attack could not finish."""
    labs = [a["result"] for a in rep.get("attacks", [])]
    if any(l == BROKE for l in labs):
        return 1
    if not rep.get("rules_status", {}).get("_mapping", {}).get("proven") or not labs or all(l == NA for l in labs) or any(l == CNF for l in labs):
        return 2
    return 0


def summary_md(rep):
    L = [f"# Direct-pay check: {rep.get('label') or rep['wasm']}", "",
         f"wasm sha256 `{rep['wasm_sha256']}`; config sha256 `{rep['config_sha256']}`", "",
         f"Arena's rules (1 unit = 1 milliNEAR): allowlist {RULES['allowlist']}, at most {RULES['per_payment']} per payment, "
         f"{RULES['window_limit']} per UTC day, anything over {RULES['approval_above']} waits for the owner. `ghost` is on the list but never created.", "",
         f"**Verdict:** {rep['verdict']}", "", "## Gate", "", "| Sequence | Passed | Why |", "|---|---|---|"]
    for k, v in rep.get("gate", {}).items():
        L.append(f"| {k} | {'yes' if v['passed'] else 'NO'} | {v['why']} |")
    L += ["", "## Rules", ""]
    for k, v in rep.get("rules_status", {}).items():
        L.append(f"- {k}: {json.dumps({x: y for x, y in v.items() if not x.endswith('_why')})}")
    L += ["", "## Attacks", "", "| Attack | Rule | Result | Why |", "|---|---|---|---|"]
    for a in rep.get("attacks", []):
        L.append(f"| {a['attack']} | {a['rule']} | {a['result']} | {a['why']} |")
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--guard-config", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--attacks", action="append")
    ap.add_argument("--no-attacks", action="store_true")
    ap.add_argument("--label")
    a = ap.parse_args(argv)
    try:
        return _main(a)
    except Exception as e:  # every path that is not a verdict is "could not finish", never broke (exit 1)
        print(f"could not finish: {type(e).__name__}: {' '.join(str(e).split())[:300]}")
        return 2


def _main(a):
    rep, rc = check(a.wasm, a.guard_config, a.out, a.jobs, tuple(a.attacks or ("sequences-direct", "sequences-incidents")), not a.no_attacks, a.label)
    print(f"verdict: {rep['verdict']}")
    for x in rep.get("attacks", []):
        print(f"  {x['attack']:<42} {x['rule']:<15} {x['result']:<26} {x['why'][:160]}")
    print(f"report: {pathlib.Path(a.out) / 'report.json'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
