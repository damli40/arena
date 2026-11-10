"""Turn harness failures into plain words that say what to fix.

The harness logs NEAR's own error text (e.g. `MethodResolveError(MethodNotFound)`,
`Smart contract panicked: owner only`). These functions match the few cases a guard author
hits first and say what to change. Anything unmatched is passed through with the log's path,
never hidden.
"""
import json, pathlib, re

ROOT = pathlib.Path(__file__).resolve().parents[2]


class CheckError(RuntimeError):
    """A reason the check could not run, already in plain words."""


def _panic(text):
    m = re.search(r"Smart contract panicked: ([^\"\\]{1,300})", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"ExecutionError\(\\?\"([^\"\\]{1,300})", text)
    return m.group(1).strip() if m else None


def _setup_step(text):
    m = re.search(r"SETUP STEP (\w+): ([^\n]{0,200})", text)
    return (m.group(1), m.group(2)) if m else (None, None)


def from_text(text, log_path=None):
    """Plain-words reason from harness output. Returns a string (never empty)."""
    where = f" Full log: {log_path}" if log_path else ""
    step, what = _setup_step(text)
    p = _panic(text)
    m = re.search(r"(CompilationError|PrepareError)[^\n]{0,160}", text)
    if m:
        return ("NEAR could not load your wasm (" + m.group(0) + "). Build it for wasm32-unknown-unknown with a Rust "
                "version NEAR's VM accepts (Arena uses 1.86)." + where)
    if "MethodNotFound" in text:
        return (f"{(what or 'A call')} : the guard has no method with that name (NEAR said MethodNotFound). "
                "Check the method names in your config/mapping against the guard's exported methods (listed in the report)." + where)
    if p and "doesn't accept deposit" in p:
        return (f"{what or 'A call'}: the guard refuses an attached deposit ({p}). Set \"deposits\": {{\"{step or '<method role>'}\": 0}} in your mapping." + where)
    if p and "attached deposit" in p.lower():
        return (f"{what or 'A call'}: the guard requires an attached deposit ({p}). Set \"deposits\": {{\"{step or '<method role>'}\": 1}} in your mapping." + where)
    if p and ("deserialize" in p.lower() or "missing field" in p.lower() or "unknown variant" in p.lower() or "invalid type" in p.lower()):
        return (f"{what or 'A call'}: the guard could not read the arguments Arena sent ({p}). "
                "Check init.args in your config, or the argument-shape choices (\"shapes\") in your mapping." + where)
    if step == "init":
        return (f"{what}: {p or 'it failed'}. Check init.method and init.args in your config; "
                "Arena fills $owner, $agent and $token with its own sandbox accounts." + where)
    if step:
        return (f"Setup failed at {step}: {what} ({p or 'no panic message'}). "
                "Check that your init args put Arena's owner in the owner role ($owner), and the deposits in your mapping." + where)
    if "SCORING:" in text:
        m = re.search(r"SCORING: ([^\n]{0,300})", text)
        return (f"{m.group(1)}. Arena reads each invoice's status through get_invoice to score; map get_invoice and its "
                "status field (shapes.status_field, shapes.paid_value)." + where)
    if "timeout after" in text:
        return "The attempt ran out of time (240 s) and was stopped; it is not counted as held." + where
    tail = " | ".join(text.strip().splitlines()[-3:])[:400]
    return f"The harness stopped with an error it does not explain: {tail}." + where


def attempt_error(why, log_path):
    text = why or ""
    if log_path and pathlib.Path(log_path).exists():
        text = pathlib.Path(log_path).read_text(errors="replace")[-20000:] + "\n" + text
    return from_text(text, log_path)


def preflight(cell, out, resolved):
    """None if the honest payment worked; else a plain reason. `cell` is runner.run_one's result."""
    log = ROOT / cell["log"] if not pathlib.Path(cell["log"]).is_absolute() else pathlib.Path(cell["log"])
    if cell["status"] == "error":
        why = attempt_error(cell.get("why"), log)
        return "Preflight (one honest payment) could not run. " + why[:1].upper() + why[1:]
    rj = ROOT / cell["result_json"] if not pathlib.Path(cell["result_json"]).is_absolute() else pathlib.Path(cell["result_json"])
    r = json.loads(rj.read_text())
    if cell.get("honest_settled", 0) >= 1 and cell.get("unauthorised", 0) == 0:
        return None
    pay_name = resolved["methods"]["pay"]
    pays = [s for s in r.get("steps", []) if s.get("method") == "pay"]
    sam = next((int(e["received"]) for e in r["final"]["received"] if e["receiver"] == "sam"), 0)
    status = next((s["status"] for s in r["final"]["invoice_statuses"] if s["id"] == "inv-pay"), "null")
    head = (f"Preflight failed: Arena approved one 100-token invoice (inv-pay, to sam) and the agent called `{pay_name}` once. ")
    if pays and not pays[0]["success"]:
        return head + f"The call failed: {from_text(pays[0].get('failure', ''), log)}"
    logs = " ".join(" ".join(s.get("logs", [])) for s in pays)
    if sam == 0 and "ft_transfer" not in logs:
        return head + (f"The call succeeded, but no ft_transfer was seen and sam got 0 tokens. Arena scores only NEP-141 "
                       f"tokens: `{pay_name}` must call ft_transfer on the token account it was given at init ($token). "
                       f"If `{pay_name}` is not your pay method, fix methods.pay in your mapping. Log: {log}")
    if status == "Paid-unmapped":
        status = "Paid"  # adapter.rs marks a "Paid" that is not the chosen paid value; show what the guard said
    if sam == 100 and status != "Paid" or sam == 100 and resolved["shapes"]["paid_value"] != "Paid" and status == "Paid":
        return head + (f"sam got the 100 tokens, but the guard's invoice status reads {status!r}, which is not the paid value Arena was told to expect. Arena reads "
                       f"get_invoice (`{resolved['methods']['get_invoice']}`) field {resolved['shapes']['status_field']!r} and "
                       f"expects {resolved['shapes']['paid_value']!r}. Fix shapes.status_field / shapes.paid_value in your mapping. Log: {log}")
    return head + (f"Expected sam to get exactly 100 with the invoice marked paid; got sam={sam}, status={status!r}, "
                   f"beyond policy={cell.get('unauthorised')}. A guard that cannot pay one honest invoice cannot be scored. Log: {log}")
