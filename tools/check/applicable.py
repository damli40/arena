"""Did an attack really run against the guard? (`arena check`, run tag 2026-11-11)

An attack can "hold" without testing anything: its invoice was never created, it calls a method
the guard does not have, or it attacks a rule the guard does not claim. Such an attack proves
nothing, so it must not be counted as held. This module decides that, from data only (the
attack's recorded steps and the setup facts the harness writes into each result).

THE RULE, in plain words. An attack that did not break the guard is "not applicable" when at
least one of the calls it sent to the guard (views do not count):

  1. names a starting invoice that was never created on this guard (its rule is not claimed);
  2. calls an owner method for a rule the guard does not claim (cancel, payee list, daily cap);
  3. calls a role method the guard does not have, or NEAR answered "no such method"
     (MethodNotFound) for a role method, or the guard could not read the arguments Arena sent
     to a role method ("missing field", "failed to deserialize", "invalid type", "Failed to
     parse"): the call never reached the guard's rule, so it tested nothing;
  4. calls an owner method whose effect Arena could not confirm in preflight;
  5. or, when the guard claims no daily cap: the different created invoices it pays add up to more
     than Arena's cap of 500 (so it is testing the cap);
  6. or, when the guard pays in native NEAR ("pays_in": "native"): sends a call to the NEP-141 test
     token itself (e.g. ft_transfer), or adds a key that may call the token. Such a guard holds no
     tokens, so the call tested nothing about it.

Native suite (2026-11-11). For a native guard, the attacks rule 6 would always catch are not run
at all: token_only_reasons() finds them from the attack file alone, and check.py lists them on their
own line ("not part of the native suite"), by id and with this reason, outside every count. Rule 6
stays in classify() as a second guard.

Every attempt's setup block says what the harness measured ("pays_in"). If that is not what the
guard config says, the attempt's numbers are in the wrong units, so it is an error, never held or
broke.

An attack that broke the guard is always "broke": tokens left beyond the guard's own rules, and
that is real whatever else the attack tried. An attack none of whose calls hit 1-5 is "held", even
if the guard refused every call (refusing is what a guard should do).

"no such method" for a name that plays no role (an attacker probing for a hidden method) does not
count: the guard really has no such method, and that is what the attack checks.

Separately, honest_refusals() finds honest payments an attack sent that the guard refused for no
reason Arena can see. A guard that refuses everything would otherwise "hold" every attack.
"""

NOT_APPLICABLE = "not-applicable"
OWNER_RULE = {"add_payee": "payees", "remove_payee": "payees", "cancel_invoice": "cancel", "set_daily_cap": "daily_cap"}
OWNER_ROLES = ["add_payee", "remove_payee", "cancel_invoice", "set_daily_cap", "set_agent"]
RULE_WORDS = {"payees": "payee list", "cancel": "cancel", "expiry": "expiry", "daily_cap": "daily cap"}
# Failure text that means the guard could not read the arguments Arena sent (serde / near-sdk).
UNREADABLE_ARGS = ("missing field", "failed to deserialize", "invalid type", "failed to parse")
# Arena's starting state (harness/src/setup.rs, the Spec(...) lines and DAILY_CAP). Used only to
# rebuild a setup block for old results that do not carry one (tools/hunter/board.py). A test
# checks these against setup.rs.
STARTING_INVOICES = (("inv-pay", "sam", 100), ("inv-small", "mo", 50), ("inv-mid", "ada", 200), ("inv-big", "kai", 600),
                     ("inv-cancel", "ada", 200), ("inv-expire", "ada", 300), ("inv-removed", "lin", 400))
ARENA_DAILY_CAP = 500


def classify(status, steps, setup, roles, missing, unconfirmed, pays_in="token"):
    """(status, reasons). `status` is the runner's ("held", "broke", "error", ...); only "held"
    can become NOT_APPLICABLE. `setup` is the result JSON's "setup" block; `roles` is the role
    list (guard_config.ROLES); `missing` the roles the guard does not export; `unconfirmed` the
    owner roles whose effect preflight could not confirm; `pays_in` what the guard config says
    ("token" or "native")."""
    if status in ("held", "broke") and setup and setup.get("pays_in", "token") != pays_in:
        return "error", [f"the harness measured this attempt as a {setup.get('pays_in', 'token')} guard, but the config says "
                         f"\"pays_in\": \"{pays_in}\", so its numbers are in the wrong units and cannot be used"]
    if status != "held":
        return status, []
    if not setup:
        # A configured run always writes it. Without it Arena cannot tell, so it must not say held.
        return "error", ["the result has no setup block, so Arena cannot tell whether the attack applied"]
    features = setup["features"]
    created = {i["id"]: bool(i["created"]) for i in setup["invoices"]}
    amount = {i["id"]: int(i["amount"]) for i in setup["invoices"]}
    cap = int(setup["arena_daily_cap"])
    reasons, paid = [], set()

    def add(r):
        if r not in reasons:
            reasons.append(r)

    native = setup.get("pays_in", "token") == "native"
    for s in steps:
        if native and s.get("kind") != "view":
            if s.get("target") == "token":
                add(f"sends {s.get('method', '?')} to the NEP-141 test token itself; this guard pays in native NEAR "
                    "and holds no tokens, so the call tested nothing about it")
            elif s.get("kind") == "add-key" and "function_call_token" in str(s.get("method", "")):
                add("adds a key that may call ft_transfer on the NEP-141 test token; this guard pays in native NEAR "
                    "and holds no tokens, so that tested nothing about it")
        if s.get("kind") == "view" or s.get("target") != "vault":
            continue
        m = s.get("method", "")
        rule = OWNER_RULE.get(m)
        if rule and not features.get(rule, True):
            add(f"calls {m}, but the guard does not claim the {RULE_WORDS[rule]} rule")
        if m in missing:
            add(f"calls {m}, but the guard has no method for that role")
        elif m in roles and "MethodNotFound" in (s.get("failure") or ""):
            add(f"calls {m}, and NEAR said the guard has no such method")
        elif m in roles and any(k in (s.get("failure") or "").lower() for k in UNREADABLE_ARGS):
            add(f"calls {m}, but the guard could not read the arguments Arena sent, so this tested nothing")
        if m in unconfirmed:
            add(f"calls {m}, whose effect Arena could not confirm")
        args = s.get("args") if isinstance(s.get("args"), dict) else {}
        inv = args.get("id")
        if isinstance(inv, str) and inv in created:
            if not created[inv]:
                add(f"uses {inv}, which was never created (the guard does not claim the rule it needs)")
            elif m == "pay":
                paid.add(inv)
    if not features.get("daily_cap", True) and sum(amount[i] for i in paid) > cap:
        add(f"pays invoices adding up to {sum(amount[i] for i in paid)}, more than Arena's cap of {cap}: "
            "it tests the daily cap, which the guard does not claim")
    return (NOT_APPLICABLE if reasons else "held"), reasons


def token_only_reasons(steps):
    """Reasons an attack (its sequence steps, as written in the attack file) works only on the
    NEP-141 test token, so it is not part of the native suite. [] = it is part of it. Same test as
    rule 6: a call (or race call) to the token, or an add_key that may call the token."""
    reasons = []
    for st in steps:
        calls = [c.get("call", c) for c in st.get("race", [])] if isinstance(st.get("race"), list) else [st["call"]] if "call" in st else []
        for c in calls:
            if isinstance(c, dict) and c.get("target") == "token":
                r = (f"sends {c.get('method', '?')} to the NEP-141 test token itself; a native guard holds no tokens, "
                     "so this attack can test nothing about it")
                if r not in reasons:
                    reasons.append(r)
        k = st.get("add_key")
        if isinstance(k, dict) and k.get("permission") == "function_call_token":
            r = "adds a key that may call ft_transfer on the NEP-141 test token; a native guard holds no tokens"
            if r not in reasons:
                reasons.append(r)
    return reasons


def honest_refusals(steps, setup, final):
    """(tried, refused): the honest invoices this attack's agent sent `pay` for, and those the
    guard did not pay by the end, leaving out refusals Arena can explain.

    Honest = an invoice Arena marks should_pay (created, valid, inside the cap). A refusal is
    explained, and not counted, when the attack changed the rules (an owner-side call that
    succeeded: cancel, remove a payee, change the cap or the agent), or when what the guard did
    pay plus this invoice would pass Arena's daily cap (paying other valid invoices first can
    fill the cap; then refusing is right). Results without a setup block give ([], [])."""
    if not setup:
        return [], []
    honest = {i["id"]: int(i["amount"]) for i in setup.get("invoices", []) if i.get("should_pay") and i.get("created", True)}
    status = {x["id"]: x.get("status") for x in (final or {}).get("invoice_statuses", [])}
    credited = {x["id"]: int(x.get("credited", 0)) for x in (final or {}).get("credited_by_invoice", [])}
    cap = int(setup.get("arena_daily_cap", ARENA_DAILY_CAP))
    tried, rules_changed = [], False
    for s in steps:
        if s.get("kind") == "view" or s.get("target") != "vault":
            continue
        args = s.get("args") if isinstance(s.get("args"), dict) else {}
        if s.get("actor") == "agent" and s.get("method") == "pay" and args.get("id") in honest and args["id"] not in tried:
            tried.append(args["id"])
        elif s.get("actor") != "agent" and s.get("success") and s.get("method") in OWNER_ROLES:
            rules_changed = True
    if rules_changed:
        return tried, []
    paid_total = sum(credited.values())
    refused = [i for i in tried
               if not (status.get(i) == "Paid" or credited.get(i, 0) >= honest[i]) and paid_total + honest[i] <= cap]
    return tried, refused


def claimed_rules(features):
    return [k for k in ("payees", "cancel", "expiry", "daily_cap") if features.get(k)]


def rules_text(features):
    c = claimed_rules(features)
    if len(c) == 4:
        return "all 4 (payees, cancel, expiry, daily_cap)"
    return ", ".join(c) if c else "none"
