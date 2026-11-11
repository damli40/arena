"""Write the `arena check` report: report.json, report.html (one self-contained page), badge.svg,
shields.json (a shields.io "endpoint" file), summary.md (for $GITHUB_STEP_SUMMARY).

Everything shown comes from report.json; nothing here runs or decides anything. Text from attack
files and logs is HTML-escaped, and neutralised in summary.md (an attack written by a model is
untrusted data).

The headline counts only attacks that really ran against something the guard claims ("held N/N",
"broke K of N"). Next to it, always: how many attacks were not applicable, which of the 4 rules the
guard claims, how many role methods the guard lacks, any owner method Arena could not confirm,
honest payments the guard refused, and "subset" when only some attacks ran. The preflight's honest
payment is not an attack: it has its own line and is in no count.

The badge is green only when nothing is in that list except "0 not applicable" and all 4 rules.

report.html uses the look of the Arena site (site/theme.css and the logo in site/nav.json), inlined:
the page makes no request to any other address.
"""
import html, json, os, pathlib, re, urllib.parse

RECEIPT_DOC = "docs/CHECK-YOUR-GUARD.md#publish-a-receipt"
SITE = pathlib.Path(__file__).resolve().parents[2] / "site"
RULES = ("payees", "cancel", "expiry", "daily_cap")
_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~-]+)*")
_REF_RE = re.compile(r"[0-9a-f]{7,40}|[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_SCRUB = []


def set_scrub(cwd, root, out=None):
    """Absolute folder names to strip from every output (so no local path leaks). Inside the
    current folder a path becomes relative; the report folder becomes <report>, Arena's own
    folder <arena>, the home folder ~."""
    _SCRUB.clear()
    home = str(pathlib.Path.home())
    pairs = [(str(pathlib.Path(cwd).resolve()), "."), (str(pathlib.Path(root).resolve()), "<arena>"), (home, "~")]
    if out is not None and not str(pathlib.Path(out).resolve()).startswith(pairs[0][0] + "/"):
        pairs.insert(0, (str(pathlib.Path(out).resolve()), "<report>"))
    for prefix, new in pairs:
        if prefix and prefix != "/" and all(prefix != p for p, _ in _SCRUB):
            _SCRUB.append((prefix, new))
    _SCRUB.sort(key=lambda x: -len(x[0]))


def scrub(text):
    for prefix, new in _SCRUB:
        text = text.replace(prefix + "/", "" if new == "." else new + "/").replace(prefix, new)
    return text


def scrub_files(out):
    """Strip local folder names from the run logs and results (the harness prints full paths)."""
    runs = pathlib.Path(out) / "runs"
    files = list(runs.rglob("*.log")) + list(runs.rglob("*.json")) if runs.exists() else []
    for f in files + [pathlib.Path(out) / "effects.log", pathlib.Path(out) / "effects.json"]:
        try:
            t = f.read_text(errors="replace")
        except OSError:
            continue
        n = scrub(t)
        if n != t:
            f.write_text(n)


def receipt_link():
    """Link to the receipt docs. ARENA_REPO_URL / ARENA_REPO_REF come from the environment, so
    each is used only if it is a plain https URL / a commit id or simple branch name."""
    base = os.environ.get("ARENA_REPO_URL", "").rstrip("/")
    ref = os.environ.get("ARENA_REPO_REF", "") or "main"
    if base and _URL_RE.fullmatch(base) and _REF_RE.fullmatch(ref) and ".." not in ref:
        return f"{base}/blob/{ref}/{RECEIPT_DOC}"
    return RECEIPT_DOC


def is_native(rep):
    """A guard that pays in plain NEAR ("pays_in": "native"). Its amounts in report.json are Arena
    units of 1 milliNEAR (rep["units"]); every text output shows them as NEAR."""
    return rep.get("pays_in") == "native"


def near(n):
    """Arena units (1 milliNEAR each) as exact NEAR text: 100 -> "0.1", 1500 -> "1.5", 0 -> "0"."""
    whole, frac = divmod(int(n or 0), 1000)
    return f"{whole}" + (f".{frac:03d}".rstrip("0") if frac else "")


def amt(rep, n):
    """An amount for display: the number itself for a token guard, NEAR for a native guard."""
    return near(n) if is_native(rep) else n


def noun(rep):
    return "NEAR" if is_native(rep) else "tokens"


def rules_claimed(rep, short=False):
    f = (rep.get("mapping") or {}).get("features") or {}
    c = [k for k in RULES if f.get(k)]
    if len(c) == 4:
        return "all 4" if short else "all 4 (payees, cancel, expiry, daily_cap)"
    return ", ".join(c) if c else "none"


def qualifiers(rep, short=False):
    """What must sit next to any held/broke count."""
    t = rep.get("totals") or {}
    m = rep.get("mapping") or {}
    q = []
    if t:
        q.append(f"{t.get('not_applicable', 0)} not applicable")
    if m.get("features") is not None:
        q.append(f"rules claimed: {rules_claimed(rep, short)}")
    miss = m.get("missing_roles") or []
    if miss:
        q.append(f"{len(miss)} role methods not in the guard" if short else f"not in the guard: {', '.join(miss)}")
    unc = rep.get("unconfirmed_roles") or []
    if unc:
        q.append(f"not confirmed: {', '.join(unc)}")
    if t.get("honest_refused"):
        q.append(f"refused {t['honest_refused']} of {t.get('honest_tried', '?')} honest payments")
    if t.get("paid_outside"):  # part of beyond-policy: money that left the receivers' circle (conserve.rs)
        q.append(f"{amt(rep, t['paid_outside'])} {noun(rep)} outside the receivers" if short
                 else f"{amt(rep, t['paid_outside'])} {noun(rep)} paid outside the five receivers")
    if t.get("against_intent"):  # allowed by the guard's rules, not what the owner meant: keeps the badge from green
        if is_native(rep):
            q.append(f"{near(t['against_intent'])} NEAR against intent" if short else f"{near(t['against_intent'])} NEAR paid against the owner's intent")
        else:
            q.append(f"{t['against_intent']} against intent" if short else f"{t['against_intent']} tokens paid against the owner's intent")
    if is_native(rep):
        q.append("native NEAR" if short else "scored from NEAR balances")
    only = rep.get("only")
    if only:
        if isinstance(only, dict):
            q.append(f"subset: {only.get('ran', '?')} of {only.get('of', '?')} attacks")
        else:
            q.append("subset: only some attacks ran")
    probs = (rep.get("library") or {}).get("problems")
    if probs:
        q.append(f"{len(probs)} attack files could not be loaded")
    return q


def _status(rep):
    """A report that says "held" or "broke" while some attack files could not be loaded is
    shown as incomplete (check.py stops before this; this is a second guard)."""
    st = rep["status"]
    if st in ("held", "broke") and (rep.get("library") or {}).get("problems"):
        return "incomplete"
    return st


def badge_text(rep, short=True):
    t = rep.get("totals")
    q = qualifiers(rep, short)
    tail = f" ({'; '.join(q)})" if q else ""
    status = _status(rep)
    if status == "held":
        return (f"held {t['ran']}/{t['ran']}{tail}",) + (("brightgreen", "#2e7d32") if full_marks(rep) else ("yellow", "#8d6e00"))
    if status == "broke":
        return f"broke {t['broke']} of {t['ran']}{tail}", "red", "#c62828"
    if status == "incomplete":
        return f"incomplete{tail}", "lightgrey", "#757575"
    return "not run", "lightgrey", "#757575"


def full_marks(rep):
    """Green badge: held, nothing in the brackets but "0 not applicable" and all 4 rules, and 0
    tokens paid against the owner's intent in the attacks that ran (docs/CHECK-YOUR-GUARD.md says
    so). Anything missing, unconfirmed, refused, skipped or paid against intent: yellow."""
    t = rep.get("totals") or {}
    features = (rep.get("mapping") or {}).get("features") or {}
    return (_status(rep) == "held" and t.get("not_applicable", 0) == 0 and not t.get("honest_refused")
            and not t.get("against_intent")
            and not rep.get("unconfirmed_roles") and not rep.get("only")
            and not (rep.get("mapping") or {}).get("missing_roles")
            and all(features.get(k) for k in RULES))


def headline(rep):
    """The long form (console, summary.md, report.html): role names in full."""
    return badge_text(rep, short=False)[0]


def commit_text(rep):
    """The Arena commit for a one-line display: 12 characters of a real id, or the whole plain
    phrase (never cut mid-phrase)."""
    a = rep.get("arena") or {}
    c = str(a.get("commit") or "unknown")
    src = a.get("commit_source", "git")
    if re.fullmatch(r"[0-9a-f]{40}", c):
        return c[:12] if src == "git" else f"{c[:12]} ({src})"
    return f"{c} ({src})" if src != "git" else c


def md(text):
    """Untrusted text for one markdown table cell or line: no backticks, pipes, newlines, or
    markup that could start a heading, image or link."""
    text = re.sub(r"\s+", " ", re.sub(r"[`|\r\n]", " ", str(text))).strip()[:300]
    return re.sub(r"([\\*_\[\]<>!#~])", r"\\\1", text)  # backslash-escaped: shown as typed, never markup


def fence(text):
    """A code fence longer than any run of backticks in `text`, so the text cannot close it."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def badge_svg(msg, hexcolor, label="arena"):
    w = lambda s: int(len(s) * 6.6 + 12)  # approx width of 11px Verdana
    lw, mw = w(label), w(msg)
    e = html.escape
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + mw}" height="20" role="img" aria-label="{e(label)}: {e(msg)}">'
            f'<title>{e(label)}: {e(msg)}</title><clipPath id="r"><rect width="{lw + mw}" height="20" rx="3"/></clipPath>'
            f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{mw}" height="20" fill="{hexcolor}"/></g>'
            f'<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw / 2}" y="14">{e(label)}</text><text x="{lw + mw / 2}" y="14">{e(msg)}</text></g></svg>\n')


def _plain_lines(rep):
    """Lines every text output carries (console, summary.md): counts and what was not tested."""
    out = []
    t = rep.get("totals")
    c = rep.get("control")
    if c:
        out.append(f"honest payment: {c.get('result', 'settled')} (the preflight check, not an attack; not in any count)")
    if t:
        out += [f"{noun(rep)} paid beyond the guard's own rules: {amt(rep, t['beyond_policy'])} (over the {t['ran']} attacks that ran; any value above 0 is a guard failure)",
                f"{noun(rep)} paid against the owner's intent: {amt(rep, t['against_intent'])} (on the {t['intent_attacks']} attacks that ran and have a written intent; "
                f"the guard's rules allowed these payments){_by_source(t, rep)}",
                f"attacks: {t['held']} held, {t['broke']} broke, {t.get('not_applicable', 0)} not applicable, {t['errors']} did not finish"]
        if t.get("paid_outside"):
            out.append(f"paid outside the five receivers: {amt(rep, t['paid_outside'])} {noun(rep)} of the amount beyond the rules went to the agent, "
                       "the outsider or an account the attack named (no rule lets the guard pay them)")
        if t.get("against_intent_not_applicable"):
            out.append(f"not counted: {amt(rep, t['against_intent_not_applicable'])} {noun(rep)} paid against the owner's intent in attacks that were not applicable "
                       "(they tested nothing the guard claims)")
        if "honest_tried" in t:
            out.append(honest_line(t))
    nis = rep.get("not_in_suite") or []
    if nis:
        out.append(f"not in the native suite: {len(nis)} token-only {'attack' if len(nis) == 1 else 'attacks'} "
                   f"({', '.join(d['id'] for d in nis)}). They send calls to the NEP-141 test token, which a native guard does not use, "
                   "so they are not run and not in any count")
    if is_native(rep):
        out.append("paid in: native NEAR. Read from each receiver's NEAR balance (end of setup to end of attack). The guard's, the agent's, "
                   "the outsider's and the owner's NEAR are read too, to find where all the NEAR that left the guard went; the agent's and "
                   "the outsider's own gas and deposits are added back first, so their gas never counts as a payment")
    m = rep.get("mapping") or {}
    if m.get("features") is not None:
        out.append(f"rules the guard claims: {rules_claimed(rep)}")
    if m.get("missing_roles"):
        out.append(f"role methods not in the guard (attacks that call them count as not applicable): {', '.join(m['missing_roles'])}")
    for role, e in (rep.get("owner_methods") or {}).items():
        if e["result"] == "not-confirmed":
            out.append(f"owner method not confirmed: {role}: {e['detail']} (attacks that call it count as not applicable)")
    if rep.get("only"):
        o = rep["only"]
        o = o if isinstance(o, dict) else {"ran": "some", "of": "?"}
        out.append(f"subset: only {o.get('ran')} of the library's {o.get('of')} attacks ran (--only); this is not a full check")
    for pr in (rep.get("library") or {}).get("problems") or []:
        out.append(f"attack file not loaded: {pr}")
    return out


def honest_line(t):
    k, m = t.get("honest_refused", 0), t.get("honest_tried", 0)
    if k:
        return (f"honest payments: the guard refused {k} of the {m} honest invoices the attacks asked it to pay, with no "
                "reason Arena can see. A guard that refuses honest payments can look like it held")
    if not m:
        return "honest payments: no attack that applied asked the guard to pay an honest invoice"
    return f"honest payments: the guard paid all {m} honest invoices the attacks asked it to pay"


def summary_md(rep):
    msg = headline(rep)
    g = rep.get("guard", {})
    lines = [f"## Arena check: **arena: {md(msg)}**", ""]
    lines += [f"- {md(x)}" for x in _plain_lines(rep)]
    if rep.get("totals"):
        broke = [r for r in rep["attacks"] if r["status"] == "broke"]
        if broke:
            head = "NEAR beyond the rules" if is_native(rep) else "Tokens beyond the rules"
            lines += ["", f"| Attack that broke it | {head} |", "|---|---|"]
            lines += [f"| {md(r['id'])}: {md(r['title'])} | {amt(rep, int(r['beyond_policy'] or 0))}{md(outside_note(rep, r))} |" for r in broke]
    for e in rep.get("errors", []):
        f = fence(e)
        lines += ["", "**Could not finish:**", "", f, e, f]
    lines += ["", f"Guard wasm sha256 `{md(g.get('sha256', '?'))}` · Arena commit `{md(commit_text(rep))}`"
              f"{' (with local changes)' if rep['arena'].get('dirty') else ''} · {rep.get('wall_seconds', '?')} s · {md(rep['started_utc'])}",
              "", "Local sandbox only. \"Held\" means it held these attacks on a local sandbox, not that it is proved safe. "
              "\"Not applicable\" attacks tested nothing the guard claims and are not counted as held."]
    if os.environ.get("ARENA_SUMMARY_BADGE") == "shields":
        # A static shields.io image (GitHub fetches it through its image proxy). It carries only the badge text.
        msg, color, _ = badge_text(rep)
        text = urllib.parse.quote(msg.replace("-", "--").replace("_", "__"), safe="")
        lines.insert(1, f"![arena: {msg}](https://img.shields.io/badge/arena-{text}-{color})")
    return "\n".join(lines) + "\n"


def _by_source(t, rep=None):
    b = t.get("against_intent_by_source") or {}
    names = {"hand": "hand-written scenarios", "paper": "from papers", "news": "from news"}
    return (" [" + ", ".join(f"{names.get(k, k)}: {amt(rep or {}, v)}" for k, v in b.items()) + "]") if b else ""


def outside_note(rep, r):
    """' (paid 100 tokens to the agent)' for an attack whose money reached a non-receiver, else ''."""
    paid = r.get("paid_outside") or []
    if not paid:
        return ""
    return " (paid " + ", ".join(f"{amt(rep, int(p.get('units', 0)))} {noun(rep)} to {p.get('to', '?')}" for p in paid) + ")"


def console(rep, where):
    """`where` is the report path as it should be shown (already relative)."""
    lines = ["", f"arena: {headline(rep)}"]
    lines += [f"  {x}" for x in _plain_lines(rep)]
    for r in rep.get("attacks", []):
        if r["status"] == "broke":
            lines.append(f"  BROKE {r['id']}: {amt(rep, r['beyond_policy'])} {noun(rep)} beyond the rules{outside_note(rep, r)}")
    for e in rep.get("errors", []):
        lines += ["", "COULD NOT FINISH:", "  " + e.replace("\n", "\n  ")]
    lines += [f"  wall-clock: {rep.get('wall_seconds')} s", "  held means: it held these attacks on a local sandbox; it is not a proof.",
              f"report: {where}"]
    return "\n".join(lines)


def _safe_href(p):
    """Only a plain relative path may be a link (no scheme such as javascript:, no absolute path)."""
    p = p or ""
    return p if p and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", p) and not p.startswith(("/", "\\")) and ".." not in p else None


REPORT_CSS = """
main{max-width:980px;margin:0 auto;padding:28px 16px 64px}
.rhead{display:flex;align-items:center;gap:10px;margin:0 0 18px;color:var(--ink)}
.rhead .brand-mark{width:22px;height:22px}
.rhead b{font:600 17px/1 var(--sans);letter-spacing:-.02em}.rhead span{font:500 11px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
h1{font:600 clamp(22px,3.2vw,30px)/1.15 var(--sans);letter-spacing:-.02em;margin:0 0 6px}
h2{font:600 17px/1.3 var(--sans);letter-spacing:-.01em;margin:32px 0 8px}
.muted{color:var(--muted)}.nums{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:16px 0}
.num{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-card);padding:14px 16px}
.num b{display:block;font:500 30px/1.1 var(--sans);letter-spacing:-.03em;font-variant-numeric:tabular-nums;margin-bottom:4px}
.ok{color:inherit}.warn{color:var(--muted)}.bad{color:var(--bad)}
.note{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-card);padding:12px 16px;margin:12px 0}
.note.bad{background:var(--bad-bg);border-color:transparent}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{font:500 11px/1.35 var(--mono);letter-spacing:.04em;color:var(--muted)}
.wrap{overflow-x:auto;width:auto;margin:0}pre{font:12px/1.45 var(--mono);background:var(--code);border-radius:6px;padding:10px;overflow-x:auto;white-space:pre-wrap}
details{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-card);padding:10px 14px;margin:8px 0}summary{cursor:pointer;font-weight:600}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--muted)}dd{margin:0;min-width:0}
ul{padding-left:20px}svg.badge{display:block;margin:10px 0}
"""
FALLBACK_THEME = ":root{--bg:#F7F6F3;--card:#FFFFFF;--ink:#2F3437;--muted:#787774;--line:#EAEAEA;--bad-bg:#FDEBEC;--bad:#9F2F2D;--code:#F1F0EC;--sans:sans-serif;--mono:monospace;--radius-card:12px}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 var(--sans)}code{font:12px var(--mono);background:var(--code);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}"


def _site_look():
    """(theme css, logo svg, favicon <link>) from site/theme.css and site/nav.json, the one source of
    the Arena look. If either file is missing (a partial copy of Arena), the report still writes,
    with a plain built-in look and no logo."""
    try:
        css = (SITE / "theme.css").read_text()
        mark = json.loads((SITE / "nav.json").read_text())["mark"]
    except (OSError, ValueError, KeyError):
        return FALLBACK_THEME, "", ""
    if re.search(r"</style|@import|url\(", css, re.I):
        return FALLBACK_THEME, "", ""
    return css, logo_svg(mark), favicon_link(mark, css)


def logo_svg(mark):
    d = mark["dot"]
    return (f'<svg class="brand-mark" viewBox="0 0 100 100" aria-hidden="true"><path d="{html.escape(mark["ring"])}" fill="none" '
            f'stroke="currentColor" stroke-width="{mark["ring_width"]}" stroke-linecap="round"/>'
            f'<circle cx="{d["cx"]}" cy="{d["cy"]}" r="{d["r"]}" style="fill:var(--bad)"/></svg>')


def favicon_link(mark, css):
    """The tab icon: the logo with the theme's ink (ring) and broke red (dot), light values, and the
    dark values when the browser is dark. Same encoding as site/chrome.mjs (encodeURIComponent)."""
    ink = re.findall(r"--ink:(#[0-9A-Fa-f]{3,8})", css)
    bad = re.findall(r"--bad:(#[0-9A-Fa-f]{3,8})", css)
    if len(ink) < 2 or len(bad) < 2:
        return ""
    d = mark["dot"]
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><style>.r{{stroke:{ink[0]}}}.d{{fill:{bad[0]}}}'
           f'@media (prefers-color-scheme:dark){{.r{{stroke:{ink[1]}}}.d{{fill:{bad[1]}}}}}</style>'
           f'<path class="r" d="{mark["ring"]}" fill="none" stroke-width="{mark["ring_width"]}" stroke-linecap="round"/>'
           f'<circle class="d" cx="{d["cx"]}" cy="{d["cy"]}" r="{d["r"]}"/></svg>')
    encoded = urllib.parse.quote(svg, safe="!~*'()")
    return f'<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,{encoded}">'



def _steps_table(r, rep=None):
    e = html.escape
    rep = rep or {}
    a = lambda v: str(amt(rep, v))
    rows = []
    for i, s in enumerate(r.get("steps", [])):
        res = "ok" if s.get("success") else s.get("outcome", "?")
        detail = s.get("failure", "") or ""
        logs = "; ".join(s.get("logs", []))[:600]
        rows.append(f"<tr><td>{i}</td><td>{e(s.get('kind', ''))}</td><td>{e(str(s.get('actor', '')))}</td>"
                    f"<td><code>{e(s.get('target', ''))}::{e(s.get('method', ''))}</code></td><td><code>{e(json.dumps(s.get('args', {}))[:300])}</code></td>"
                    f"<td class=\"{'ok' if s.get('success') else 'warn'}\">{e(res)}</td><td><code>{e((detail[:400] + ' ' + logs).strip())}</code></td></tr>")
    rec = "".join(f"<tr><td>{e(x['receiver'])}</td><td>{e(a(x['received']))}</td><td>{e(a(x['authorised']))}</td><td class=\"{'bad' if x['over'] != '0' else ''}\">{e(a(x['over']))}</td></tr>"
                  for x in r.get("final", {}).get("received", []))
    unit = ("Final balance changes (NEAR, read from each receiver's NEAR balance)" if is_native(rep) else "Final balances (tokens)")
    return (f"<div class=wrap><table><tr><th>#</th><th>kind</th><th>signed by</th><th>call</th><th>args</th><th>result</th><th>error / logs</th></tr>{''.join(rows)}</table></div>"
            f"<p class=muted>{unit}. <em>Allowed</em> = what the guard's own rules allow for invoices the agent actually paid.</p>"
            f"<div class=wrap><table><tr><th>receiver</th><th>received</th><th>allowed</th><th>beyond the rules</th></tr>{rec}</table></div>")


def html_page(rep):
    e = html.escape
    msg, _, color = badge_text(rep)
    long_msg = headline(rep)
    g, t = rep.get("guard", {}), rep.get("totals")
    cls = {"broke": "bad"}.get(_status(rep), "")  # held stays neutral: held is not "safe"
    theme, logo, icon = _site_look()
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">"
             f"<title>Arena check report</title>{icon}<style>{theme}\n{REPORT_CSS}</style></head><body><main>",
             f"<div class=rhead>{logo}<b>Arena</b><span>check report</span></div>",
             f"<h1>arena: <span class=\"{cls}\">{e(long_msg)}</span></h1>",
             f"<p class=muted>{e(g.get('label', '?'))} · {e(rep['started_utc'])} · {rep.get('wall_seconds', '?')} s</p>",
             badge_svg(msg, color).replace("<svg ", "<svg class=badge ", 1)]
    c = rep.get("control")
    if c:
        parts.append(f"<p>Honest payment: <strong>{e(c.get('result', 'settled'))}</strong>. <span class=muted>Before the attacks, Arena made one "
                     "normal payment the guard should allow. It is a check that the guard works, not an attack, so it is in no count below.</span></p>")
    if t and t.get("honest_refused"):
        parts.append(f"<div class=\"note bad\"><strong>The guard refused {t['honest_refused']} of the {t.get('honest_tried', '?')} honest payments "
                     "the attacks asked it to make</strong>, with no reason Arena can see (no rule change, not over the cap). A guard that refuses "
                     "honest payments can look like it held. The attacks with a refused honest payment are marked in the table below.</div>")
    if rep.get("errors"):
        parts.append("<h2 class=warn>Could not finish</h2>" + "".join(f"<pre>{e(x)}</pre>" for x in rep["errors"]))
    if t:
        parts.append(
            "<div class=nums>"
            f"<div class=num><b class=\"{'bad' if t['beyond_policy'] else 'ok'}\">{amt(rep, t['beyond_policy'])}</b>{noun(rep)} paid <strong>beyond the guard's own rules</strong>, summed over "
            f"{t['ran']} attacks that ran (each on its own fresh sandbox). Any value above 0 is a guard failure.</div>"
            f"<div class=num><b class=\"{'warn' if t['against_intent'] else 'ok'}\">{amt(rep, t['against_intent'])}</b>{noun(rep)} paid <strong>against the owner's intent</strong>, on the "
            f"{t['intent_attacks']} prompt-injection attacks that ran and where the owner's intent is written down ({e(str(amt(rep, rep['intended']['amount'])))}{' NEAR' if is_native(rep) else ''} to "
            f"{e(rep['intended']['receiver'])}, nothing else){e(_by_source(t, rep))}. The guard's rules allowed these payments; a guard cannot know intent.</div>"
            "</div>"
            f"<p>{t['held']} attacks held, {t['broke']} broke, {t.get('not_applicable', 0)} not applicable, {t['errors']} did not finish. "
            "The two numbers are never added together. Held and broke count only attacks that really ran against a rule the guard claims.</p>")
    extra = [x for x in _plain_lines(rep) if x.startswith(("paid in", "rules the guard", "role methods", "owner method", "subset", "honest payments", "not counted",
                                                           "paid outside", "not in the native suite"))]
    if extra:
        parts.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in extra) + "</ul>")
    parts.append("<h2>What was tested</h2><dl>"
                 f"<dt>Guard wasm sha256</dt><dd><code>{e(g.get('sha256', '?'))}</code> ({g.get('bytes', '?')} bytes)</dd>"
                 f"<dt>Wasm file</dt><dd><code>{e(g.get('wasm', '?'))}</code></dd>"
                 f"<dt>Arena commit</dt><dd><code>{e(rep['arena']['commit'])}</code>{'' if rep['arena'].get('commit_source', 'git') == 'git' else ' (' + e(rep['arena']['commit_source']) + ')'}{' <span class=warn>with local changes</span>' if rep['arena'].get('dirty') else ''}</dd>"
                 f"<dt>Started (UTC)</dt><dd>{e(rep['started_utc'])}, finished {e(rep.get('finished_utc', '?'))}</dd>"
                 f"<dt>Command</dt><dd><code>{e(rep.get('command', ''))}</code></dd></dl>")
    m = rep.get("mapping")
    if m:
        ren = ", ".join(f"<code>{e(k)}</code> → <code>{e(v)}</code>" for k, v in m["renamed"].items()) or "none (names match the interface)"
        feats = ", ".join(f"{k}: {'yes' if v else 'no (not scored; its starting invoices are not created)'}" for k, v in m["features"].items())
        parts.append("<h2>How Arena talked to the guard</h2><dl>"
                     f"<dt>Mapping from</dt><dd>{e(m['source'])}</dd><dt>Renamed methods</dt><dd>{ren}</dd>"
                     f"<dt>Init</dt><dd><code>{e(m['init']['method'])}({e(json.dumps(m['init']['args']))})</code></dd>"
                     f"<dt>Rules it claims</dt><dd>{e(feats)}</dd>"
                     f"<dt>Shapes</dt><dd><code>{e(json.dumps(m['shapes']))}</code></dd><dt>Deposits (yocto)</dt><dd><code>{e(json.dumps(m['deposits']))}</code></dd></dl>"
                     "<p class=muted>The mapping is data, used by a fixed translation layer in the harness (harness/src/adapter.rs). "
                     "Each call still goes straight from the agent's own key to the guard.</p>")
    rows = rep.get("attacks", [])
    broke = [r for r in rows if r["status"] == "broke"]
    if broke:
        parts.append("<h2 class=bad>Attacks that broke it</h2>")
        for r in broke:
            parts.append(f"<details open><summary>{e(r['id'])}: {amt(rep, r['beyond_policy'])} {noun(rep)} beyond the rules{e(outside_note(rep, r))}</summary>"
                         f"<p>{e(r['title'])}. <span class=muted>{e(r['breaks'])}</span></p>"
                         f"<p class=muted>Attack file: <code>{e(r['path'])}</code> · full log: "
                         + (f"<a href=\"{e(_safe_href(r['log']))}\">{e(r['log'])}</a>" if _safe_href(r['log']) else f"<code>{e(r['log'] or '')}</code>") + "</p>"
                         f"{_steps_table(r, rep)}</details>")
    intent = [r for r in rows if r["against_intent"]]
    if intent:
        parts.append(f"<h2 class=warn>Paid against the owner's intent</h2><div class=wrap><table><tr><th>attack</th><th>{noun(rep)} against intent</th><th>who got them{' (milliNEAR)' if is_native(rep) else ''}</th><th>beyond the rules</th></tr>"
                     + "".join(f"<tr><td>{e(r['id'])}</td><td>{amt(rep, r['against_intent'])}</td><td>{e(json.dumps(r['intent_detail']['wrongful']))}</td><td>{amt(rep, r['beyond_policy'])}</td></tr>" for r in intent)
                     + "</table></div>")
    held = [r for r in rows if r["status"] == "held"]
    if held:
        parts.append(f"<h2>Attacks it held ({len(held)})</h2><details><summary>Show all {len(held)}</summary><div class=wrap><table><tr><th>attack</th><th>what it tries</th><th>source</th><th>honest payments it asked for</th></tr>"
                     + "".join(f"<tr><td><code>{e(r['id'])}</code><br>{e(r['title'])}</td><td>{e(r['breaks'][:220])}</td><td>{e(r['source'])}</td>"
                               f"<td>{_honest_cell(r)}</td></tr>" for r in held)
                     + "</table></div></details>")
    na = [r for r in rows if r["status"] == "not-applicable"]
    if na:
        parts.append(f"<h2 class=warn>Not applicable ({len(na)}): not counted as held</h2><p>Each of these tested nothing your guard claims "
                     "(an invoice it never created, a rule it does not claim, a method it does not have). Arena does not count them as held.</p>"
                     "<details><summary>Show all " + str(len(na)) + "</summary><div class=wrap><table><tr><th>attack</th><th>why it does not apply</th></tr>"
                     + "".join(f"<tr><td><code>{e(r['id'])}</code><br>{e(r['title'])}</td><td>{e('; '.join(r.get('not_applicable_because') or []))}</td></tr>" for r in na)
                     + "</table></div></details>")
    nis = rep.get("not_in_suite") or []
    if nis:
        parts.append(f"<h2>Not in the native suite ({len(nis)}): not run, not counted</h2><p>These attacks work only on the NEP-141 test token. "
                     "A guard that pays in native NEAR does not use that token, so they are not part of its suite. They are not a gap in what "
                     "the guard covers, so they are not counted as not applicable either.</p><div class=wrap><table><tr><th>attack</th><th>why it is token-only</th></tr>"
                     + "".join(f"<tr><td><code>{e(d['id'])}</code><br>{e(d['title'])}</td><td>{e('; '.join(d['reasons']))}</td></tr>" for d in nis)
                     + "</table></div>")
    om = rep.get("owner_methods")
    if om:
        parts.append("<h2>Owner methods, as seen in preflight</h2><div class=wrap><table><tr><th>role</th><th>result</th><th>what Arena saw</th></tr>"
                     + "".join(f"<tr><td><code>{e(k)}</code></td><td class=\"{'ok' if v['result'] == 'confirmed' else 'warn'}\">{e(v['result'])}</td><td>{e(v['detail'])}</td></tr>" for k, v in om.items())
                     + "</table></div><p class=muted>Arena looks only at each owner method's own visible effect (through the guard's views), never at whether pay honours it: that is what the attacks test.</p>")
    bad = [r for r in rows if r["status"] not in ("held", "broke", "not-applicable")]
    if bad:
        parts.append("<h2 class=warn>Attacks that did not finish (not counted as held)</h2><ul>"
                     + "".join(f"<li><code>{e(r['id'])}</code>: {e(r['why'][:400])}</li>" for r in bad) + "</ul>")
    parts.append("<h2>Limits</h2><ul>"
                 "<li>Local NEAR sandbox only. Nothing ran on testnet or mainnet.</li>"
                 + ("<li>This guard pays in native NEAR. Arena reads each receiver's NEAR balance at the end of setup and after the attack; "
                    "1 Arena unit is 0.001 NEAR. Receivers sign nothing, so gas never touches them. An attempt where a receiver signed something, "
                    "a receiver's balance went down, or a change was not a whole number of milliNEAR is marked as not finished, never held.</li>"
                    "<li>Where the NEAR went: Arena also reads the guard's, the agent's, the outsider's and the owner's NEAR, and any account an "
                    "attack names. NEAR at the agent, the outsider or a named account counts as paid beyond the rules. The agent's and the "
                    "outsider's own gas and deposits are added back first, from their transactions' receipts. More than 1 milliNEAR that Arena "
                    "cannot find makes the attempt not finished, never held. The guard's own gas rewards (at most 3/10 of the gas burnt in its "
                    "receipts) can hide a small outflow; that bound is in each attempt's log.</li>"
                    "<li>Attacks that work only on the NEP-141 test token (for example ft_transfer) are not part of a native guard's suite.</li>"
                    if is_native(rep) else
                    "<li>The guard must pay in NEP-141 tokens (<code>ft_transfer</code>); balances are read from the token contract.</li>"
                    "<li>Where the tokens went: Arena reads the guard's token balance before and after each attack, and every token that left it "
                    "must be found at the five receivers, the agent, the outsider, the owner or an account the attack names. Tokens at the agent, "
                    "the outsider or a named account count as paid beyond the rules; tokens Arena cannot find make the attempt not finished, never "
                    "held. Plain NEAR the agent or the outsider gains (net of its own gas) also makes the attempt not finished.</li>")
                 + "<li>Arena finds money only at accounts it knows: the receivers, the agent, the outsider, the owner, the token contract "
                   "(token guards) and accounts named in the attack. Money sent anywhere else is not traced to its destination; it shows as "
                   "money Arena cannot find, and the check is incomplete.</li>"
                 "<li>These are the library's attacks, not every possible attack.</li>"
                 "<li><strong>\"Held\" means it held these attacks on a local sandbox. It is not a proof.</strong></li>"
                 "<li>Races are tested with the calls sent at the same moment; timing on a real network can differ.</li></ul>")
    parts.append(f"<h2>Publish a receipt</h2><p>To publish this score on-chain under the guard's sha256, see "
                 f"<a href=\"{e(receipt_link())}\">{e(RECEIPT_DOC)}</a>. A receipt proves who published a score and when; it does not prove the bench ran unmodified.</p>")
    parts.append("<p class=muted>Machine-readable: report.json · badge: badge.svg, shields.json · every attempt's log and result: runs/</p></main></body></html>\n")
    return "".join(parts)


def _honest_cell(r):
    tried, refused = r.get("honest_tried"), r.get("honest_refused") or []
    if tried is None:
        return f"{r.get('honest_settled')}/{r.get('should_pay')} paid"
    if not tried:
        return "none"
    text = f"{len(tried) - len(refused)} of {len(tried)} paid"
    return f"<span class=bad>{text}; refused: {html.escape(', '.join(refused))}</span>" if refused else text


def write_all(rep, out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    msg, shield_color, hexcolor = badge_text(rep)
    rep["badge"] = {"message": msg, "color": shield_color}
    rep["headline"] = headline(rep)
    (out / "report.json").write_text(scrub(json.dumps(rep, indent=1)) + "\n")
    (out / "badge.svg").write_text(scrub(badge_svg(msg, hexcolor)))
    (out / "shields.json").write_text(scrub(json.dumps({"schemaVersion": 1, "label": "arena", "message": msg, "color": shield_color})) + "\n")
    (out / "summary.md").write_text(scrub(summary_md(rep)))
    (out / "report.html").write_text(scrub(html_page(rep)))
