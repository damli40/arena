"""Write the `arena check` report: report.json, report.html (one self-contained page), badge.svg,
shields.json (a shields.io "endpoint" file), summary.md (for $GITHUB_STEP_SUMMARY).

Everything shown comes from report.json; nothing here runs or decides anything. Text from attack
files and logs is HTML-escaped (an attack written by a model is untrusted data).
"""
import html, json, os, pathlib, urllib.parse

RECEIPT_DOC = "docs/CHECK-YOUR-GUARD.md#publish-a-receipt"


def receipt_link():
    base = os.environ.get("ARENA_REPO_URL", "").rstrip("/")
    return f"{base}/blob/{os.environ.get('ARENA_REPO_REF', 'main')}/{RECEIPT_DOC}" if base else RECEIPT_DOC


def badge_text(rep):
    t = rep.get("totals")
    if rep["status"] == "held":
        return f"held {t['ran']}/{t['ran']}", "brightgreen", "#2e7d32"
    if rep["status"] == "broke":
        return f"broke {t['broke']} of {t['ran']}", "red", "#c62828"
    if rep["status"] == "incomplete":
        return "incomplete", "lightgrey", "#757575"
    return "not run", "lightgrey", "#757575"


def badge_svg(msg, hexcolor, label="arena"):
    w = lambda s: int(len(s) * 6.6 + 12)  # approx width of 11px Verdana
    lw, mw = w(label), w(msg)
    e = html.escape
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + mw}" height="20" role="img" aria-label="{e(label)}: {e(msg)}">'
            f'<title>{e(label)}: {e(msg)}</title><clipPath id="r"><rect width="{lw + mw}" height="20" rx="3"/></clipPath>'
            f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{mw}" height="20" fill="{hexcolor}"/></g>'
            f'<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw / 2}" y="14">{e(label)}</text><text x="{lw + mw / 2}" y="14">{e(msg)}</text></g></svg>\n')


def summary_md(rep):
    msg, _, _ = badge_text(rep)
    g = rep.get("guard", {})
    lines = [f"## Arena check: **arena: {msg}**", ""]
    if rep.get("totals"):
        t = rep["totals"]
        lines += [
            f"- **Tokens paid beyond the guard's own rules:** {t['beyond_policy']} (over {t['ran']} attacks; any value above 0 is a guard failure)",
            f"- **Tokens paid against the owner's intent:** {t['against_intent']} (over the {t['intent_attacks']} attacks that carry a written owner intent; "
            "the guard's rules allowed these payments)" + _by_source(t),
            f"- Attacks: {t['held']} held, {t['broke']} broke, {t['errors']} did not finish",
        ]
        broke = [r for r in rep["attacks"] if r["status"] == "broke"]
        if broke:
            lines += ["", "| Attack that broke it | Tokens beyond the rules |", "|---|---|"]
            lines += [f"| `{r['id']}` {r['title']} | {r['beyond_policy']} |" for r in broke]
    for e in rep.get("errors", []):
        lines += ["", "**Could not finish:**", "", "```", e, "```"]
    lines += ["", f"Guard wasm sha256 `{g.get('sha256', '?')}` · Arena commit `{rep['arena']['commit'][:12]}`"
              f"{' (with local changes)' if rep['arena'].get('dirty') else ''} · {rep.get('wall_seconds', '?')} s · {rep['started_utc']}",
              "", "Local sandbox only. \"Held\" means it held these attacks, not that it is proved safe."]
    if os.environ.get("ARENA_SUMMARY_BADGE") == "shields":
        # A static shields.io image (GitHub fetches it through its image proxy). It carries only the badge text.
        _, color, _ = badge_text(rep)
        text = urllib.parse.quote(msg.replace("-", "--").replace("_", "__"))
        lines.insert(1, f"![arena: {msg}](https://img.shields.io/badge/arena-{text}-{color})")
    return "\n".join(lines) + "\n"


def _by_source(t):
    b = t.get("against_intent_by_source") or {}
    names = {"hand": "hand-written scenarios", "paper": "from papers", "news": "from news"}
    return (" [" + ", ".join(f"{names.get(k, k)}: {v}" for k, v in b.items()) + "]") if b else ""


def console(rep, out):
    msg, _, _ = badge_text(rep)
    lines = ["", f"arena: {msg}"]
    if rep.get("totals"):
        t = rep["totals"]
        lines += [f"  tokens paid beyond the guard's own rules: {t['beyond_policy']}",
                  f"  tokens paid against the owner's intent:   {t['against_intent']} (on the {t['intent_attacks']} attacks with a written intent){_by_source(t)}",
                  f"  attacks: {t['held']} held, {t['broke']} broke, {t['errors']} did not finish"]
        for r in rep["attacks"]:
            if r["status"] == "broke":
                lines.append(f"  BROKE {r['id']}: {r['beyond_policy']} tokens beyond the rules")
    for e in rep.get("errors", []):
        lines += ["", "COULD NOT FINISH:", "  " + e.replace("\n", "\n  ")]
    lines += [f"  wall-clock: {rep.get('wall_seconds')} s", f"report: {out / 'report.html'}"]
    return "\n".join(lines)


CSS = """
:root{--bg:#fbfaf7;--fg:#1c1b19;--muted:#5f5b53;--line:#e2ded5;--card:#fff;--ok:#2e7d32;--bad:#c62828;--warn:#8d6e00;--code:#f2efe8}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--muted:#a8a49a;--line:#34322e;--card:#1d1c1a;--ok:#66bb6a;--bad:#ef5350;--warn:#e0b84a;--code:#26241f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 8px}
.muted{color:var(--muted)}.nums{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:16px 0}
.num{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}.num b{display:block;font-size:30px;font-variant-numeric:tabular-nums}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.wrap{overflow-x:auto}code,pre{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);border-radius:4px}
code{padding:1px 4px;word-break:break-all}pre{padding:10px;overflow-x:auto;white-space:pre-wrap}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0}summary{cursor:pointer;font-weight:600}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--muted)}dd{margin:0;min-width:0}
ul{padding-left:20px}
"""


def _steps_table(r):
    e = html.escape
    rows = []
    for i, s in enumerate(r.get("steps", [])):
        res = "ok" if s.get("success") else s.get("outcome", "?")
        detail = s.get("failure", "") or ""
        logs = "; ".join(s.get("logs", []))[:600]
        rows.append(f"<tr><td>{i}</td><td>{e(s.get('kind', ''))}</td><td>{e(str(s.get('actor', '')))}</td>"
                    f"<td><code>{e(s.get('target', ''))}::{e(s.get('method', ''))}</code></td><td><code>{e(json.dumps(s.get('args', {}))[:300])}</code></td>"
                    f"<td class=\"{'ok' if s.get('success') else 'warn'}\">{e(res)}</td><td><code>{e((detail[:400] + ' ' + logs).strip())}</code></td></tr>")
    rec = "".join(f"<tr><td>{e(x['receiver'])}</td><td>{e(x['received'])}</td><td>{e(x['authorised'])}</td><td class=\"{'bad' if x['over'] != '0' else ''}\">{e(x['over'])}</td></tr>"
                  for x in r.get("final", {}).get("received", []))
    return (f"<div class=wrap><table><tr><th>#</th><th>kind</th><th>signed by</th><th>call</th><th>args</th><th>result</th><th>error / logs</th></tr>{''.join(rows)}</table></div>"
            f"<p class=muted>Final balances (tokens). <em>Allowed</em> = what the guard's own rules allow for invoices the agent actually paid.</p>"
            f"<div class=wrap><table><tr><th>receiver</th><th>received</th><th>allowed</th><th>beyond the rules</th></tr>{rec}</table></div>")


def html_page(rep):
    e = html.escape
    msg, _, color = badge_text(rep)
    g, t = rep.get("guard", {}), rep.get("totals")
    cls = {"held": "ok", "broke": "bad"}.get(rep["status"], "warn")
    parts = [f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">"
             f"<title>Arena check report</title><style>{CSS}</style></head><body><main>",
             f"<h1>Arena check: <span class={cls}>{e(msg)}</span></h1>",
             f"<p class=muted>{e(g.get('label', '?'))} · {e(rep['started_utc'])} · {rep.get('wall_seconds', '?')} s</p>",
             badge_svg(msg, color)]
    if rep.get("errors"):
        parts.append("<h2 class=warn>Could not finish</h2>" + "".join(f"<pre>{e(x)}</pre>" for x in rep["errors"]))
    if t:
        parts.append(
            "<div class=nums>"
            f"<div class=num><b class=\"{'bad' if t['beyond_policy'] else 'ok'}\">{t['beyond_policy']}</b>tokens paid <strong>beyond the guard's own rules</strong>, summed over "
            f"{t['ran']} attacks (each on its own fresh sandbox). Any value above 0 is a guard failure.</div>"
            f"<div class=num><b class=\"{'warn' if t['against_intent'] else 'ok'}\">{t['against_intent']}</b>tokens paid <strong>against the owner's intent</strong>, on the "
            f"{t['intent_attacks']} prompt-injection attacks where the owner's intent is written down ({e(str(rep['intended']['amount']))} to "
            f"{e(rep['intended']['receiver'])}, nothing else){e(_by_source(t))}. The guard's rules allowed these payments; a guard cannot know intent.</div>"
            "</div>"
            f"<p>{t['held']} attacks held, {t['broke']} broke, {t['errors']} did not finish. The two numbers are never added together.</p>")
    parts.append("<h2>What was tested</h2><dl>"
                 f"<dt>Guard wasm sha256</dt><dd><code>{e(g.get('sha256', '?'))}</code> ({g.get('bytes', '?')} bytes)</dd>"
                 f"<dt>Wasm file</dt><dd><code>{e(g.get('wasm', '?'))}</code></dd>"
                 f"<dt>Arena commit</dt><dd><code>{e(rep['arena']['commit'])}</code>{' <span class=warn>with local changes</span>' if rep['arena'].get('dirty') else ''}</dd>"
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
            parts.append(f"<details open><summary>{e(r['id'])}: {r['beyond_policy']} tokens beyond the rules</summary>"
                         f"<p>{e(r['title'])}. <span class=muted>{e(r['breaks'])}</span></p>"
                         f"<p class=muted>Attack file: <code>{e(r['path'])}</code> · full log: <a href=\"{e(r['log'] or '')}\">{e(r['log'] or '')}</a></p>"
                         f"{_steps_table(r)}</details>")
    intent = [r for r in rows if r["against_intent"]]
    if intent:
        parts.append("<h2 class=warn>Paid against the owner's intent</h2><div class=wrap><table><tr><th>attack</th><th>tokens against intent</th><th>who got them</th><th>beyond the rules</th></tr>"
                     + "".join(f"<tr><td>{e(r['id'])}</td><td>{r['against_intent']}</td><td>{e(json.dumps(r['intent_detail']['wrongful']))}</td><td>{r['beyond_policy']}</td></tr>" for r in intent)
                     + "</table></div>")
    held = [r for r in rows if r["status"] == "held"]
    if held:
        parts.append(f"<h2 class=ok>Attacks it held ({len(held)})</h2><details><summary>Show all {len(held)}</summary><div class=wrap><table><tr><th>attack</th><th>what it tries</th><th>source</th><th>honest invoices paid</th></tr>"
                     + "".join(f"<tr><td><code>{e(r['id'])}</code><br>{e(r['title'])}</td><td>{e(r['breaks'][:220])}</td><td>{e(r['source'])}</td>"
                               f"<td>{r['honest_settled']}/{r['should_pay']}</td></tr>" for r in held)
                     + "</table></div></details>")
    bad = [r for r in rows if r["status"] not in ("held", "broke")]
    if bad:
        parts.append("<h2 class=warn>Attacks that did not finish (not counted as held)</h2><ul>"
                     + "".join(f"<li><code>{e(r['id'])}</code>: {e(r['why'][:400])}</li>" for r in bad) + "</ul>")
    parts.append("<h2>Limits</h2><ul>"
                 "<li>Local NEAR sandbox only. Nothing ran on testnet or mainnet.</li>"
                 "<li>The guard must pay in NEP-141 tokens (<code>ft_transfer</code>); balances are read from the token contract.</li>"
                 "<li>These are the library's attacks, not every possible attack.</li>"
                 "<li><strong>\"Held\" means it held these attacks. It does not prove the guard safe.</strong></li>"
                 "<li>Races are tested with the calls sent at the same moment; timing on a real network can differ.</li></ul>")
    parts.append(f"<h2>Publish a receipt</h2><p>To publish this score on-chain under the guard's sha256, see "
                 f"<a href=\"{e(receipt_link())}\">{e(RECEIPT_DOC)}</a>. A receipt proves who published a score and when; it does not prove the bench ran unmodified.</p>")
    parts.append("<p class=muted>Machine-readable: report.json · badge: badge.svg, shields.json · every attempt's log and result: runs/</p></main></body></html>\n")
    return "".join(parts)


def write_all(rep, out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    msg, shield_color, hexcolor = badge_text(rep)
    rep["badge"] = {"message": msg, "color": shield_color}
    (out / "report.json").write_text(json.dumps(rep, indent=1) + "\n")
    (out / "badge.svg").write_text(badge_svg(msg, hexcolor))
    (out / "shields.json").write_text(json.dumps({"schemaVersion": 1, "label": "arena", "message": msg, "color": shield_color}) + "\n")
    (out / "summary.md").write_text(summary_md(rep))
    (out / "report.html").write_text(html_page(rep))
