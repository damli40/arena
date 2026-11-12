#!/usr/bin/env python3
"""Results board: guards x attacks -> latest result, from every hunt's evidence JSON.

  python3 -I tools/hunter/board.py        rebuild site/board-data.json and site/board.html

"Latest" = the result from the most recently finished trusted hunt that ran that attack on that
guard. Untrusted hunts (guard bytes changed, canary blind) never reach the board. The canary
attempts are folded in under the canary attack's library id.

Every "held" is checked the same way `arena check` checks it (tools/check/applicable.py): an attack
that tested nothing the guard claims (an invoice the guard never created, a rule it does not claim,
a method it does not have) is shown as "not applicable" and is not counted as held. The hunt result
files do not carry the setup facts that check needs, so they are rebuilt from data only: which
invoices exist (the result's own invoice statuses: "null" = never created), the rules the guard's
interface claims (guards/registry.json -> FEATURES_BY_INTERFACE), and Arena's fixed starting state
(applicable.STARTING_INVOICES, checked against harness/src/setup.rs by a test). A cell whose result
file is missing or whose guard's interface is unknown is shown as "unchecked", never as held.

The honest-payment control (CONTROL_ID) is not an attack: it is left out of the table and the
counts, and reported on its own line (did the honest payment settle on each guard).
"""
import html, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HUNTS = ROOT / "evidence" / "hunts"
CANARY_ID = "scripted-02-race-double-pay"
CONTROL_ID = "scripted-01-control-pay-valid"
REGISTRY = ROOT / "guards" / "registry.json"
sys.path.insert(0, str(ROOT / "tools" / "check"))
import applicable as A  # noqa: E402
import guard_config as C  # noqa: E402

ALL_RULES = {"payees": True, "cancel": True, "expiry": True, "daily_cap": True}
# The rules each registry interface claims. vault-a: all four (targets/vault-a/INTERFACE.md).
# contracts-guard: none (the same claim as examples/configs/contracts-guard-fixed.json).
FEATURES_BY_INTERFACE = {
    "vault-a": ALL_RULES,
    "contracts-guard": json.loads((ROOT / "examples/configs/contracts-guard-fixed.json").read_text())["features"],
}


def _interfaces():
    try:
        return {g["id"]: g.get("interface") for g in json.loads(REGISTRY.read_text())["guards"]}
    except (OSError, ValueError, KeyError):
        return {}


def classify_cell(c, interface):
    """(result, reasons) for one hunt result cell, with the same rule as `arena check`."""
    if c.get("status") != "held":
        return c.get("status"), []
    rj = ROOT / c["result_json"] if c.get("result_json") else None
    if not rj or not rj.is_file():
        return "unchecked", ["the result file is missing, so the board cannot tell whether this attack applied"]
    r = json.loads(rj.read_text())
    setup = r.get("setup")
    if not setup:
        features = FEATURES_BY_INTERFACE.get(interface)
        if features is None:
            return "unchecked", [f"the board does not know which rules interface {interface!r} claims"]
        status = {x["id"]: x.get("status") for x in (r.get("final") or {}).get("invoice_statuses", [])}
        setup = {"arena_daily_cap": str(A.ARENA_DAILY_CAP), "features": features,
                 "invoices": [{"id": i, "amount": str(a), "created": status.get(i, "null") != "null"}
                              for i, _, a in A.STARTING_INVOICES]}
    return A.classify("held", r.get("steps", []), setup, C.ROLES, [], [])


def build(hunts_dir=HUNTS):
    hunts = []
    for p in sorted(pathlib.Path(hunts_dir).glob("*.json")):
        if p.name == "used-papers.json":
            continue
        try:
            h = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        if isinstance(h, dict) and h.get("hunt_id") and h.get("trusted"):
            hunts.append(h)
    hunts.sort(key=lambda h: h.get("finished_utc", ""))
    guards, attacks, cells, control = {}, {}, {}, {}
    iface = _interfaces()
    for h in hunts:
        for g in h.get("guards", []):
            guards[g["id"]] = {"id": g["id"], "name": g["name"], "role": g["role"], "policy": g["policy"],
                               "runnable": g["runnable"], "scoring": g.get("scoring"),
                               "not_run_reason": g.get("skipped") if not g["runnable"] else None,
                               "wasm_sha256": g["fingerprint_before"]["wasm_sha256"]}
        rows = list(h.get("attacks", []))
        if h.get("canary"):
            rows.append({"id": CANARY_ID, "results": h["canary"]["results"], "_canary": True})
        for e in rows:
            if not e.get("_canary"):
                attacks[e["id"]] = {"id": e["id"], "title": e["title"], "source": e["source"], "kind": e["kind"],
                                    "paper": e.get("paper"), "news": e.get("news"), "parents": e.get("parents"), "family": e.get("family"), "breaks": e["breaks"],
                                    "expected_safe_result": e["expected_safe_result"],
                                    "saved_to": e.get("saved_to") or attacks.get(e["id"], {}).get("saved_to")}
            src = "library" if e.get("_canary") else e.get("source")
            for gid, c in e.get("results", {}).items():
                if c.get("status") == "skipped":
                    continue
                if e["id"] == CONTROL_ID:  # the honest payment: not an attack
                    ok = c.get("status") == "held" and (c.get("honest_settled") or 0) >= 1 and not c.get("unauthorised")
                    control[gid] = {"guard": gid, "result": "settled" if ok else "did not settle",
                                    "date": h["finished_utc"][:10], "hunt_id": h["hunt_id"]}
                    continue
                result, reasons = classify_cell(c, iface.get(gid))
                cells[f"{e['id']}|{gid}"] = {"attack": e["id"], "guard": gid, "result": result, "source": src,
                                             "unauthorised": c.get("unauthorised"),
                                             "why": "; ".join(reasons) if reasons else c.get("why", ""),
                                             "date": h["finished_utc"][:10], "hunt_id": h["hunt_id"],
                                             "evidence": f"evidence/hunts/{h['hunt_id']}.md"}
    order = {"subject": 0, "negative-control": 1, "positive-control": 2}
    glist = sorted(guards.values(), key=lambda g: (order.get(g["role"], 9), g["id"]))
    src_order = {"news": 0, "paper": 1, "combined": 2, "ai": 3, "hand": 4}
    alist = sorted((a for a in attacks.values() if a["id"] != CONTROL_ID and any(k.startswith(a["id"] + "|") for k in cells)),
                   key=lambda a: (src_order.get(a["source"], 9), a["id"]))
    return {
        "_about": "Arena results board: every attack the bench knows x every opt-in guard, latest result. "
                  "broke = a receiver got tokens beyond that guard's own policy; held = 0 beyond policy (shows these attempts found nothing, not that the guard is safe); "
                  "not-applicable = the attack tested nothing that guard claims (same rule as arena check, tools/check/applicable.py), not counted as held. "
                  "The honest-payment control is not an attack: it is under \"control\", not in the cells. "
                  "Built by tools/hunter/board.py from evidence/hunts/*.json. Do not edit by hand.",
        "generated_from": [h["hunt_id"] for h in hunts],
        "latest_hunt_utc": hunts[-1]["finished_utc"] if hunts else None,
        "guards": glist,
        "attacks": alist,
        "cells": sorted(cells.values(), key=lambda c: (c["attack"], c["guard"])),
        "control": {"id": CONTROL_ID, "results": [control[g["id"]] for g in glist if g["id"] in control]},
    }


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Results board · Arena</title>
__ICON__
<meta name="description" content="Every attack Arena knows, against every guard whose owner opted in, with the latest result.">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet" media="print" onload="this.media='all'"><noscript><link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet"></noscript>
<style>
__THEME__
.board{padding:48px 0 16px}
h1{font:600 clamp(30px,4.4vw,44px)/1.08 var(--sans);letter-spacing:-.03em;margin:14px 0 14px}
p.lede{color:var(--muted);margin:0 0 28px;max-width:72ch}
p.lede b{color:var(--ink);font-weight:600}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:var(--radius-card);overflow:hidden;margin:0 0 18px}
.summary > div{background:var(--card);padding:16px 18px 14px}
.summary .n{font:500 30px/1 var(--sans);letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.summary .k{font:500 10.5px/1.4 var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:8px}
.summary .note{font-size:12.5px;line-height:1.4;color:var(--muted);margin-top:6px}
.summary .bad{background:var(--bad-bg)}.summary .bad .n,.summary .bad .k,.summary .bad .note{color:var(--bad)}
.legend{display:flex;flex-wrap:wrap;gap:8px 22px;margin:0 0 14px;font-size:13px;color:var(--muted);padding:0;list-style:none}
.legend li{display:flex;gap:8px;align-items:baseline}
.scroll{overflow:auto;max-height:min(72vh,760px);border:1px solid var(--line);border-radius:var(--radius-card);background:var(--card)}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:13px}
th,td{padding:9px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;background:var(--card)}
thead th{position:sticky;top:0;z-index:2;font:500 11px/1.35 var(--mono);letter-spacing:.04em;color:var(--ink);border-bottom:1px solid var(--line);box-shadow:0 1px 0 var(--line)}
th small,td small{display:block;color:var(--muted);font:400 11px/1.4 var(--mono);letter-spacing:0;margin-top:2px}
tr > :first-child{position:sticky;left:0;z-index:1;min-width:230px;max-width:300px;border-right:1px solid var(--line)}
thead tr > :first-child{z-index:3}
td:first-child{font-size:13.5px;line-height:1.4}
td:first-child small a{color:var(--muted)}
.c{white-space:nowrap;text-align:center;min-width:112px}
td.broke{background:var(--bad-bg);color:var(--bad);font-weight:600}
td.broke small{color:var(--bad);opacity:.8}
td.held{color:var(--ink)}
td.none,td.error,td.invalid,td.unchecked,td.not-applicable{color:var(--muted)}
td.not-applicable{font-size:12px}
tbody tr:last-child td{border-bottom:0}
td[title],th[title]{cursor:help}
th small.tip,td small.tip{white-space:normal;min-width:150px;color:var(--ink);font:400 12px/1.45 var(--sans);margin-top:6px;padding-top:6px;border-top:1px dashed var(--line)}
.foot{font-size:13px;color:var(--muted);margin:14px 0 0;max-width:80ch}
.foot + .foot{margin-top:6px}
/* The summary, legend and table are drawn by the script at the end of the page. On a slow connection the
   page paints before that script runs, so keep roughly their final space while they are empty and the
   footer does not jump down when they fill. Heights measured at 320-1440px wide. */
#board-summary:empty{min-height:126px}#board-legend:empty{min-height:50px}
.scroll:has(> table:empty){height:min(72vh,760px)}
@media (max-width:768px){#board-summary:empty{min-height:143px}#board-legend:empty{min-height:79px}}
@media (max-width:640px){#board-summary:empty{min-height:230px}#board-legend:empty{min-height:150px}}
/* short screens (a phone on its side): the table box may fill the screen, not 72% of it, so more than two rows show */
@media (max-height:520px){.scroll{max-height:calc(100vh - 16px)}.scroll:has(> table:empty){height:calc(100vh - 16px)}}
@media (max-width:640px){.board{padding-top:32px}.summary{grid-template-columns:1fr 1fr}.summary .n{font-size:24px}.summary > div{padding:14px 14px 12px}tr > :first-child{min-width:150px;max-width:170px}td:first-child{font-size:12.5px}th,td{padding:8px 9px}.c{min-width:92px}}
</style></head><body>
__TOPBAR__
<main class="wrap">
<section class="board" id="arena-board">
<div class="eyebrow">Results board</div>
<h1>Every attack, every guard</h1>
<p class="lede">Every attack the bench knows, against every guard whose owner opted in. Attacks marked "from the news" were written from a summary of posts on X/Telegram: an unchecked lead, not a confirmed incident. <b>broke</b> means a receiver got tokens beyond that guard's own policy. <b>held</b> means these attempts found nothing, not that the guard is safe. <b>not applicable</b> means the attack tested nothing that guard claims, so it is not counted. Guards marked leaky on purpose are there to prove the bench can see a break.</p>
<div class="summary" id="board-summary"></div>
<ul class="legend" id="board-legend"></ul>
<div class="scroll" tabindex="0" role="region" aria-label="Results table, scrolls both ways"><table id="board-table"></table></div>
<p class="foot" id="board-control"></p>
<p class="foot" id="board-skipped"></p>
<p class="foot" id="board-foot"></p>
</section>
</main>
__FOOTER__
<script id="board-data" type="application/json">__DATA__</script>
<script>
(function(){
  var d = JSON.parse(document.getElementById('board-data').textContent);
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  var roleLabel = {'subject':'guard','negative-control':'fixed control','positive-control':'leaky on purpose'};
  var guards = d.guards.filter(function(g){return g.runnable;});
  var skipped = d.guards.filter(function(g){return !g.runnable;});
  var shown = {}; guards.forEach(function(g){shown[g.id]=true;});
  var role = {}; guards.forEach(function(g){role[g.id]=g.role;});
  // "ran" counts only results that really tested something the guard claims: held or broke.
  var cells = {}, ran = 0, broke = 0, brokeLeaky = 0, na = 0, kinds = {};
  d.cells.forEach(function(c){cells[c.attack+'|'+c.guard]=c; if(shown[c.guard]){kinds[c.result]=true;
    if(c.result==='held'||c.result==='broke') ran++;
    if(c.result==='not-applicable') na++;
    if(c.result==='broke'){broke++; if(role[c.guard]==='positive-control')brokeLeaky++;}}});

  var latest = d.latest_hunt_utc ? String(d.latest_hunt_utc).slice(0,10) : 'never';
  var stat = function(n,k,cls,note){return '<div'+(cls?' class="'+cls+'"':'')+'><div class="n">'+esc(n)+'</div><div class="k">'+esc(k)+'</div>'+(note?'<div class="note">'+esc(note)+'</div>':'')+'</div>';};
  var brokeNote = broke===0 ? '' : brokeLeaky===broke ? 'all on guards that are leaky on purpose' : (broke-brokeLeaky)+' on guards that are not leaky on purpose';
  document.getElementById('board-summary').innerHTML =
    stat(guards.length, guards.length===1?'guard in the table':'guards in the table') +
    stat(d.attacks.length, d.attacks.length===1?'attack':'attacks', '', na ? na+(na===1?' result was':' results were')+' not applicable, so not counted' : '') +
    stat(broke+' of '+ran, 'results broke', broke>0?'bad':'', brokeNote) +
    stat(latest, 'latest hunt, '+d.generated_from.length+(d.generated_from.length===1?' hunt':' hunts')+' in all');

  var leg = '<li><span class="st st-broke">broke</span>a receiver got tokens beyond the guard\\u2019s own policy</li>' +
            '<li><span class="st st-held">held</span>these attempts found nothing. Not proof the guard is safe</li>' +
            '<li><span class="st st-none">not run</span>no result for this attack on this guard</li>';
  if(kinds['not-applicable']) leg += '<li><span class="st st-none">not applicable</span>tested nothing this guard claims. Not counted</li>';
  if(kinds.unchecked) leg += '<li><span class="st st-none">unchecked</span>the board could not tell if it applied. Not counted</li>';
  if(kinds.error||kinds.invalid) leg += '<li><span class="st st-none">error / invalid</span>the attempt ran but could not be scored</li>';
  document.getElementById('board-legend').innerHTML = leg;

  var h = '<thead><tr><th>Attack<small>where it came from</small></th>';
  guards.forEach(function(g){ h += '<th class="c" title="'+esc(g.policy)+'">'+esc(g.id)+'<small>'+esc(roleLabel[g.role]||g.role)+'</small></th>'; });
  h += '</tr></thead><tbody>';
  d.attacks.forEach(function(a){
    var src = a.source==='paper' && a.paper ? 'paper <a href="'+esc(a.paper.url)+'" rel="noopener">'+esc(a.paper.arxiv_id)+'</a>'
            : a.source==='combined' && a.parents ? 'combined: '+a.parents.map(esc).join(' + ')
            : a.source==='news' && a.news ? 'from the news, '+esc(a.news.date)+(a.news.links && a.news.links.length && ['https://x.com/','https://twitter.com/','https://t.me/'].some(function(p){return a.news.links[0].indexOf(p)===0;}) ? ' <a href="'+esc(a.news.links[0])+'" rel="noopener nofollow">post</a>' : '')+' (unchecked lead)'
            : esc(a.source);
    h += '<tr><td title="'+esc(a.breaks)+'">'+esc(a.title)+'<small>'+src+'</small></td>';
    guards.forEach(function(g){
      var c = cells[a.id+'|'+g.id];
      if(!c){ h += '<td class="c none">not run</td>'; return; }
      var label = c.result==='broke' ? 'broke +'+esc(c.unauthorised) : c.result==='not-applicable' ? 'not applicable' : esc(c.result);
      h += '<td class="c '+esc(c.result)+'" title="'+esc(c.date+' '+c.hunt_id+' '+(c.why||''))+'">'+label+'<small>'+esc(c.date)+'</small></td>';
    });
    h += '</tr>';
  });
  document.getElementById('board-table').innerHTML = h + '</tbody>';
  // A header or cell's title (the guard's policy, what the attack breaks, when and why a result) shows on mouse
  // hover only. A tap or click opens the same text inside the cell, and a second tap closes it, so touch
  // screens can read it too. Links inside a cell keep working as links.
  document.getElementById('board-table').addEventListener('click', function(e){
    if (e.target.closest('a')) return;
    var cell = e.target.closest('td[title],th[title]'); if (!cell || !cell.getAttribute('title')) return;
    var tip = cell.querySelector('.tip');
    if (tip) { tip.remove(); return; }
    tip = document.createElement('small'); tip.className = 'tip'; tip.textContent = cell.getAttribute('title');
    cell.appendChild(tip);
  });

  var ctl = (d.control && d.control.results || []).filter(function(r){return shown[r.guard];});
  var ce = document.getElementById('board-control');
  if(ctl.length){
    var ok = ctl.filter(function(r){return r.result==='settled';}).length;
    ce.innerHTML = '<b>Honest payment</b> (a check that each guard can pay a normal bill, not an attack, so it is in no count): settled on '+ok+' of '+ctl.length+' guards' +
      (ok<ctl.length ? '. Did not settle on: '+ctl.filter(function(r){return r.result!=='settled';}).map(function(r){return '<code>'+esc(r.guard)+'</code>';}).join(', ') : '') + '.';
  } else { ce.remove(); }
  var sk = document.getElementById('board-skipped');
  if(skipped.length){
    sk.innerHTML = '<b>Left out of the table</b> because they cannot run: ' + skipped.map(function(g){
      return '<code>'+esc(g.id)+'</code> ('+esc(roleLabel[g.role]||g.role)+'). '+esc(g.not_run_reason||'No reason recorded.');
    }).join(' ');
  } else { sk.remove(); }
  document.getElementById('board-foot').textContent = 'Built from ' + d.generated_from.length + ' hunt(s); latest ' + (d.latest_hunt_utc||'never') + '. Evidence: evidence/hunts/.';
})();
</script>
</body></html>
"""

THEME = ROOT / "site" / "theme.css"
NAV = ROOT / "site" / "nav.json"


def _theme():
    """site/theme.css, the one source of the look, inlined so board.html stays one standalone file
    (tools/hunter/ci-steps.sh copies board.html alone)."""
    css = THEME.read_text()
    low = css.lower()
    if "</style" in low or "@import" in low or "url(" in low or "__data__" in low:
        raise ValueError("site/theme.css must not contain </style, @import, url( or __DATA__: it is inlined into board.html")
    return css


def _chrome(current):
    """Top bar and footer from site/nav.json: the same markup as site/chrome.mjs renders."""
    nav = json.loads(NAV.read_text())
    e = lambda s: html.escape(str(s), quote=True)
    def links(cur):
        return "".join(f'<a href="{e(l["href"])}"' + (' aria-current="page"' if l["id"] == cur else "") + f'>{e(l["label"])}</a>'
                       for l in nav["links"])
    brand = f'<a class="brand" href="{e(nav["brand"]["href"])}">{_mark(nav["mark"])}{e(nav["brand"]["label"])}</a>'
    top = f'<header class="topbar"><div class="topbar-in">{brand}<nav aria-label="Arena pages">{links(current)}</nav></div></header>'
    foot = (f'<footer class="site-foot"><div class="foot-in"><nav aria-label="Arena pages, again">'
            f'<a href="{e(nav["brand"]["href"])}">{e(nav["brand"]["label"])}</a>{links(None)}</nav>'
            f'<p>{e(nav["footer_note"])}</p></div></footer>')
    return top, foot


def _mark(m):
    """The logo, inline (same markup as site/chrome.mjs markSvg): ring in the text colour, dot in --bad."""
    e = lambda s: html.escape(str(s), quote=True)
    d = m["dot"]
    return (f'<svg class="brand-mark" viewBox="0 0 100 100" aria-hidden="true"><path d="{e(m["ring"])}" fill="none" stroke="currentColor" '
            f'stroke-width="{e(m["ring_width"])}" stroke-linecap="round"/><circle cx="{e(d["cx"])}" cy="{e(d["cy"])}" r="{e(d["r"])}" style="fill:var(--bad)"/></svg>')


def _icon():
    """The browser-tab icon, built exactly as site/chrome.mjs FAVICON and tools/check/report.py do."""
    import re, urllib.parse
    css, m = THEME.read_text(), json.loads(NAV.read_text())["mark"]
    ink, bad = re.findall(r"--ink:(#[0-9A-Fa-f]{3,8})", css), re.findall(r"--bad:(#[0-9A-Fa-f]{3,8})", css)
    d = m["dot"]
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><style>.r{{stroke:{ink[0]}}}.d{{fill:{bad[0]}}}'
           f'@media (prefers-color-scheme:dark){{.r{{stroke:{ink[1]}}}.d{{fill:{bad[1]}}}}}</style>'
           f'<path class="r" d="{m["ring"]}" fill="none" stroke-width="{m["ring_width"]}" stroke-linecap="round"/>'
           f'<circle class="d" cx="{d["cx"]}" cy="{d["cy"]}" r="{d["r"]}"/></svg>')
    return f'<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,{urllib.parse.quote(svg, safe="!~*()" + chr(39))}">'


def write(b, out_dir):
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "board-data.json").write_text(json.dumps(b, indent=2) + "\n")
    data = json.dumps(b).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    top, foot = _chrome("board")
    # The fixed parts go in first and the data last, so nothing in the data can be read as a placeholder.
    page = PAGE.replace("__THEME__", _theme()).replace("__ICON__", _icon()).replace("__TOPBAR__", top).replace("__FOOTER__", foot)
    (out_dir / "board.html").write_text(page.replace("__DATA__", data))

if __name__ == "__main__":
    b = build()
    write(b, ROOT / "site")
    print(f"board: {len(b['guards'])} guards x {len(b['attacks'])} attacks, {len(b['cells'])} cells, from {len(b['generated_from'])} hunt(s)")
    sys.exit(0)
