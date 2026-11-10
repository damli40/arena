#!/usr/bin/env python3
"""Results board: guards x attacks -> latest result, from every hunt's evidence JSON.

  python3 -I tools/hunter/board.py        rebuild site/board-data.json and site/board.html

"Latest" = the result from the most recently finished trusted hunt that ran that attack on that
guard. Untrusted hunts (guard bytes changed, canary blind) never reach the board. The canary
attempts are folded in under the canary attack's library id.
"""
import json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HUNTS = ROOT / "evidence" / "hunts"
CANARY_ID = "scripted-02-race-double-pay"


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
    guards, attacks, cells = {}, {}, {}
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
                cells[f"{e['id']}|{gid}"] = {"attack": e["id"], "guard": gid, "result": c["status"], "source": src,
                                             "unauthorised": c.get("unauthorised"), "why": c.get("why", ""),
                                             "date": h["finished_utc"][:10], "hunt_id": h["hunt_id"],
                                             "evidence": f"evidence/hunts/{h['hunt_id']}.md"}
    order = {"subject": 0, "negative-control": 1, "positive-control": 2}
    glist = sorted(guards.values(), key=lambda g: (order.get(g["role"], 9), g["id"]))
    src_order = {"news": 0, "paper": 1, "combined": 2, "ai": 3, "hand": 4}
    alist = sorted((a for a in attacks.values() if any(k.startswith(a["id"] + "|") for k in cells)),
                   key=lambda a: (src_order.get(a["source"], 9), a["id"]))
    return {
        "_about": "Arena results board: every attack the bench knows x every opt-in guard, latest result. "
                  "broke = a receiver got tokens beyond that guard's own policy; held = 0 beyond policy (shows these attempts found nothing, not that the guard is safe). "
                  "Built by tools/hunter/board.py from evidence/hunts/*.json. Do not edit by hand.",
        "generated_from": [h["hunt_id"] for h in hunts],
        "latest_hunt_utc": hunts[-1]["finished_utc"] if hunts else None,
        "guards": glist,
        "attacks": alist,
        "cells": sorted(cells.values(), key=lambda c: (c["attack"], c["guard"])),
    }


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Arena results board</title>
<style>
:root{--bg:#fbfaf7;--fg:#1c1b19;--muted:#6b665d;--line:#e3dfd6;--held:#2f6b3a;--held-bg:#e7f1e6;--broke:#9b2c1f;--broke-bg:#f8e3df;--other:#7a5b00;--other-bg:#f6eed2}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#151513;--fg:#ecebe6;--muted:#a19c91;--line:#33312c;--held:#8fd19a;--held-bg:#1d2d1f;--broke:#ff9b8a;--broke-bg:#3a1d18;--other:#e8c96a;--other-bg:#332a12}}
:root[data-theme="dark"]{--bg:#151513;--fg:#ecebe6;--muted:#a19c91;--line:#33312c;--held:#8fd19a;--held-bg:#1d2d1f;--broke:#ff9b8a;--broke-bg:#3a1d18;--other:#e8c96a;--other-bg:#332a12}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
.board{max-width:1200px;margin:0 auto;padding:24px 16px}
h2{font-size:20px;margin:0 0 6px} p.lede{color:var(--muted);margin:0 0 16px;max-width:70ch}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--bg);font-weight:600}
th small,td small{display:block;color:var(--muted);font-weight:400}
.c{white-space:nowrap;text-align:center}
.held{color:var(--held);background:var(--held-bg)} .broke{color:var(--broke);background:var(--broke-bg);font-weight:600}
.error,.invalid,.none{color:var(--other);background:var(--other-bg)}
a{color:inherit}
</style></head><body>
<section class="board" id="arena-board">
<h2>Results board</h2>
<p class="lede">Every attack the bench knows, against every guard whose owner opted in. Attacks marked "from the news" were written from a summary of posts on X/Telegram: an unchecked lead, not a confirmed incident. <b>broke</b> means a receiver got tokens beyond that guard's own policy. <b>held</b> means these attempts found nothing, not that the guard is safe. Guards marked leaky on purpose are there to prove the bench can see a break.</p>
<div class="wrap"><table id="board-table"></table></div>
<p class="lede" id="board-foot"></p>
</section>
<script id="board-data" type="application/json">__DATA__</script>
<script>
(function(){
  var d = JSON.parse(document.getElementById('board-data').textContent);
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
  var roleLabel = {'subject':'guard','negative-control':'fixed control','positive-control':'leaky on purpose'};
  var cells = {}; d.cells.forEach(function(c){cells[c.attack+'|'+c.guard]=c;});
  var h = '<thead><tr><th>Attack<small>source</small></th>';
  d.guards.forEach(function(g){ h += '<th class="c" title="'+esc(g.policy)+'">'+esc(g.id)+'<small>'+esc(roleLabel[g.role]||g.role)+'</small></th>'; });
  h += '</tr></thead><tbody>';
  d.attacks.forEach(function(a){
    var src = a.source==='paper' && a.paper ? 'paper <a href="'+esc(a.paper.url)+'" rel="noopener">'+esc(a.paper.arxiv_id)+'</a>'
            : a.source==='combined' && a.parents ? 'combined: '+a.parents.map(esc).join(' + ')
            : a.source==='news' && a.news ? 'from the news, '+esc(a.news.date)+(a.news.links && a.news.links.length && ['https://x.com/','https://twitter.com/','https://t.me/'].some(function(p){return a.news.links[0].indexOf(p)===0;}) ? ' <a href="'+esc(a.news.links[0])+'" rel="noopener nofollow">post</a>' : '')+' (unchecked lead)'
            : esc(a.source);
    h += '<tr><td title="'+esc(a.breaks)+'">'+esc(a.title)+'<small>'+src+'</small></td>';
    d.guards.forEach(function(g){
      var c = cells[a.id+'|'+g.id];
      if(!g.runnable){ h += '<td class="c none" title="'+esc(g.not_run_reason)+'">not runnable</td>'; return; }
      if(!c){ h += '<td class="c none">-</td>'; return; }
      var label = c.result==='broke' ? 'broke +'+esc(c.unauthorised) : esc(c.result);
      h += '<td class="c '+esc(c.result)+'" title="'+esc(c.date+' '+c.hunt_id+' '+(c.why||''))+'">'+label+'<small>'+esc(c.date)+'</small></td>';
    });
    h += '</tr>';
  });
  document.getElementById('board-table').innerHTML = h + '</tbody>';
  document.getElementById('board-foot').textContent = 'Built from ' + d.generated_from.length + ' hunt(s); latest ' + (d.latest_hunt_utc||'never') + '. Evidence: evidence/hunts/.';
})();
</script>
</body></html>
"""


def write(b, out_dir):
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "board-data.json").write_text(json.dumps(b, indent=2) + "\n")
    data = json.dumps(b).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    (out_dir / "board.html").write_text(PAGE.replace("__DATA__", data))


if __name__ == "__main__":
    b = build()
    write(b, ROOT / "site")
    print(f"board: {len(b['guards'])} guards x {len(b['attacks'])} attacks, {len(b['cells'])} cells, from {len(b['generated_from'])} hunt(s)")
    sys.exit(0)
