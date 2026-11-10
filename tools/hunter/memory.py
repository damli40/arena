"""Memory of what works: attack x guard -> result over time, and the choices it drives.

Design credit: the attack memory and memory-guided selection follow AutoRedTeamer (Andy Zhou,
Kevin Wu, Francesco Pinto, Zhaorun Chen, Yi Zeng, Yu Yang, Shuang Yang, Sanmi Koyejo, James Zou,
Bo Li; NeurIPS 2025; arXiv 2503.15754). Ideas adapted, no code copied. Scaled to this bench: no
embeddings, no model in the loop for the record itself; just counts from the evidence files.

- An attack's FAMILY is computed from its steps (no model): which mechanisms it uses, e.g.
  "race+expiry". Two attacks in one family try the same kind of thing.
- The MEMORY is rebuilt from every trusted hunt file (evidence/hunts/*.json): for each attack and
  each family, on each guard: tries, breaks, last result and date. It is never edited by hand and
  never written by the model, so it cannot drift from the evidence.
- SELECTION (what to run next) favours (a) families that broke a guard before and (b) families
  never tried on a guard. Each pick carries its reason, which the hunt file prints.
"""
import json, pathlib
import validate as V

ROOT = pathlib.Path(__file__).resolve().parents[2]
HUNTS = ROOT / "evidence" / "hunts"

# Mechanism tags. Each is a plain test on the canonical steps.
FAMILY_TAGS = ("race", "repeat-pay", "expiry", "over-cap", "cancelled", "removed-payee", "outsider",
               "low-gas", "unknown-invoice", "direct-token", "non-pay-method", "add-key", "injection")
KNOWN_INVOICES = {"inv-pay", "inv-small", "inv-mid", "inv-big", "inv-cancel", "inv-expire", "inv-removed"}


def families(doc):
    """Sorted tags for one attack doc ({steps, meta}). Never empty."""
    steps = V.canonical_steps(doc["steps"])
    calls = []
    tags = set()
    for st in steps:
        (k, v), = st.items()
        if k == "race":
            tags.add("race")
            calls += v
        elif k == "call":
            calls.append(v)
        elif k == "add_key":
            tags.add("add-key")
        elif k == "wait_seconds":
            tags.add("expiry")
    pays = [c["args"].get("id") for c in calls if c["target"] == "vault" and c["method"] == "pay"]
    for c in calls:
        if c["actor"] == "outsider":
            tags.add("outsider")
        if c["gas_tgas"] < 100:
            tags.add("low-gas")
        if c["target"] == "token":
            tags.add("direct-token")
        elif c["method"] != "pay":
            tags.add("non-pay-method")
    if len(pays) != len(set(pays)):
        tags.add("repeat-pay")
    for p in pays:
        if p == "inv-expire":
            tags.add("expiry")
        elif p == "inv-cancel":
            tags.add("cancelled")
        elif p == "inv-removed":
            tags.add("removed-payee")
        elif p == "inv-big":
            tags.add("over-cap")
        elif p not in KNOWN_INVOICES:
            tags.add("unknown-invoice")
    if len(set(p for p in pays if p in ("inv-pay", "inv-small", "inv-mid"))) >= 3:
        tags.add("over-cap")  # filling the cap with several honest invoices
    if doc.get("meta", {}).get("kind") == "injection":
        tags.add("injection")
    return sorted(tags) or ["plain-pay"]


def family_key(doc):
    return "+".join(families(doc))


def build(hunts_dir=HUNTS, library=None):
    """Rebuild the memory from trusted hunt files. library = catalog attacks (to name families of
    attacks seen in hunts). Returns {"attacks": {id: {guard: rec}}, "families": {fam: {guard: rec}},
    "hunts": [ids]} where rec = {tries, breaks, last, last_date}."""
    fam_of = {a["meta"]["id"]: family_key(a) for a in (library or [])}
    mem = {"attacks": {}, "families": {}, "hunts": []}
    files = sorted(pathlib.Path(hunts_dir).glob("*.json"))
    hs = []
    for p in files:
        if p.name in ("used-papers.json", "memory.json"):
            continue
        try:
            h = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        if isinstance(h, dict) and h.get("trusted") and h.get("hunt_id"):
            hs.append(h)
    hs.sort(key=lambda h: h.get("finished_utc", ""))
    for h in hs:
        mem["hunts"].append(h["hunt_id"])
        rows = [(e["id"], e.get("family") or fam_of.get(e["id"]), e.get("results", {})) for e in h.get("attacks", [])]
        if h.get("canary"):
            rows.append(("scripted-02-race-double-pay", fam_of.get("scripted-02-race-double-pay", "race+repeat-pay"), h["canary"]["results"]))
        for aid, fam, results in rows:
            for gid, c in results.items():
                st = c.get("status")
                if st not in ("broke", "held"):
                    continue  # errors and skips are not evidence either way
                for table, key in (("attacks", aid), ("families", fam or "unknown")):
                    rec = mem[table].setdefault(key, {}).setdefault(gid, {"tries": 0, "breaks": 0, "last": None, "last_date": None})
                    rec["tries"] += 1
                    rec["breaks"] += st == "broke"
                    rec["last"], rec["last_date"] = st, h["finished_utc"][:10]
    return mem


def pick_library_runs(library, guards, mem, k):
    """Up to k (attack, guard ids, reason) re-runs from the library, chosen by the memory:
    1. attacks never tried on a guard (coverage: a newly registered guard gets these first);
    2. attacks whose family broke a guard that is NOT leaky on purpose (re-check: did it stay broken / get fixed);
    Positive controls are left out of the coverage rule: every hunt's canary already covers them."""
    picks = []
    gids = [g["id"] for g in guards]
    subj = {g["id"] for g in guards if g["role"] != "positive-control"}
    for a in library:
        aid, fam = a["meta"]["id"], family_key(a)
        tried = mem["attacks"].get(aid, {})
        never = [g for g in gids if g not in tried]
        if never:
            picks.append((0, aid, never, f"never tried on {', '.join(never)}"))
            continue
        fam_broke = [g for g, r in mem["families"].get(fam, {}).items() if r["breaks"] and g in subj]
        if fam_broke:
            picks.append((1, aid, fam_broke, f"family {fam} broke {', '.join(fam_broke)} before; re-check"))
    picks.sort(key=lambda x: (x[0], x[1]))
    return [(aid, gs, why) for _, aid, gs, why in picks[:k]]


def family_stats(mem, fam):
    """Plain-words summary of a family across guards, for prompts and logs."""
    recs = mem["families"].get(fam, {})
    if not recs:
        return "never run"
    br = sorted(g for g, r in recs.items() if r["breaks"])
    return f"run on {len(recs)} guards; broke {', '.join(br) if br else 'none'}"


def distance(paper_families, lib_family_counts):
    """0-5: how far a paper's attack mechanisms are from what the library already has.
    For each mechanism tag the paper uses, count library attacks that use it (capped at 5); the
    distance is 5 minus the average. A tag no library attack uses -> 5; a tag 5+ attacks use -> 0.
    (Changed 2026-11-10 after the first real hunt: the first version compared whole family strings,
    so "injection" looked new although 4 library attacks use it. See evidence/hunter-plan-2026-11-11.md.)"""
    tags = set(paper_families) - {"other", "unknown"}
    if not tags:
        return 3  # the model could not place it: middle value, said in the reason
    per_tag = {t: sum(n for fam, n in lib_family_counts.items() if t in fam.split("+")) for t in tags}
    return max(0, round(5 - sum(min(5, n) for n in per_tag.values()) / len(per_tag)))
