#!/usr/bin/env python3
"""The paper hunter: recent security papers -> Muse proposes attacks as data -> validate -> dedupe
-> run on the LOCAL sandbox against every registered guard -> evidence + results board.

  ./run-arena.sh hunt [--days N] [--max-papers N] [--paper <arxiv id>]     (preferred: frozen checks around it)
  python3 -I tools/hunter/hunt.py [same flags]

Flags:
  --days N            papers submitted in the last N days (default 7)
  --max-papers N      at most N papers (default 5, hard cap 5)
  --paper ID          attack this one arXiv paper (ignores --days; allowed even if used before)
  --library           no papers, no model: run every attack in the library against every guard
  --max-muse-calls N  default 20, hard cap 20 (every HTTP request counts, retries included)
  --guards a,b        only these registry ids (default: every runnable guard)
  --jobs N            attempts in parallel (default 4)
  --timeout-min N     whole-hunt deadline (default 60); attempts not started by then are skipped
  --no-run            propose and validate only; run nothing
  --offline-replies F JSON list of canned model replies (tests / CI dry run; no key, no network to Muse)
  --papers-file F     JSON list of papers instead of the arXiv API (tests / CI dry run)
  --out-dir D         evidence directory (default evidence/hunts)
  --board-out D       where board-data.json / board.html go (default site/)
  --no-save           do not write sequences-paper/ or the used-papers cache (dry runs)

Exit code: 0 = hunt completed (finding breaks is a result, not a failure); 1 = the hunt could not
be trusted (fingerprint changed, canary blind) ; 2 = bad usage or setup.
"""
import argparse, datetime, hashlib, json, os, pathlib, secrets, subprocess, sys, time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import arxiv, board, catalog, memory, muse, proposals, registry, runner  # noqa: E402
import validate as V  # noqa: E402

ROOT = HERE.parents[1]
HARD_MAX_PAPERS, HARD_MAX_CALLS = 5, 20
CANARY = ROOT / "sequences-scripted" / "02-race-double-pay.json"
DESIGN_CREDIT = ("Design credit: paper scoring, validate-before-adding, attack combination and the attack memory follow "
                 "AutoRedTeamer: Autonomous Red Teaming with Lifelong Attack Integration (Andy Zhou, Kevin Wu, Francesco Pinto, "
                 "Zhaorun Chen, Yi Zeng, Yu Yang, Shuang Yang, Sanmi Koyejo, James Zou, Bo Li; NeurIPS 2025; arXiv 2503.15754, "
                 "https://arxiv.org/abs/2503.15754). Ideas adapted to this bench, no code copied. One deliberate difference: "
                 "AutoRedTeamer has the model write attack code; here the model writes data only, in a fixed step vocabulary.")


def sh(*cmd):
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def rel(p):
    p = pathlib.Path(p)
    try:
        return str(p.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(p)


def parse_args(argv):
    ap = argparse.ArgumentParser(prog="hunt", add_help=True)
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--max-papers", type=int, default=5)
    ap.add_argument("--paper")
    ap.add_argument("--library", action="store_true")
    ap.add_argument("--max-muse-calls", type=int, default=20)
    ap.add_argument("--guards")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout-min", type=float, default=60)
    ap.add_argument("--no-run", action="store_true")
    ap.add_argument("--offline-replies")
    ap.add_argument("--papers-file")
    ap.add_argument("--out-dir", default=str(ROOT / "evidence" / "hunts"))
    ap.add_argument("--board-out", default=str(ROOT / "site"))
    ap.add_argument("--no-save", action="store_true")
    ap.add_argument("--candidates", type=int, default=10, help="papers scored before the top --max-papers are attacked")
    ap.add_argument("--combine", type=int, default=2, help="combined attacks to ask for (0 = off; 1 Muse call)")
    ap.add_argument("--memory-picks", type=int, default=6, help="library attacks re-run where the memory says (0 = off)")
    a = ap.parse_args(argv)
    if not (1 <= a.days <= 365):
        ap.error("--days must be 1-365")
    if a.max_papers < 1 or a.max_muse_calls < 0 or a.jobs < 1 or a.timeout_min <= 0:
        ap.error("--max-papers >= 1, --max-muse-calls >= 0, --jobs >= 1, --timeout-min > 0")
    if a.paper and not arxiv.ARXIV_ID_RE.match(a.paper):
        ap.error(f"--paper must be an arXiv id like 2104.08638, got {a.paper!r}")
    if a.library and (a.paper or a.offline_replies or a.papers_file):
        ap.error("--library runs the library only; it takes no paper flags")
    a.max_papers = min(a.max_papers, HARD_MAX_PAPERS)
    a.candidates = max(a.max_papers, min(a.candidates, 15))
    a.combine = max(0, min(a.combine, 3))
    a.memory_picks = max(0, min(a.memory_picks, 12))
    a.max_muse_calls = min(a.max_muse_calls, HARD_MAX_CALLS)
    return a


def main(argv):
    a = parse_args(argv)
    t_start = time.time()
    deadline = t_start + a.timeout_min * 60
    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.strftime("%Y-%m-%d")
    mode = "library" if a.library else ("paper" if a.paper else "papers")
    hunt_id = f"{today}-{mode}-{secrets.token_hex(3)}"
    out_dir = pathlib.Path(a.out_dir)
    raw = out_dir / hunt_id
    (raw / "attacks").mkdir(parents=True, exist_ok=True)
    used_path = out_dir / "used-papers.json"
    print(f"hunt {hunt_id}: mode={mode} evidence -> {rel(out_dir)}/{hunt_id}.md", flush=True)

    H = {"hunt_id": hunt_id, "mode": mode, "started_utc": now.isoformat(timespec="seconds"),
         "command": "hunt " + " ".join(argv), "git_head": sh("git", "rev-parse", "HEAD"),
         "git_dirty_files": len([l for l in sh("git", "status", "--porcelain").splitlines() if l.strip()]),
         "harness_sha256": registry.sha256(runner.HARNESS) if runner.HARNESS.exists() else None,
         "model": None if a.library else {"base": muse.BASE, "model": muse.MODEL, "offline": bool(a.offline_replies)},
         "bounds": {"max_papers": a.max_papers, "max_attacks_per_paper": proposals.MAX_PER_PAPER,
                    "max_muse_calls": a.max_muse_calls, "attempt_timeout_s": runner.ATTEMPT_TIMEOUT_S,
                    "hunt_timeout_min": a.timeout_min, "days": a.days},
         "papers": [], "attacks": [], "rejections": [], "duplicates": [], "notes": [], "trusted": True,
         "design_credit": DESIGN_CREDIT}

    # ---- guards: registry + fingerprints (refuse to run on changed bytes)
    try:
        guards_all = registry.load()
    except registry.RegistryError as e:
        print(f"REGISTRY INVALID: {e}", file=sys.stderr)
        return 2
    want = set(a.guards.split(",")) if a.guards else None
    if want and not want <= {g["id"] for g in guards_all}:
        print(f"unknown guard ids: {sorted(want - {g['id'] for g in guards_all})}", file=sys.stderr)
        return 2
    guards, H["guards"] = [], []
    for g in guards_all:
        fp = registry.fingerprint(g)
        entry = {"id": g["id"], "name": g["name"], "role": g["role"], "policy": g["policy"], "runnable": g["runnable"],
                 "scoring": g["scoring"], "fingerprint_before": fp}
        if not g["runnable"]:
            entry["skipped"] = g["not_runnable_reason"]
        elif want and g["id"] not in want:
            entry["skipped"] = "not selected (--guards)"
        elif not fp["ok"]:
            entry["skipped"] = f"fingerprint mismatch: {fp['why']}"
            H["trusted"] = False
        else:
            guards.append(g)
        H["guards"].append(entry)
    if not a.no_run and not runner.HARNESS.exists():
        print(f"harness binary missing: {rel(runner.HARNESS)} (cd harness && cargo build --release)", file=sys.stderr)
        return 2

    library, problems = catalog.load()
    H["library_problems"] = problems
    lib_index = catalog.index_by_hash(library)
    lib_unique, _ = catalog.unique(library)
    mem = memory.build(out_dir, library)
    fam_counts = {}
    for d in lib_unique:
        fam_counts[memory.family_key(d)] = fam_counts.get(memory.family_key(d), 0) + 1
    new_attacks = []  # (doc, extra)
    seen_hashes = {}

    lib_ids = {d["meta"]["id"] for d in library}
    hunt_tag = hunt_id.rsplit("-", 1)[-1]

    def add_new(doc, extra, where_from):
        """Dedupe against the library and this hunt; True if kept. An id already taken (same paper
        attacked again, or a combined attack on the same day) gets this hunt's tag appended, so the
        memory and the board never merge two different attacks."""
        if doc["meta"]["id"] in lib_ids or any(d["meta"]["id"] == doc["meta"]["id"] for d, _ in new_attacks):
            new = f"{doc['name'][:64 - len(hunt_tag) - 1]}-{hunt_tag}"
            H["notes"].append(f"id {doc['meta']['id']} already taken; renamed {new}")
            doc["name"] = doc["meta"]["id"] = new
        h = doc["meta"]["steps_sha256"]
        if h in lib_index:
            H["duplicates"].append({"attack": doc["meta"]["id"], "same_steps_as": lib_index[h]["meta"]["id"], "where": f"library ({where_from})"})
            return False
        if h in seen_hashes:
            H["duplicates"].append({"attack": doc["meta"]["id"], "same_steps_as": seen_hashes[h], "where": f"this hunt ({where_from})"})
            return False
        seen_hashes[h] = doc["meta"]["id"]
        new_attacks.append((doc, extra))
        return True

    if a.library:
        uniq, dups = catalog.unique(library)
        for d, orig in dups:
            H["duplicates"].append({"attack": d["meta"]["id"], "same_steps_as": orig["meta"]["id"], "where": "within the library"})
        for d in uniq:
            new_attacks.append((d, {"library_path": d["path"]}))
    else:
        # ---- papers
        used = arxiv.load_used(used_path)
        try:
            if a.papers_file:
                cand = json.loads(pathlib.Path(a.papers_file).read_text())
                for p in cand:
                    p.setdefault("base_id", p["arxiv_id"].split("v")[0])
                    p.setdefault("url", f"https://arxiv.org/abs/{p['arxiv_id']}")
                H["search"] = {"source": rel(a.papers_file), "returned": len(cand)}
                picked, info = arxiv.pick(cand, used, a.candidates) if not a.paper else ([p for p in cand if p["arxiv_id"] == a.paper][:1], {})
            elif a.paper:
                p = arxiv.fetch_by_id(a.paper)
                H["search"] = {"source": "arXiv id_list", "id": a.paper}
                if p["base_id"] in used:
                    H["notes"].append(f"{a.paper} was used before (hunt {used[p['base_id']].get('hunt_id')}); attacked again because it was pinned with --paper")
                picked, info = [dict(p, relevance=arxiv.relevance(p))], {}
            else:
                r = arxiv.search_recent(a.days)
                H["search"] = {"source": "arXiv API", "query": r["query"], "returned": r["returned"], "within_days": r["within_days"]}
                picked, info = arxiv.pick(r["papers"], used, a.candidates)
            H["search"].update(info)
        except (arxiv.ArxivError, OSError, json.JSONDecodeError, KeyError) as e:
            H["search"] = {"error": str(e)[:300]}
            picked = []
        if not picked:
            H["notes"].append("No papers to attack (none in the window, none relevant, all used before, or arXiv unreachable). Nothing was proposed or run beyond the canary.")

        # ---- Muse
        key = None
        replies = None
        if a.offline_replies:
            replies = json.loads(pathlib.Path(a.offline_replies).read_text())
            if not isinstance(replies, list):
                print("--offline-replies must be a JSON list of strings", file=sys.stderr)
                return 2
        elif picked or a.combine:
            key = muse.load_key()
            if not key:
                print("MUSE_API_KEY not set and ~/.config/arena/model.env has none", file=sys.stderr)
                return 2
        client = muse.Client(a.max_muse_calls, key=key, replies=replies)
        author = f"{muse.MODEL} via tools/hunter" + (" (offline canned reply)" if replies is not None else "")
        # ---- score papers before attacking (AutoRedTeamer idea 1): novelty + distance from the
        # library + reported success, 0-15. The Muse budget goes to the top-scored papers first.
        H["paper_scores"] = []
        if len(picked) > 1:
            scores, why_fallback = {}, None
            try:
                sobj, sraw, serr = muse.score_papers(client, picked)
                (raw / "muse-scores.txt").write_text(sraw)
                if sobj is None:
                    why_fallback = f"scoring reply unusable: {serr}"
                else:
                    scores, srej = proposals.check_scores(sobj, picked, memory.FAMILY_TAGS)
                    H["rejections"] += [{"paper": "scores", "name": None, **r_} for r_ in srej]
            except (muse.BudgetExhausted, muse.MuseError) as e:
                why_fallback = f"scoring call failed: {e}"
            for p in picked:
                sc = scores.get(p["arxiv_id"])
                if sc:
                    dist = memory.distance(set(sc["families"]) - {"other"} or {"unknown"}, fam_counts)
                    total = sc["novelty"] + dist + sc["reported_success"]
                    reason = (f"novelty {sc['novelty']} + distance from library {dist} (families {'+'.join(sc['families']) or 'none'}) "
                              f"+ reported success {sc['reported_success']} = {total}. {sc['reason']}")
                else:
                    total, reason = None, f"not scored ({why_fallback or 'model gave no score'}); ranked by keyword relevance {p.get('relevance')}"
                H["paper_scores"].append({"arxiv_id": p["arxiv_id"], "title": p["title"][:160], "score": total, "reason": reason,
                                          "keyword_relevance": p.get("relevance")})
            order = {x["arxiv_id"]: (x["score"] if x["score"] is not None else -1, x["keyword_relevance"] or 0) for x in H["paper_scores"]}
            picked = sorted(picked, key=lambda p: order[p["arxiv_id"]], reverse=True)
            chosen = {p["arxiv_id"] for p in picked[:a.max_papers]}
            for x in H["paper_scores"]:
                x["chosen"] = x["arxiv_id"] in chosen
            H["paper_scores"].sort(key=lambda x: order[x["arxiv_id"]], reverse=True)
            picked = picked[:a.max_papers]
        elif picked:
            H["paper_scores"].append({"arxiv_id": picked[0]["arxiv_id"], "title": picked[0]["title"][:160], "score": None,
                                      "reason": "only one candidate (or pinned with --paper): attacked without ranking, no scoring call spent",
                                      "keyword_relevance": picked[0].get("relevance"), "chosen": True})
        for p in picked:
            pe = {k: p.get(k) for k in ("arxiv_id", "title", "url", "published", "relevance", "categories")}
            pe["abstract_chars"] = len(p.get("abstract", ""))
            pe["instruction_like_text"] = proposals.paper_flags(p)
            H["papers"].append(pe)
            if time.time() > deadline:
                pe["status"] = "not attacked: hunt timeout"
                continue
            try:
                obj, raws, err = muse.propose(client, p)
            except muse.BudgetExhausted as e:
                pe["status"] = f"not attacked: {e}"
                continue
            except muse.MuseError as e:
                pe["status"] = f"model call failed: {e}"
                continue
            (raw / f"muse-{p['base_id']}.txt").write_text("\n\n----- next reply -----\n\n".join(raws))
            pe["raw_replies"] = rel(raw / f"muse-{p['base_id']}.txt")
            if not a.no_save:
                used[p["base_id"]] = {"hunt_id": hunt_id, "date": today, "title": p["title"][:120]}
            if obj is None:
                pe["status"] = f"reply unusable: {err}"
                H["rejections"].append({"paper": p["arxiv_id"], "index": None, "name": None, "reason": err})
                pe.update(proposed=0, accepted=0, rejected=1)
                continue
            n_prop = len(obj["attacks"]) if isinstance(obj.get("attacks"), list) else 0
            acc, rej, notes = proposals.build(obj, p, today, author)
            for r_ in rej:
                H["rejections"].append({"paper": p["arxiv_id"], **r_})
            H["notes"] += [f"{p['arxiv_id']}: {n}" for n in notes]
            kept = sum(add_new(x["doc"], {"paper_idea": x["paper_idea"], "instruction_like_text_in": x["instruction_like_text_in"]}, "paper")
                       for x in acc)
            pe.update(status="attacked", proposed=n_prop, accepted=len(acc), rejected=len(rej), new_after_dedupe=kept)
        # ---- combine library attacks (AutoRedTeamer idea 3): one call, source=combined, parents listed.
        if a.combine and time.time() < deadline:
            lines, offered = [], set()
            for d in lib_unique:
                fam = memory.family_key(d)
                lines.append(f"{d['meta']['id']} | {d['meta']['title']} | {fam} | {memory.family_stats(mem, fam)}")
                offered.add(d["meta"]["id"])
            ce = {"offered": len(offered), "asked_for": a.combine}
            try:
                cobj, craw, cerr = muse.combine(client, lines, a.combine)
                (raw / "muse-combine.txt").write_text(craw)
                if cobj is None:
                    ce["status"] = f"reply unusable: {cerr}"
                else:
                    attacks_in = cobj["attacks"][:a.combine]
                    for i in range(a.combine, len(cobj["attacks"])):
                        H["rejections"].append({"paper": "combine", "index": i, "name": None, "reason": f"over the {a.combine} combined attacks asked for"})
                    acc, rej, notes = proposals.build({"attacks": attacks_in}, None, today, author, allowed_parents=offered)
                    H["rejections"] += [{"paper": "combine", **r_} for r_ in rej]
                    H["notes"] += [f"combine: {n}" for n in notes]
                    kept = sum(add_new(x["doc"], {"instruction_like_text_in": x["instruction_like_text_in"]}, "combined") for x in acc)
                    ce.update(status="ok", proposed=len(cobj["attacks"]), accepted=len(acc), rejected=len(rej), new_after_dedupe=kept)
            except muse.BudgetExhausted as e:
                ce["status"] = f"not asked: {e}"
            except muse.MuseError as e:
                ce["status"] = f"model call failed: {e}"
            H["combine"] = ce
        H["muse"] = {"cap": a.max_muse_calls, "calls": client.calls, "log": client.log}
        if not a.no_save and not a.offline_replies:
            arxiv.save_used(used_path, used)

    # ---- memory picks (AutoRedTeamer idea 4): re-run library attacks where the record says it is worth it
    picks = []
    if not a.library and a.memory_picks and not a.no_run:
        picks = memory.pick_library_runs(lib_unique, guards, mem, a.memory_picks)
    H["memory_picks"] = [{"attack": aid, "guards": gs, "why": why} for aid, gs, why in picks]
    H["memory_before"] = {"hunts": len(mem["hunts"]), "attacks_with_results": len(mem["attacks"]), "families": len(mem["families"])}

    # ---- write attack files for the harness (data only)
    to_run = []
    lib_by_id = {d["meta"]["id"]: d for d in lib_unique}
    for aid, gs, why in picks:
        d = lib_by_id[aid]
        new_attacks.append((d, {"memory_pick": why, "library_path": d["path"], "_guards": gs}))
    for doc, extra in new_attacks:
        subset = extra.pop("_guards", None)
        sp = raw / "attacks" / f"{doc['name']}.json"
        sp.write_text(json.dumps(doc, indent=2) + "\n")
        H["attacks"].append({"id": doc["meta"]["id"], "name": doc["name"], "title": doc["meta"]["title"],
                             "source": doc["meta"]["source"], "kind": doc["meta"]["kind"], "paper": doc["meta"].get("paper"),
                             "breaks": doc["meta"]["breaks"], "expected_safe_result": doc["meta"]["expected_safe_result"],
                             "steps_sha256": doc["meta"]["steps_sha256"], "family": memory.family_key(doc),
                             "parents": doc["meta"].get("parents"), "file": rel(sp), **extra, "results": {}})
        to_run.append((sp, doc["meta"]["id"], subset))

    meta_line = f"hunt={hunt_id} mode={mode}"
    if not a.no_run and guards:
        res_dir = raw / "results"
        # Canary: the known double-pay race on every guard. Positive controls must break, or the bench is blind.
        print("canary: scripted race-double-pay on every guard", flush=True)
        can = runner.run_matrix([(CANARY, "canary-race-double-pay", None)], guards, res_dir / "canary", meta_line, a.jobs, deadline)
        cells = can["canary-race-double-pay"]
        blind = [g["id"] for g in guards if g["role"] == "positive-control" and cells[g["id"]]["status"] != "broke"]
        leaky = [g["id"] for g in guards if g["role"] != "positive-control" and cells[g["id"]]["status"] == "broke"]
        H["canary"] = {"attack": rel(CANARY), "results": cells, "ok": not blind and not leaky,
                       "why": ("; ".join(([f"positive control(s) did NOT break: {blind} (bench blind?)"] if blind else []) +
                                         ([f"non-control guard(s) broke on the known race: {leaky}"] if leaky else [])) or "positive controls broke, the rest held")}
        if blind:
            H["trusted"] = False
        if to_run:
            print(f"running {len(to_run)} attack(s) against up to {len(guards)} guard(s)", flush=True)
            res = runner.run_matrix(to_run, guards, res_dir, meta_line, a.jobs, deadline)
            for e in H["attacks"]:
                e["results"] = res.get(e["id"], {})
    elif a.no_run:
        H["notes"].append("--no-run: attacks were proposed and validated but not run")

    # ---- fingerprints after
    for entry in H["guards"]:
        g = next(x for x in guards_all if x["id"] == entry["id"])
        entry["fingerprint_after"] = fp2 = registry.fingerprint(g)
        if fp2["wasm_sha256"] != entry["fingerprint_before"]["wasm_sha256"]:
            H["trusted"] = False
            H["notes"].append(f"GUARD BYTES CHANGED DURING THE HUNT: {g['id']}")

    # ---- validate before adding (AutoRedTeamer idea 2): a new attack enters the permanent library
    # (sequences-paper/) only after it ran cleanly on EVERY guard it was run on: each cell broke or
    # held, none error / invalid / skipped. Then it is recorded as "broke" or "valid-nothing-broke".
    for e in H["attacks"]:
        broke = sorted(g for g, c in e["results"].items() if c.get("status") == "broke")
        held = sorted(g for g, c in e["results"].items() if c.get("status") == "held")
        e["broke_guards"], e["held_guards"] = broke, held
        if e["source"] not in ("paper", "combined"):
            continue
        clean = bool(e["results"]) and len(e["results"]) == len(guards) and len(broke) + len(held) == len(e["results"])
        e["validation"] = ("broke" if broke else "valid-nothing-broke") if clean else None
        if not clean:
            bad = {g: c.get("status") for g, c in e["results"].items() if c.get("status") not in ("broke", "held")}
            e["not_added"] = "not run" if not e["results"] else f"did not run cleanly on every guard: {bad or 'some guards missing'}"
            continue
        if not a.no_save and H["trusted"]:
            doc = json.loads((ROOT / e["file"]).read_text())  # ROOT / an absolute path = that absolute path
            doc["meta"].update(found_in_hunt=hunt_id, broke_guards=broke, held_guards=held, validation=e["validation"])
            V.check_attack(doc)
            dest_dir = ROOT / "sequences-paper"
            dest_dir.mkdir(exist_ok=True)
            dest = dest_dir / f"{doc['name']}.json"
            n = 2
            while dest.exists():
                dest = dest_dir / f"{doc['name']}-{n}.json"
                n += 1
            dest.write_text(json.dumps(doc, indent=2) + "\n")
            e["saved_to"] = rel(dest)

    # ---- counts (numbers first in the evidence)
    def count(status, roles=None):
        return sum(1 for e in H["attacks"] for g, c in e["results"].items()
                   if c.get("status") == status and (roles is None or next(x["role"] for x in guards_all if x["id"] == g) in roles))
    H["counts"] = {
        "papers_read": sum(1 for p in H["papers"] if p.get("status") == "attacked"),
        "papers_considered": len(H["papers"]),
        "attacks_proposed": sum(p.get("proposed", 0) for p in H["papers"]),
        "attacks_rejected": len(H["rejections"]),
        "attacks_deduped": len([d for d in H["duplicates"] if d["where"] != "within the library"]),
        "attacks_run": sum(1 for e in H["attacks"] if e["results"] and not e.get("memory_pick")),
        "attempts": sum(len(e["results"]) for e in H["attacks"]),
        "cells_broke": count("broke"),
        "cells_broke_subjects": count("broke", {"subject", "negative-control"}),
        "cells_error": count("error") + count("invalid"),
        "attacks_saved": sum(1 for e in H["attacks"] if e.get("saved_to")),
        "saved_broke": sum(1 for e in H["attacks"] if e.get("saved_to") and e.get("validation") == "broke"),
        "saved_valid_nothing_broke": sum(1 for e in H["attacks"] if e.get("saved_to") and e.get("validation") == "valid-nothing-broke"),
        "combined_run": sum(1 for e in H["attacks"] if e["source"] == "combined" and e["results"]),
        "memory_reruns": len(H["memory_picks"]),
        "muse_calls": H.get("muse", {}).get("calls", 0),
    }
    H["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    H["wall_seconds"] = round(time.time() - t_start, 1)

    (out_dir / f"{hunt_id}.json").write_text(json.dumps(H, indent=2) + "\n")
    if not a.no_save or a.out_dir != str(ROOT / "evidence" / "hunts"):
        lib_now, _ = catalog.load()
        (out_dir / "memory.json").write_text(json.dumps(dict(memory.build(out_dir, lib_now),
            _about="attack x guard -> tries/breaks/last result, rebuilt from every trusted hunt file. Never edited by hand."), indent=2) + "\n")
    (out_dir / f"{hunt_id}.md").write_text(render_md(H))
    b = board.build(out_dir)  # always rebuilt from the evidence dir this hunt wrote to
    board.write(b, pathlib.Path(a.board_out))
    print(f"evidence: {rel(out_dir / (hunt_id + '.md'))}  counts: {json.dumps(H['counts'])}  trusted={H['trusted']}")
    return 0 if H["trusted"] else 1


def _cell(c):
    if not c:
        return "-"
    s = c.get("status", "?")
    if s == "broke":
        return f"**BROKE** (+{c['unauthorised']})"
    if s == "held":
        return f"held ({c['honest_settled']}/{c['should_pay']} honest paid)"
    return f"{s}: {c.get('why', '')[:60]}"


def render_md(H):
    c = H["counts"]
    L = [f"# Hunt {H['hunt_id']}", ""]
    if H["mode"] == "library":
        L += [f"**Library run: {c['attacks_run']} attacks x {sum(1 for g in H['guards'] if 'skipped' not in g)} guards = {c['attempts']} attempts. "
              f"{c['cells_broke']} broke (of which {c['cells_broke_subjects']} on guards that are not leaky on purpose), {c['cells_error']} errors.**", ""]
    else:
        L += [f"**Papers read: {c['papers_read']}. Attacks proposed: {c['attacks_proposed']}, rejected: {c['attacks_rejected']}, "
              f"duplicates dropped: {c['attacks_deduped']}, run: {c['attacks_run']} (x guards = {c['attempts']} attempts). "
              f"Broke: {c['cells_broke']} cells, {c['cells_broke_subjects']} of them on guards that are not leaky on purpose. "
              f"Added to the library (sequences-paper/) after running cleanly: {c['attacks_saved']} ({c['saved_broke']} broke a guard, {c['saved_valid_nothing_broke']} valid but nothing broke). "
              f"Combined attacks run: {c['combined_run']}. Library attacks re-run because of the memory: {c['memory_reruns']}. "
              f"Muse calls: {c['muse_calls']} of {H['bounds']['max_muse_calls']}.**", ""]
    can = H.get("canary")
    if can:
        L += [f"Pipe check (canary): the known double-pay race on every guard: **{'OK' if can['ok'] else 'PROBLEM'}**, {can['why']}.", ""]
    L += [f"Trusted: **{'yes' if H['trusted'] else 'NO'}** (guard bytes unchanged before/after, canary not blind).", ""]
    L += ["## What this is", "",
          "One run of the paper hunter (`tools/hunter/hunt.py`). " +
          ("It ran every attack already in the library against every registered guard, with no model." if H["mode"] == "library" else
           "Muse read each paper's title and abstract and proposed attacks as data in the bench's step format. Each was validated, checked for duplicates, and run on a fresh local NEAR sandbox against every registered guard, scored by the existing scorer from final balances."),
          "A guard **broke** when a receiver got tokens beyond what that guard's own policy allows. **held** = 0 beyond policy. Leaky-on-purpose controls are expected to break on the double-pay race.", "",
          f"- started {H['started_utc']}, finished {H['finished_utc']} ({H['wall_seconds']} s)",
          f"- command: `{H['command'].strip()}`",
          f"- git HEAD {H['git_head'][:12]} ({H['git_dirty_files']} files changed in the working tree), harness sha256 {str(H['harness_sha256'])[:16]}...",
          ]
    if H.get("model"):
        L.append(f"- model: {H['model']['model']} at {H['model']['base']}" + (" (OFFLINE canned replies, not a real model call)" if H["model"]["offline"] else ""))
    L += ["", "## Guards", "", "| guard | role | fingerprint (sha256) | ran? |", "|---|---|---|---|"]
    for g in H["guards"]:
        fp = g["fingerprint_before"]
        L.append(f"| {g['id']} | {g['role']} | {str(fp['wasm_sha256'])[:16]}... {'ok' if fp['ok'] else 'MISMATCH'} | {'no: ' + g['skipped'][:90] if 'skipped' in g else 'yes'} |")
    if H["mode"] != "library":
        L += ["", "## Papers", ""]
        s = H.get("search", {})
        if s.get("error"):
            L.append(f"arXiv search failed: {s['error']}")
        else:
            L.append(f"Search: {s.get('source')}; returned {s.get('returned', '-')}, within {H['bounds']['days']} days {s.get('within_days', '-')}, "
                     f"already used {s.get('already_used', '-')}, not relevant {s.get('not_relevant', '-')}.")
        L.append("")
        if not H["papers"]:
            L.append("No papers were attacked.")
        for p in H["papers"]:
            L.append(f"- [{p['arxiv_id']}]({p['url']}) {p['title']} ({(p.get('published') or '')[:10]}): {p.get('status', '-')}"
                     + (f"; proposed {p.get('proposed', 0)}, accepted {p.get('accepted', 0)}, rejected {p.get('rejected', 0)}, new after dedupe {p.get('new_after_dedupe', 0)}" if p.get("status") == "attacked" else "")
                     + (f"; instruction-like text in the abstract: {p['instruction_like_text']}" if p.get("instruction_like_text") else ""))
    if H.get("paper_scores"):
        L += ["", "## How papers were ranked before attacking", "",
              "Each candidate got a score of 0-15: novelty (0-5, from Muse) + distance from attacks already in the library (0-5, computed here from attack families) + attack success the paper reports (0-5, from Muse). The Muse budget went to the top-scored papers first.", "",
              "| paper | score | attacked? | why |", "|---|---|---|---|"]
        for x in H["paper_scores"]:
            L.append(f"| {x['arxiv_id']} {x['title'][:70]} | {x['score'] if x['score'] is not None else '-'} | {'yes' if x.get('chosen') else 'no'} | {x['reason'][:300]} |")
    if H.get("combine"):
        ce = H["combine"]
        L += ["", "## Combined attacks", "",
              f"Muse was shown {ce.get('offered')} library attacks with their families and past results, and asked for {ce.get('asked_for')} attacks that join two or more of them. "
              f"Result: {ce.get('status')}" + (f"; proposed {ce.get('proposed')}, accepted {ce.get('accepted')}, rejected {ce.get('rejected')}, new after dedupe {ce.get('new_after_dedupe')}." if ce.get("status") == "ok" else ".")]
    if H.get("memory_picks") is not None and H["mode"] != "library":
        mb = H.get("memory_before", {})
        L += ["", "## Memory: library attacks re-run because of the record", "",
              f"The record (attack x guard -> result) was rebuilt from {mb.get('hunts', 0)} earlier trusted hunt(s). It favours attacks never tried on a guard, and families that broke a guard that is not leaky on purpose. This is how the bench keeps the attacks that work.", ""]
        L += [f"- `{m['attack']}` on {', '.join(m['guards'])}: {m['why']}" for m in H["memory_picks"]] or ["- Nothing picked: every library attack has been tried on every guard, and no family has broken a guard that is not leaky on purpose."]
    L += ["", "## Results (attack x guard)", ""]
    gids = [g["id"] for g in H["guards"] if "skipped" not in g]
    if H["attacks"] and gids:
        L += ["| attack | source | family | " + " | ".join(gids) + " |", "|---|---|---|" + "---|" * len(gids)]
        for e in H["attacks"]:
            src = e["source"] + (f" [{e['paper']['arxiv_id']}]({e['paper']['url']})" if e.get("paper") else "") \
                + (f" of {' + '.join(e['parents'])}" if e.get("parents") else "") + (" (memory re-run)" if e.get("memory_pick") else "")
            L.append(f"| `{e['id']}` {e['title']} | {src} | {e.get('family', '')} | " + " | ".join(_cell(e["results"].get(g)) for g in gids) + " |")
        L += ["", "What each attack tries (plain words):", ""]
        for e in H["attacks"]:
            L.append(f"- `{e['id']}` ({e['kind']}): {e['breaks']} Safe result: {e['expected_safe_result']}"
                     + (f" Paper idea: {e['paper_idea']}" if e.get("paper_idea") else "")
                     + (f" Added to the library as {e['validation']}: `{e['saved_to']}`." if e.get("saved_to") else "")
                     + (f" Not added: {e['not_added']}." if e.get("not_added") else ""))
    else:
        L.append("No new attacks were run.")
    if can:
        L += ["", "Canary cells: " + ", ".join(f"{g} {_cell(cc)}" for g, cc in can["results"].items())]
    L += ["", "## Rejected (model output that failed validation)", ""]
    L += [f"- {r['paper']} attack {r['index']} ({r['name']}): {r['reason']}" for r in H["rejections"]] or ["None."]
    L += ["", "## Duplicates (same steps as an attack we already had)", ""]
    L += [f"- `{d['attack']}` = `{d['same_steps_as']}` ({d['where']})" for d in H["duplicates"]] or ["None."]
    if H.get("muse"):
        L += ["", "## Muse calls", "", f"{H['muse']['calls']} of a hard cap of {H['muse']['cap']} (every HTTP request counts).", ""]
        for m in H["muse"]["log"]:
            u = m.get("usage") or {}
            L.append(f"- #{m['n']} {m['purpose']}: {'ok' if m['ok'] else 'FAILED ' + m.get('error', '')}, {m.get('seconds')} s"
                     + (f", tokens in/out {u.get('prompt_tokens')}/{u.get('completion_tokens')}" if u else "") + (" (offline)" if m.get("offline") else ""))
    if H["notes"] or H.get("library_problems"):
        L += ["", "## Notes", ""] + [f"- {n}" for n in H["notes"]] + [f"- library problem: {p}" for p in H.get("library_problems", [])]
    L += ["", "## Limits", "",
          "- A guard that held shows these attempts found nothing. It does not show the guard is safe.",
          "- Muse reads only the title and abstract (no full text), and may map a paper loosely; the paper link says where the idea came from, not that the paper endorses the attack.",
          "- Injection attacks run as the pays a fully fooled agent would make (no model plays the victim here).",
          "- Local sandbox only. Raw per-attempt logs and result JSON: `" + rel(pathlib.Path(H['hunt_id'])) + "/` next to this file.",
          "- Paper scores come from one Muse call reading abstracts; a high score is a reason to spend budget, not a measure of the paper.",
          "", "## Design credit", "", H.get("design_credit", DESIGN_CREDIT), ""]
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
