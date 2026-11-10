"""Turn the model's reply into attack files, or reject it with a reason.

The reply is untrusted. Only these keys are read; anything else rejects the attack:
kind, name, title, paper_idea, breaks, expected_safe_result, steps (sequence), email and
injected_pays (injection), reasoning (logged only); news_idea instead of paper_idea for a news item.
The paper citation in meta comes from the arXiv API, and a news item's links from the Elfa reply,
never from the model.
"""
import re
import validate as V

MAX_PER_PAPER = 3
ATTACK_KEYS = {"kind", "name", "title", "paper_idea", "breaks", "expected_safe_result", "steps", "email",
               "injected_pays", "reasoning", "parents", "news_idea"}
# Phrases that suggest a paper (or a reply) is trying to instruct the model. Flagged in the
# evidence; the pipeline does not depend on catching them (nothing is executed either way).
INSTRUCTION_RE = re.compile(r"(ignore (all |any )?(previous|prior|above) instructions|system prompt|you are now|"
                            r"disregard (the|your)|<\s*script|BEGIN (SYSTEM|INSTRUCTIONS))", re.I)


def slug(s, limit=30):
    s = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return (s[:limit].strip("-")) or "attack"


def build(reply, paper, today, author, allowed_parents=None, news=None):
    """Returns (accepted attack docs, rejections [{index, name, reason}], notes).
    paper=None and allowed_parents=set(ids): a COMBINE reply (source=combined, parents required).
    paper=None and news=<item from news.parse>: a NEWS reply (source=news, citation from Elfa)."""
    combined = paper is None and news is None
    accepted, rejected, notes = [], [], []
    attacks = reply.get("attacks") if isinstance(reply, dict) else None
    if not isinstance(attacks, list):
        return [], [{"index": None, "name": None, "reason": "reply has no attacks list"}], notes
    if len(attacks) > MAX_PER_PAPER:
        for i in range(MAX_PER_PAPER, len(attacks)):
            rejected.append({"index": i, "name": None, "reason": f"over the cap of {MAX_PER_PAPER} attacks per paper"})
        attacks = attacks[:MAX_PER_PAPER]
    if combined:
        base = "c" + today.replace("-", "")[2:]
    elif news is not None:
        base = "n" + news["item_id"][2:10]
    else:
        base = "p" + paper["base_id"].replace(".", "")
    for i, a in enumerate(attacks):
        raw_name = a.get("name") if isinstance(a, dict) else None
        try:
            V._need(isinstance(a, dict), "attack must be an object")
            extra = set(a) - ATTACK_KEYS
            V._need(not extra, f"unknown keys {sorted(extra)}")
            kind = a.get("kind")
            V._need(kind in V.KINDS, f"kind must be one of {V.KINDS}")
            V._text(a.get("title"), "title", V.TEXT_LIMITS["title"])
            V._text(a.get("breaks"), "breaks", V.TEXT_LIMITS["breaks"])
            V._text(a.get("expected_safe_result"), "expected_safe_result", V.TEXT_LIMITS["expected_safe_result"])
            if a.get("paper_idea") is not None:
                V._text(a["paper_idea"], "paper_idea", 400)
            if a.get("news_idea") is not None:
                V._need(news is not None, "news_idea only belongs on an attack from a news item")
                V._text(a["news_idea"], "news_idea", 400)
            if a.get("reasoning") is not None:
                V._need(isinstance(a["reasoning"], str) and len(a["reasoning"]) <= 1000, "reasoning must be a string under 1000 chars")
            if combined:
                par = a.get("parents")
                V._need(kind == "sequence", "a combined attack must be kind sequence")
                V._need(isinstance(par, list) and 2 <= len(par) <= 4 and len(set(map(str, par))) == len(par),
                        "a combined attack needs 2-4 distinct parents")
                V._need(all(isinstance(x, str) and x in allowed_parents for x in par),
                        f"parents must be ids from the library list offered ({sorted(set(map(str, par)) - set(allowed_parents or ()))[:3]} not offered)")
            else:
                V._need("parents" not in a, "parents only belongs on a combined attack")
            name = f"{base}-{i + 1}-{slug(raw_name or a.get('title'))}"
            if raw_name is not None and slug(raw_name) != raw_name:
                notes.append(f"attack {i}: name {str(raw_name)[:60]!r} turned into file-safe {name!r}")
            meta = {
                "id": name,
                "title": a["title"],
                "source": "combined" if combined else ("news" if news is not None else "paper"),
                "kind": kind,
                "breaks": a["breaks"],
                "expected_safe_result": a["expected_safe_result"],
                "added": today,
                "author": author,
            }
            if combined:
                meta["parents"] = list(a["parents"])
            elif news is not None:
                meta["news"] = {"item_id": news["item_id"], "date": news["date"], "links": list(news["links"][:V.MAX_NEWS_LINKS])}
            else:
                meta["paper"] = {"arxiv_id": paper["arxiv_id"], "title": paper["title"][:300], "url": paper["url"]}
            if kind == "sequence":
                V._need("email" not in a and "injected_pays" not in a, "a sequence attack has steps only (no email/injected_pays)")
                steps = a.get("steps")
                V.check_steps(steps)
            else:
                V._need("steps" not in a, "an injection attack has email + injected_pays, not steps")
                pays = a.get("injected_pays")
                V._need(isinstance(pays, list) and 1 <= len(pays) <= V.MAX_INJECTED_PAYS
                        and all(isinstance(x, str) and V.INVOICE_RE.match(x) for x in pays),
                        f"injected_pays must list 1-{V.MAX_INJECTED_PAYS} invoice ids")
                V._text(a.get("email"), "email", V.MAX_EMAIL, allow_newlines=True)
                steps = V.injection_steps(pays)
                meta["injection"] = {"email": a["email"], "injected_pays": pays}
            meta["steps_sha256"] = V.steps_hash(steps)
            doc = {"name": name, "steps": steps, "meta": meta}
            V.check_attack(doc)
            flagged = [k for k in ("title", "breaks", "expected_safe_result", "email", "paper_idea", "news_idea")
                       if isinstance(a.get(k), str) and INSTRUCTION_RE.search(a[k])]
            accepted.append({"doc": doc, "paper_idea": a.get("paper_idea") or a.get("news_idea"), "reasoning": a.get("reasoning"),
                             "instruction_like_text_in": flagged})
        except V.Invalid as e:
            rejected.append({"index": i, "name": str(raw_name)[:60] if raw_name is not None else None, "reason": str(e)})
        except (TypeError, AttributeError, KeyError, ValueError) as e:
            rejected.append({"index": i, "name": str(raw_name)[:60] if raw_name is not None else None,
                             "reason": f"malformed attack ({type(e).__name__})"})
    return accepted, rejected, notes


def paper_flags(paper):
    t = paper["title"] + " " + paper["abstract"]
    return [m.group(0)[:60] for m in INSTRUCTION_RE.finditer(t)][:5]


SCORE_KEYS = {"arxiv_id", "novelty", "reported_success", "families", "reason"}


def check_scores(obj, candidates, family_tags):
    """Validate the model's paper scores. Returns ({arxiv_id: score}, [rejections])."""
    ids = {p["arxiv_id"] for p in candidates}
    good, bad = {}, []
    for i, sc in enumerate((obj or {}).get("scores", [])[:len(candidates) + 2]):
        try:
            V._need(isinstance(sc, dict) and not (set(sc) - SCORE_KEYS), "score entry has unknown keys")
            V._need(sc.get("arxiv_id") in ids, "score names a paper that was not offered")
            V._need(sc["arxiv_id"] not in good, "paper scored twice")
            for k in ("novelty", "reported_success"):
                V._need(V._is_int(sc.get(k)) and 0 <= sc[k] <= 5, f"{k} must be a whole number 0-5")
            fams = sc.get("families", [])
            V._need(isinstance(fams, list) and len(fams) <= 8 and all(f in family_tags or f == "other" for f in fams),
                    "families must come from the fixed tag list")
            V._text(sc.get("reason"), "reason", 200)
            good[sc["arxiv_id"]] = {"novelty": sc["novelty"], "reported_success": sc["reported_success"],
                                    "families": sorted(set(fams)), "reason": sc["reason"]}
        except (V.Invalid, TypeError, KeyError) as e:
            bad.append({"index": i, "reason": f"score rejected: {e}"})
    return good, bad


NEWS_SCORE_KEYS = {"id", "maps", "novelty", "reported_success", "families", "reason"}


def check_news_scores(obj, items, family_tags):
    """Validate the model's news scores. Returns ({item_id: score}, [rejections]).
    `maps` in the result is decided here, not only by the model: an item maps only if the model
    says so AND it names at least one real mechanism (families other than "other")."""
    ids = {it["item_id"] for it in items}
    good, bad = {}, []
    for i, sc in enumerate((obj or {}).get("scores", [])[:len(items) + 2]):
        try:
            V._need(isinstance(sc, dict) and not (set(sc) - NEWS_SCORE_KEYS), "score entry has unknown keys")
            V._need(sc.get("id") in ids, "score names an item that was not offered")
            V._need(sc["id"] not in good, "item scored twice")
            V._need(isinstance(sc.get("maps"), bool), "maps must be true or false")
            for k in ("novelty", "reported_success"):
                V._need(V._is_int(sc.get(k)) and 0 <= sc[k] <= 5, f"{k} must be a whole number 0-5")
            fams = sc.get("families", [])
            V._need(isinstance(fams, list) and len(fams) <= 8 and all(f in family_tags or f == "other" for f in fams),
                    "families must come from the fixed tag list")
            V._text(sc.get("reason"), "reason", 240)
            real = sorted(set(fams) - {"other"})
            maps = sc["maps"] and bool(real)
            why_not = None
            if not maps:
                why_not = sc["reason"] if not sc["maps"] else "the model said it maps but named no mechanism a payment guard has"
            good[sc["id"]] = {"novelty": sc["novelty"], "reported_success": sc["reported_success"],
                              "families": sorted(set(fams)), "reason": sc["reason"], "maps": maps, "doesnt_map": why_not}
        except (V.Invalid, TypeError, KeyError) as e:
            bad.append({"index": i, "reason": f"score rejected: {e}"})
    return good, bad
