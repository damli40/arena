"""Fetch recent papers from the arXiv API, filter them, and remember which ones were used.

One HTTPS request per hunt (two with --paper): the arXiv API asks for at most one request every
3 seconds, and we make far fewer. The reply is capped at 5 MB, parsed as Atom XML, and every
field is length-capped and stripped of control characters. Paper text is UNTRUSTED: it is only
ever passed to the model as data inside a marked block, never acted on.
"""
import datetime, json, pathlib, re, time, urllib.parse, urllib.request
import xml.etree.ElementTree as ET

API = "https://export.arxiv.org/api/query"
ATOM = "{http://www.w3.org/2005/Atom}"
MAX_BYTES = 5 * 1024 * 1024
MAX_TITLE, MAX_ABSTRACT = 300, 3000
CATEGORIES = ("cs.CR", "cs.AI", "cs.MA")
# Search terms (any of them, in the abstract), sent to the API.
SEARCH_TERMS = ('"prompt injection"', '"smart contract"', "reentrancy", '"race condition"', '"double spending"',
                '"agent payment"', '"agentic payment"', '"AI agent"', '"LLM agent"', "authorization",
                '"access control"', '"transaction ordering"', '"front-running"', "blockchain")
# Local relevance score: a paper must touch money/contracts OR agents+attacks to be picked.
MONEY = ("smart contract", "reentran", "blockchain", "payment", "double spend", "double-spend", "defi", "stablecoin", "escrow",
         "transaction", "wallet", "front-run", "frontrun", "mev", "solidity", "near protocol", "race condition",
         "state inconsisten", "transaction order")
AGENT = ("agent", "llm", "language model", "tool use", "tool-use", "autonomous")
ATTACK = ("prompt injection", "injection attack", "indirect injection", "jailbreak", "exploit", "authoriz",
          "access control", "privilege escalation", "bypass", "double spend", "race condition", "reentran", "drain")
ARXIV_ID_RE = re.compile(r"^\d{4}\.\d{4,5}(v\d+)?$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class ArxivError(RuntimeError):
    pass


def _clean(s, limit):
    s = CONTROL_RE.sub(" ", s or "")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def _get(params, timeout=60):
    url = API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "arena-paper-hunter/1 (local benchmark; 1 request per hunt)"})
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ArxivError("arXiv reply larger than 5 MB; refused")
            return body
        except (OSError, TimeoutError) as e:  # URLError is an OSError
            last = e
            time.sleep(3 * (attempt + 1))
    raise ArxivError(f"arXiv unreachable after 3 tries: {type(last).__name__}")


def parse_feed(body):
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise ArxivError(f"arXiv reply is not valid XML: {e}")
    papers = []
    for e in root.findall(ATOM + "entry"):
        raw_id = (e.findtext(ATOM + "id") or "").rsplit("/abs/", 1)[-1].strip()
        if not ARXIV_ID_RE.match(raw_id):
            continue  # old-style ids (cs/0101001) and error entries are skipped
        cats = sorted({c.get("term", "") for c in e.findall(ATOM + "category")})
        papers.append({
            "arxiv_id": raw_id,
            "base_id": raw_id.split("v")[0],
            "title": _clean(e.findtext(ATOM + "title"), MAX_TITLE),
            "abstract": _clean(e.findtext(ATOM + "summary"), MAX_ABSTRACT),
            "published": _clean(e.findtext(ATOM + "published"), 40),
            "categories": [_clean(c, 20) for c in cats][:12],
            "url": f"https://arxiv.org/abs/{raw_id}",
        })
    return papers


def relevance(p):
    t = (p["title"] + " " + p["abstract"]).lower()
    money = sum(k in t for k in MONEY)
    agent = sum(k in t for k in AGENT)
    attack = sum(k in t for k in ATTACK)
    if money == 0 and not (agent and attack):
        return 0
    return 4 * min(money, 4) + 2 * min(agent, 3) + 2 * min(attack, 4)


def search_recent(days, max_results=100):
    cats = " OR ".join(f"cat:{c}" for c in CATEGORIES)
    terms = " OR ".join(f"abs:{t}" for t in SEARCH_TERMS)
    q = f"({cats}) AND ({terms})"
    body = _get({"search_query": q, "sortBy": "submittedDate", "sortOrder": "descending",
                 "start": 0, "max_results": max_results})
    papers = parse_feed(body)
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    recent = []
    for p in papers:
        try:
            pub = datetime.datetime.fromisoformat(p["published"].replace("Z", "+00:00"))
        except ValueError:
            continue
        if pub >= cutoff:
            recent.append(p)
    return {"query": q, "returned": len(papers), "within_days": len(recent), "papers": recent}


def fetch_by_id(arxiv_id):
    if not ARXIV_ID_RE.match(arxiv_id):
        raise ArxivError(f"not an arXiv id: {arxiv_id!r}")
    papers = parse_feed(_get({"id_list": arxiv_id, "max_results": 1}))
    if not papers:
        raise ArxivError(f"arXiv returned no paper for {arxiv_id}")
    return papers[0]


def pick(papers, used, max_papers):
    """Relevant papers not used before, best score first, newest first on ties."""
    fresh = [p for p in papers if p["base_id"] not in used]
    scored = [(relevance(p), p) for p in fresh]
    kept = [x for x in scored if x[0] > 0]
    kept.sort(key=lambda x: x[0], reverse=True)  # stable: score desc, then API order (newest first)
    return [dict(p, relevance=s) for s, p in kept[:max_papers]], {
        "already_used": len(papers) - len(fresh), "not_relevant": len(scored) - len(kept)}


def load_used(path):
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    try:
        d = json.loads(p.read_text())
        return d if isinstance(d, dict) else {}
    except json.JSONDecodeError:
        return {}


def save_used(path, used):
    pathlib.Path(path).write_text(json.dumps(used, indent=2, sort_keys=True) + "\n")
