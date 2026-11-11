"""Recent hack news from the Elfa AI API, as a second source for the hunter (besides papers).

Elfa watches crypto posts on X and Telegram. Its /v2/data/event-summary endpoint takes keywords
and a time window and returns short written summaries of what people posted, each with links to
the posts. A summary is a RETELLING OF TWEETS: an unchecked lead, never a confirmed incident.

Safety rules this file enforces:
- The key comes from ELFA_API_KEY (CI secret) or ~/.config/arena/news.env (local, mode 600). It goes
  in the x-elfa-api-key header only. It is never printed, logged, put in a URL or written to a file.
- At most HARD_MAX_CALLS event-summary calls per hunt (every HTTP request counts). Each costs about
  CREDITS_PER_CALL credits. The free tier fails closed when credits run out; it never bills.
- Only event-summary is called. key-status is never called here: its reply contains the key itself.
- Summary text is UNTRUSTED. It is cleaned (control characters out, whitespace collapsed, length
  capped), its quote markers are removed so it cannot close its own quoted block, and instruction-
  like phrases are flagged (same pattern as papers). It reaches Muse only as quoted data.
- No URL from a reply is ever fetched. Links are kept only if they are plain https post links on
  x.com, twitter.com or t.me, and are written to the evidence as text.
"""
import hashlib, json, os, pathlib, re, time, urllib.error, urllib.parse, urllib.request

import proposals
import validate as V

API = "https://api.elfa.ai"
ENDPOINT = "/v2/data/event-summary"
CALL_TIMEOUT_S = 150          # event-summary takes 30-120 s (tested Sep 2 2026)
HARD_MAX_CALLS = 2
CREDITS_PER_CALL = 5
MAX_BYTES = 2 * 1024 * 1024
MAX_SUMMARY = 1500
MAX_ITEMS_PER_CALL = 40
WINDOWS = ("24h", "7d", "30d")
MARKER_RE = re.compile(r"(<<<\s*NEWS|NEWS\s*>>>|<<<\s*PAPERS?|PAPERS?\s*>>>)", re.I)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Two calls, five keywords each, aimed at what a payment guard for an AI agent can be tested on.
QUERIES = (
    ("agents-and-payments", ("AI agent drained", "agent wallet exploit", "prompt injection", "x402 exploit", "agent overspend")),
    ("contract-exploits", ("double spend", "replay attack", "approval exploit", "allowance exploit", "smart contract hack")),
)


class ElfaError(RuntimeError):
    pass


class BudgetExhausted(RuntimeError):
    pass


def load_key():
    k = os.environ.get("ELFA_API_KEY", "").strip()
    if k:
        return k
    f = pathlib.Path.home() / ".config/arena/news.env"
    if f.exists():
        for line in f.read_text().splitlines():
            if line.startswith("ELFA_API_KEY="):
                return line.split("=", 1)[1].strip() or None
    return None


class Client:
    """Counts every HTTP request against the cap. `canned` (offline mode) is a list of reply
    objects used instead of the network, for tests and the CI dry run."""

    def __init__(self, max_calls, key=None, canned=None):
        self.max_calls = min(max_calls, HARD_MAX_CALLS)
        self.calls = 0
        self.log = []
        self._key = key
        self._canned = list(canned) if canned is not None else None

    @property
    def offline(self):
        return self._canned is not None

    def event_summary(self, label, keywords, window):
        if window not in WINDOWS:
            raise ElfaError(f"time window must be one of {WINDOWS}")
        if self.calls >= self.max_calls:
            raise BudgetExhausted(f"Elfa call cap {self.max_calls} reached")
        self.calls += 1
        entry = {"n": self.calls, "query": label, "keywords": list(keywords), "window": window}
        t0 = time.time()
        if self.offline:
            reply = self._canned.pop(0) if self._canned else {"success": True, "data": []}
            self.log.append(dict(entry, ok=True, offline=True, seconds=0.0, credits_estimate=0))
            return reply
        params = {"keywords": ",".join(keywords), "timeWindow": window, "searchType": "or"}
        req = urllib.request.Request(f"{API}{ENDPOINT}?{urllib.parse.urlencode(params)}",
                                     headers={"x-elfa-api-key": self._key, "User-Agent": "arena-news-hunter/1"})
        try:
            with urllib.request.urlopen(req, timeout=CALL_TIMEOUT_S) as r:
                body = r.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ElfaError("Elfa reply larger than 2 MB; refused")
            reply = json.loads(body)
        except urllib.error.HTTPError as e:
            self.log.append(dict(entry, ok=False, error=f"HTTP {e.code}", seconds=round(time.time() - t0, 1),
                                 credits_estimate=0))
            raise ElfaError(f"Elfa HTTP {e.code}")
        except (OSError, TimeoutError, json.JSONDecodeError) as e:
            self.log.append(dict(entry, ok=False, error=type(e).__name__, seconds=round(time.time() - t0, 1),
                                 credits_estimate=CREDITS_PER_CALL))  # a timeout may still have been charged
            raise ElfaError(f"Elfa unreachable: {type(e).__name__}")
        self.log.append(dict(entry, ok=True, seconds=round(time.time() - t0, 1), credits_estimate=CREDITS_PER_CALL))
        return reply


def clean_summary(s):
    """Untrusted text -> plain, bounded text that cannot close its quoted block."""
    s = CONTROL_RE.sub(" ", s if isinstance(s, str) else "")
    s = MARKER_RE.sub("[marker removed]", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:MAX_SUMMARY]


def clean_links(links):
    """Keep at most 3 plain https post links; count the rest. Nothing here is ever fetched."""
    kept, dropped = [], 0
    for x in links if isinstance(links, list) else []:
        if isinstance(x, str) and V.NEWS_LINK_RE.fullmatch(x.strip()) and x.strip() not in kept:
            if len(kept) < V.MAX_NEWS_LINKS:
                kept.append(x.strip())
            continue
        dropped += 1
    return kept, dropped


def item_id(summary, links):
    basis = "\n".join(sorted(links)) if links else summary
    return "n-" + hashlib.sha256(basis.encode()).hexdigest()[:10]


def parse(reply, query, today):
    """Elfa reply -> list of items. Bad shapes give an empty list, never an exception."""
    data = reply.get("data") if isinstance(reply, dict) else None
    items = []
    for raw in (data if isinstance(data, list) else [])[:MAX_ITEMS_PER_CALL]:
        if not isinstance(raw, dict):
            continue
        summary = clean_summary(raw.get("summary"))
        if len(summary) < 20:
            continue
        links, dropped = clean_links(raw.get("sourceLinks"))
        flags = [m.group(0)[:60] for m in proposals.INSTRUCTION_RE.finditer(summary)][:5]
        n_tweets = len(raw.get("tweetIds")) if isinstance(raw.get("tweetIds"), list) else 0
        items.append({"item_id": item_id(summary, links), "query": query, "date": today, "summary": summary,
                      "links": links, "links_dropped": dropped, "posts_summarised": n_tweets,
                      "instruction_like_text": flags,
                      "markers_removed": summary.count("[marker removed]")})
    return items


def used_keys(item):
    return [f"news:{x}" for x in item["links"]] or [f"news:{item['item_id']}"]


def pick(items, used):
    """Items not seen in an earlier hunt (by any post link) and not repeated in this one."""
    fresh, seen, info = [], set(), {"returned": len(items), "already_used": 0, "repeated_in_this_hunt": 0}
    for it in items:
        keys = used_keys(it)
        if any(k in used for k in keys):
            info["already_used"] += 1
            continue
        if it["item_id"] in seen or any(k in seen for k in keys):
            info["repeated_in_this_hunt"] += 1
            continue
        seen.update(keys + [it["item_id"]])
        fresh.append(it)
    return fresh, info


def mark_used(used, item, hunt_id, today):
    for k in used_keys(item):
        used[k] = {"hunt_id": hunt_id, "date": today, "title": item["summary"][:120]}


def relevance(item):
    """Keyword fallback when the scoring call fails (same lists as papers)."""
    import arxiv
    return arxiv.relevance({"title": "", "abstract": item["summary"]})
