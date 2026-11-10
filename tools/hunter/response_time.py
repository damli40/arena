#!/usr/bin/env python3
"""How long from "a paper or a hack post goes public" to "Arena has a scored attack built from it"?

This is a REPLAY (a simulation), not a live measurement: the scheduled hunt has never run on
GitHub. It takes three kinds of real input and one stated rule, and does arithmetic on them:

  1. real publish times   arXiv's own `published` stamp on each paper; the post time packed inside
                          each X post id that an Elfa news item cites (no post is ever fetched)
  2. real pipeline times  how long the two real hunts of 2026-11-10 took on one laptop, read from
                          their records in evidence/hunts/
  3. the real schedule    the cron lines in .github/workflows/hunt.yml, and which of them hunts
                          papers (the run whose cron line the workflow maps to source "all")
  4. one stated rule      arXiv's published announcement table (a paper is not public the moment
                          it is stamped; it is public at the next announcement)

For every real item it asks: had the scheduled hunt been running, when would its results exist?
"Results exist" means the whole run has finished, because the workflow only hands results out at
the end, as an artifact.

    python3 -I tools/hunter/response_time.py                  # replay from saved data, write evidence
    python3 -I tools/hunter/response_time.py --fetch-arxiv    # also ask arXiv once for this week's stamps

Every run starts with self-checks of the date rules; if one fails, nothing is written. If the real
runs' result times cannot be read (for example after a fresh clone, when file times are the
clone's), it stops with an error and writes nothing.
"""
import argparse, datetime, inspect, json, os, pathlib, re, statistics, sys, zoneinfo

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

UTC = datetime.timezone.utc
ET = zoneinfo.ZoneInfo("America/New_York")      # arXiv's clock
X_EPOCH_MS = 1288834974657                      # X post ids count milliseconds from this moment
ARXIV_TABLE = "https://info.arxiv.org/help/availability.html"
PAPERS_RUN = "evidence/hunts/2026-11-10-papers-c1bea9.json"
NEWS_RUN = "evidence/hunts/2026-11-10-news-21d429.json"
ON_DEMAND_RUNS = ["evidence/hunts/2026-11-10-paper-abc6e6.json", "evidence/hunts/2026-11-10-paper-cd8587.json"]
WORKFLOW = ".github/workflows/hunt.yml"


def utc(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC)


def iso(t):
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def hours(a, b):
    return (b - a).total_seconds() / 3600


# ---- the three date rules ------------------------------------------------------------------

def read_schedule(text):
    """The workflow's schedule: (paper run times, all run times), each a sorted list of (hour, minute)
    UTC. Only once-a-day "minute hour * * *" lines are understood. The paper run is the cron line
    the workflow's HUNT_SOURCE expression maps to 'all'; every other scheduled run is news only."""
    crons = [(int(h), int(m)) for m, h in re.findall(r'cron:\s*"(\d{1,2}) (\d{1,2}) \* \* \*"', text)]
    if not crons:
        sys.exit("response_time: the workflow has no plain once-a-day cron line")
    if len(crons) == 1:
        return crons, crons
    pm = re.findall(r"github\.event\.schedule == '(\d{1,2}) (\d{1,2}) \* \* \*' && 'all'", text)
    if len(pm) != 1:
        sys.exit("response_time: several cron lines, but not exactly one mapped to source 'all' in HUNT_SOURCE")
    paper = [(int(pm[0][1]), int(pm[0][0]))]
    if paper[0] not in crons:
        sys.exit("response_time: the paper run's cron line is not in the schedule")
    return paper, sorted(crons)


def read_cron(text):
    """Backward-compatible: the first run time (hour, minute)."""
    return read_schedule(text)[1][0]


def next_run(t, hour, minute, every_h=24):
    """First scheduled start at or after t. Runs start at hour:minute UTC, then every `every_h` hours."""
    c = t.replace(hour=hour, minute=minute, second=0, microsecond=0) - datetime.timedelta(days=1)
    while c < t:
        c += datetime.timedelta(hours=every_h)
    return c


def next_of(t, times):
    """First start at or after t among several daily run times [(hour, minute), ...]."""
    return min(next_run(t, h, m) for h, m in times)


def arxiv_announce(stamp):
    """When arXiv makes a paper stamped `stamp` public, by arXiv's own table (ARXIV_TABLE).

    Deadlines are 14:00 US Eastern, Monday to Friday. A paper in before a deadline is announced at
    20:00 Eastern that day; the Friday deadline's papers wait until Sunday 20:00. Holidays and
    moderation holds (arXiv says checks can take one to four days) are NOT modelled, so the real
    wait can only be longer than this.
    """
    e = stamp.astimezone(ET)
    d = e.date()
    while not (d.weekday() < 5 and datetime.datetime.combine(d, datetime.time(14), tzinfo=ET) >= e):
        d += datetime.timedelta(days=1)
    if d.weekday() == 4:
        d += datetime.timedelta(days=2)
    return datetime.datetime.combine(d, datetime.time(20), tzinfo=ET).astimezone(UTC)


def to_summer(stamp, winter_monday=datetime.date(2026, 11, 9), summer_monday=datetime.date(2026, 7, 6)):
    """The same US Eastern weekday and wall-clock time, moved into a summer week (Eastern daylight
    time), so the replay can show what changes when arXiv's 20:00 Eastern is 00:00 UTC."""
    e = stamp.astimezone(ET)
    d = summer_monday + (e.date() - winter_monday)
    return datetime.datetime.combine(d, e.time(), tzinfo=ET).astimezone(UTC)


def post_time(link):
    """The time an X post was made, read from the id in its link. None for any other link."""
    m = re.match(r"^https://(?:x|twitter)\.com/[A-Za-z0-9_]{1,20}/status/(\d{15,20})$", link)
    if not m:
        return None
    ms = (int(m.group(1)) >> 22) + X_EPOCH_MS
    return datetime.datetime.fromtimestamp(ms / 1000, UTC)


def self_checks():
    """Each row of arXiv's table, the cron rule, and one post whose time is known. Fail = stop."""
    et = lambda y, mo, d, h, mi=0: datetime.datetime(y, mo, d, h, mi, tzinfo=ET)
    rows = [  # (received, announced): one case inside each row of the table, in the week of 2026-11-09
        (et(2026, 11, 9, 15), et(2026, 11, 10, 20)),    # Mon 14:00 - Tue 14:00 -> Tue 20:00
        (et(2026, 11, 10, 15), et(2026, 11, 11, 20)),   # Tue 14:00 - Wed 14:00 -> Wed 20:00
        (et(2026, 11, 11, 15), et(2026, 11, 12, 20)),   # Wed 14:00 - Thu 14:00 -> Thu 20:00
        (et(2026, 11, 12, 15), et(2026, 11, 15, 20)),   # Thu 14:00 - Fri 14:00 -> Sun 20:00
        (et(2026, 11, 13, 15), et(2026, 11, 16, 20)),   # Fri 14:00 - Mon 14:00 -> Mon 20:00
        (et(2026, 11, 14, 9), et(2026, 11, 16, 20)),    # a Saturday paper -> Mon 20:00
        (et(2026, 11, 9, 13, 59), et(2026, 11, 9, 20)),  # just before Monday's deadline -> Mon 20:00
    ]
    for got_in, want in rows:
        got = arxiv_announce(got_in.astimezone(UTC))
        assert got == want.astimezone(UTC), f"arXiv rule wrong for {got_in}: {got} != {want}"
    d = lambda *a: datetime.datetime(*a, tzinfo=UTC)
    assert next_run(d(2026, 11, 10, 1, 0), 5, 17) == d(2026, 11, 10, 5, 17)
    assert next_run(d(2026, 11, 10, 5, 17), 5, 17) == d(2026, 11, 10, 5, 17)
    assert next_run(d(2026, 11, 10, 5, 18), 5, 17) == d(2026, 11, 11, 5, 17)
    assert next_run(d(2026, 11, 10, 5, 18), 5, 17, 6) == d(2026, 11, 10, 11, 17)
    assert next_of(d(2026, 11, 10, 8, 0), [(1, 17), (7, 17), (13, 17), (19, 17)]) == d(2026, 11, 10, 13, 17)
    # 20:00 Eastern is 01:00 UTC in winter and 00:00 UTC in summer
    assert arxiv_announce(et(2026, 11, 9, 9).astimezone(UTC)).hour == 1
    assert arxiv_announce(to_summer(et(2026, 11, 9, 9).astimezone(UTC))).hour == 0
    # A post whose time is known: NEAR AI's post, shown on X as 2026-11-10 20:38 UTC.
    known = post_time("https://x.com/near_ai/status/2120254883039514982")
    assert known and known.strftime("%Y-%m-%d %H:%M") == "2026-11-10 20:38", f"post-id clock wrong: {known}"
    assert post_time("https://t.me/somechannel/12") is None
    assert read_schedule('    - cron: "17 5 * * *"   # daily') == ([(5, 17)], [(5, 17)])
    two = ('- cron: "17 1 * * *"\n- cron: "17 7 * * *"\n'
           "HUNT_SOURCE: ${{ github.event_name == 'schedule' && (github.event.schedule == '17 1 * * *' && 'all' || 'news') }}")
    assert read_schedule(two) == ([(1, 17)], [(1, 17), (7, 17)])


# ---- real inputs ---------------------------------------------------------------------------

TIME_KEYS = ("finished_utc", "written_utc", "result_utc")


def load_run(rel, root=None):
    """One real hunt record: when it started and ended, and when each source item's first result
    was written. A time recorded inside the run (the result cell or its result file, keys
    TIME_KEYS) is used when there is one; otherwise the result file's modified time, kept only if
    it falls inside the run (after a fresh clone it does not, and the item is left out).
    `time_source` counts which was used."""
    root = ROOT if root is None else root
    H = json.loads((root / rel).read_text())
    start, end = utc(H["started_utc"]), utc(H["finished_utc"])
    first, src = {}, {"recorded": 0, "file_time": 0, "file_time_outside_run": 0}
    for a in H["attacks"]:
        key = (a.get("paper") or {}).get("arxiv_id") if a["source"] == "paper" else \
              (a.get("news") or {}).get("item_id") if a["source"] == "news" else None
        if not key:
            continue
        for r in (a.get("results") or {}).values():
            f = root / r.get("result_json", "")
            rec = next((r[k] for k in TIME_KEYS if r.get(k)), None)
            if rec is None and r.get("result_json") and f.is_file():
                try:
                    rj = json.loads(f.read_text())
                    rec = next((rj[k] for k in TIME_KEYS if isinstance(rj, dict) and rj.get(k)), None)
                except ValueError:
                    rec = None
            if rec is not None:
                t = utc(rec)
                src["recorded"] += 1
            elif r.get("result_json") and f.is_file():
                t = datetime.datetime.fromtimestamp(f.stat().st_mtime, UTC)
                if not (start - datetime.timedelta(seconds=2) <= t <= end + datetime.timedelta(seconds=5)):
                    src["file_time_outside_run"] += 1
                    continue
                src["file_time"] += 1
            else:
                continue
            first[key] = min(first.get(key, t), t)
    return {"record": rel, "mode": H["mode"], "started_utc": iso(start), "finished_utc": iso(end),
            "wall_seconds": H["wall_seconds"], "start": start, "end": end, "first_result": first, "time_source": src, "H": H}


def require_loaded(*runs):
    """Stop (non-zero, nothing written) if any real run gave no first-result time."""
    empty = [r["record"] for r in runs if not r["first_result"]]
    if empty:
        sys.exit("response_time: no result time could be read for " + ", ".join(empty) + ". The result files' "
                 "modified times are not inside the run (a fresh clone sets them to the clone time), and the run "
                 "records no time of its own. Nothing was written.")


def stats(xs):
    xs = sorted(xs)
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "mean_h": round(statistics.fmean(xs), 1), "median_h": round(statistics.median(xs), 1),
            "min_h": round(xs[0], 1), "max_h": round(xs[-1], 1)}


def replay_paper(stamp, paper_times, pipe_s):
    public = arxiv_announce(stamp)
    start = next_of(public, paper_times)
    done = start + datetime.timedelta(seconds=pipe_s)
    return {"stamp_utc": iso(stamp), "public_utc": iso(public), "run_start_utc": iso(start), "results_utc": iso(done),
            "from_stamp_h": round(hours(stamp, done), 2), "from_public_h": round(hours(public, done), 2),
            "arxiv_queue_h": round(hours(stamp, public), 2), "wait_for_run_h": round(hours(public, start), 2),
            "run_h": round(pipe_s / 3600, 2)}


def replay_post(newest, oldest, all_times, paper_times, pipe_all_s, pipe_news_s):
    start = next_of(newest, all_times)
    pipe = pipe_all_s if (start.hour, start.minute) in paper_times else pipe_news_s
    done = start + datetime.timedelta(seconds=pipe)
    return {"newest_post_utc": iso(newest), "oldest_post_utc": iso(oldest), "run_start_utc": iso(start), "results_utc": iso(done),
            "from_newest_h": round(hours(newest, done), 2), "from_oldest_h": round(hours(oldest, done), 2),
            "wait_for_run_h": round(hours(newest, start), 2), "run_h": round(pipe / 3600, 2)}


def split(items, parts):
    """Mean of each part of the wait, over the items: where the hours go."""
    return {p: round(statistics.fmean(i[p] for i in items), 1) for p in parts} if items else {}


def anchors_after_release(minute):
    """Daily run times right after arXiv's 20:00 Eastern release: winter 01:mm, summer 00:mm UTC."""
    return {"winter": [(1, minute)], "summer": [(0, minute)]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fetch-arxiv", action="store_true", help="ask arXiv once for this week's papers and save their stamps")
    ap.add_argument("--date", default=os.environ.get("ARENA_DATE") or datetime.datetime.now(UTC).strftime("%Y-%m-%d"))
    a = ap.parse_args()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", a.date):
        sys.exit("response_time: --date must look like 2026-11-11")
    self_checks()

    paper_times, all_times = read_schedule((ROOT / WORKFLOW).read_text())
    P, N = load_run(PAPERS_RUN), load_run(NEWS_RUN)
    require_loaded(P, N)  # before anything is written
    out_dir = ROOT / "evidence" / f"response-time-{a.date}"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamps_file = out_dir / "arxiv-stamps.json"
    # A papers + news run is taken as the two real runs added up; a news-only run as the news run.
    pipe_all = P["wall_seconds"] + N["wall_seconds"]
    pipe_news = N["wall_seconds"]

    if a.fetch_arxiv:
        import arxiv
        r = arxiv.search_recent(7)
        now = datetime.datetime.now(UTC)
        stamps_file.write_text(json.dumps({
            "fetched_utc": iso(now), "source": "arXiv API, the hunter's own query (tools/hunter/arxiv.py search_recent(7))",
            "returned": r["returned"], "within_7_days": r["within_days"],
            "papers": [{"arxiv_id": p["arxiv_id"], "published": p["published"], "relevance": arxiv.relevance(p)}
                       for p in r["papers"]]}, indent=1) + "\n")

    # ---- what really happened on 2026-11-10 (no simulation) ----
    real_papers, real_news = [], []
    for p in P["H"]["papers"]:
        t = P["first_result"].get(p["arxiv_id"])
        if not t:
            continue
        stamp = utc(p["published"])
        real_papers.append({"arxiv_id": p["arxiv_id"], "stamp_utc": iso(stamp), "public_utc": iso(arxiv_announce(stamp)),
                            "first_result_utc": iso(t), "seconds_into_run": round((t - P["start"]).total_seconds()),
                            "age_from_stamp_h": round(hours(stamp, t), 1),
                            "age_from_public_h": round(hours(arxiv_announce(stamp), t), 1)})
    items = {}
    for it in N["H"]["news"]["items"]:
        ts = sorted(t for t in (post_time(l) for l in it.get("links", [])) if t)
        if ts:
            items[it["item_id"]] = {"item_id": it["item_id"], "status": it["status"], "posts_with_a_time": len(ts),
                                    "newest": ts[-1], "oldest": ts[0]}
    for k, t in sorted(N["first_result"].items(), key=lambda kv: kv[1]):
        if k in items:
            i = items[k]
            real_news.append({"item_id": k, "newest_post_utc": iso(i["newest"]), "oldest_post_utc": iso(i["oldest"]),
                              "first_result_utc": iso(t), "seconds_into_run": round((t - N["start"]).total_seconds()),
                              "age_from_newest_h": round(hours(i["newest"], t), 1),
                              "age_from_oldest_h": round(hours(i["oldest"], t), 1)})

    # ---- the replay, on the current schedule ----
    rp_attacked = [dict(arxiv_id=p["arxiv_id"], **replay_paper(utc(p["stamp_utc"]), paper_times, pipe_all)) for p in real_papers]
    week, week_meta, model_breaks, week_stamps = [], None, [], []
    if stamps_file.is_file():
        import arxiv
        cap = inspect.signature(arxiv.search_recent).parameters["max_results"].default
        S = json.loads(stamps_file.read_text())
        fetched = utc(S["fetched_utc"])
        rel = [p for p in S["papers"] if p["relevance"] > 0]
        week_stamps = [utc(p["published"]) for p in rel]
        week = [dict(arxiv_id=p["arxiv_id"], **replay_paper(utc(p["published"]), paper_times, pipe_all)) for p in rel]
        stamps_all = [utc(p["published"]) for p in S["papers"]]
        newest = max(stamps_all)
        # If arXiv's API showed a paper BEFORE the table says it is public, the rule here is wrong.
        model_breaks = [p["arxiv_id"] for p in S["papers"] if arxiv_announce(utc(p["published"])) > fetched]
        week_meta = {"fetched_utc": S["fetched_utc"], "returned": S["returned"], "within_7_days": S["within_7_days"],
                     "query_cap": cap, "cap_hit": S["returned"] >= cap,
                     "stamps_span_days": round(hours(min(stamps_all), newest) / 24, 1),
                     "relevant": len(rel), "newest_stamp_utc": iso(newest),
                     "newest_stamp_age_at_fetch_h": round(hours(newest, fetched), 1),
                     "papers_listed_before_the_table_says_public": model_breaks}
    attacked_ids = {r["item_id"] for r in real_news}
    rn_all = [dict(item_id=k, status=i["status"], **replay_post(i["newest"], i["oldest"], all_times, paper_times, pipe_all, pipe_news))
              for k, i in sorted(items.items())]
    rn_attacked = [r for r in rn_all if r["item_id"] in attacked_ids]
    newest_seen = max(i["newest"] for i in items.values())

    # ---- what the schedule alone decides ----
    stamps_for_options = week_stamps or [utc(p["stamp_utc"]) for p in real_papers]
    paper_mean = lambda stamps, times: stats([replay_paper(s, times, pipe_all)["from_public_h"] for s in stamps])["mean_h"]
    summer = [to_summer(s) for s in stamps_for_options]
    minute = paper_times[0][1]
    after = anchors_after_release(minute)
    paper_options = []
    for label, times in (("current schedule (papers at " + ", ".join(f"{h:02d}:{m:02d}" for h, m in paper_times) + " UTC)", paper_times),
                         ("the old schedule (05:17 UTC)", [(5, 17)]),
                         (f"one daily run {minute} min after arXiv's release (01:{minute:02d} UTC winter, 00:{minute:02d} UTC summer)", None),
                         (f"every hour at :{minute:02d}", [(h, minute) for h in range(24)])):
        paper_options.append({"option": label,
                              "winter_from_public_mean_h": paper_mean(stamps_for_options, times or after["winter"]),
                              "summer_from_public_mean_h": paper_mean(summer, times or after["summer"])})
    news_options = []
    gaps = lambda times: [(((times[(i + 1) % len(times)][0] * 60 + times[(i + 1) % len(times)][1]) - (h * 60 + m)) % 1440 or 1440) / 60
                          for i, (h, m) in enumerate(times)]
    for label, times in (("current schedule (" + ", ".join(f"{h:02d}:{m:02d}" for h, m in all_times) + " UTC)", all_times),
                         ("the old schedule (05:17 UTC)", [(5, 17)]),
                         (f"every hour at :{minute:02d}", [(h, minute) for h in range(24)])):
        g = gaps(times)
        rows = [replay_post(utc(r["newest_post_utc"]), utc(r["oldest_post_utc"]), times, paper_times if times == all_times else times,
                            pipe_all, pipe_news if times == all_times else pipe_all) for r in rn_all]
        news_options.append({"option": label,
                             # current: news-only runs are shorter; the other options run papers + news each time
                             "any_time_of_day_mean_h": round(sum(x * x / 2 for x in g) / 24 + (pipe_news if times == all_times else pipe_all) / 3600, 1),
                             "any_time_of_day_worst_h": round(max(g) + pipe_all / 3600, 1),
                             "replay_from_newest_post_mean_h": stats([r["from_newest_h"] for r in rows])["mean_h"],
                             "replay_from_newest_post_worst_h": stats([r["from_newest_h"] for r in rows])["max_h"]})

    on_demand = []
    for rel_path in ON_DEMAND_RUNS:
        H = json.loads((ROOT / rel_path).read_text())
        on_demand.append({"record": rel_path, "wall_seconds": H["wall_seconds"],
                          "attacks_run": sum(1 for e in H["attacks"] if e["results"])})

    news_runs = len(all_times)
    R = {
        "what_this_is": "A replay of real publish times against the hunt's schedule. The scheduled hunt has never run on GitHub.",
        "computed_utc": iso(datetime.datetime.now(UTC)),
        "schedule": {"workflow": WORKFLOW, "papers_and_news_at_utc": [f"{h:02d}:{m:02d}" for h, m in paper_times],
                     "news_only_at_utc": [f"{h:02d}:{m:02d}" for h, m in all_times if (h, m) not in paper_times],
                     "elfa_calls_per_day_at_most": 2 * news_runs, "elfa_credits_per_day_about": 2 * 5 * news_runs},
        "pipeline": {"papers_run": {k: P[k] for k in ("record", "started_utc", "finished_utc", "wall_seconds", "time_source")},
                     "news_run": {k: N[k] for k in ("record", "started_utc", "finished_utc", "wall_seconds", "time_source")},
                     "papers_and_news_run_seconds_used": round(pipe_all, 1), "news_only_run_seconds_used": round(pipe_news, 1),
                     "note": "papers + news = the two real runs added up; news only = the real news run; local laptop, already built, --jobs 5; no GitHub start-up or build time"},
        "really_happened_2026_11_10": {"papers": real_papers, "news": real_news,
                                       "newest_post_elfa_cited_utc": iso(newest_seen),
                                       "its_age_when_the_news_run_started_h": round(hours(newest_seen, N["start"]), 1)},
        "replay": {
            "papers_attacked": {"items": rp_attacked, "from_stamp": stats([r["from_stamp_h"] for r in rp_attacked]),
                                "from_public": stats([r["from_public_h"] for r in rp_attacked]),
                                "split_mean_h": split(rp_attacked, ("arxiv_queue_h", "wait_for_run_h", "run_h"))},
            "papers_this_week": {"meta": week_meta, "items": week, "from_stamp": stats([r["from_stamp_h"] for r in week]),
                                 "from_public": stats([r["from_public_h"] for r in week]),
                                 "split_mean_h": split(week, ("arxiv_queue_h", "wait_for_run_h", "run_h"))},
            "news_attacked": {"items": rn_attacked, "from_newest_post": stats([r["from_newest_h"] for r in rn_attacked]),
                              "from_oldest_post": stats([r["from_oldest_h"] for r in rn_attacked]),
                              "split_mean_h": split(rn_attacked, ("wait_for_run_h", "run_h"))},
            "news_all_scored": {"items": rn_all, "from_newest_post": stats([r["from_newest_h"] for r in rn_all]),
                                "from_oldest_post": stats([r["from_oldest_h"] for r in rn_all]),
                                "split_mean_h": split(rn_all, ("wait_for_run_h", "run_h"))},
        },
        "papers_by_schedule": paper_options,
        "news_by_schedule": news_options,
        "on_demand": on_demand,
        "arxiv_rule_source": ARXIV_TABLE,
    }
    (out_dir / "result.json").write_text(json.dumps(R, indent=1) + "\n")
    md = render(R, a.date)
    (ROOT / "evidence" / f"response-time-{a.date}.md").write_text(md)
    print(md)
    if model_breaks:
        print(f"WARNING: arXiv listed {len(model_breaks)} paper(s) before the table says they are public. "
              "The paper numbers above are not to be quoted until this is explained.", file=sys.stderr)
        sys.exit(1)


def line(s):
    if not s.get("n"):
        return "no items"
    return f"mean {s['mean_h']} h, median {s['median_h']} h, shortest {s['min_h']} h, longest {s['max_h']} h (n = {s['n']})"


def where(sp, from_stamp):
    """Where the mean hours of one row go, in words."""
    if not sp:
        return ""
    parts = []
    if from_stamp and "arxiv_queue_h" in sp:
        parts.append(f"{sp['arxiv_queue_h']} h arXiv's own queue before it makes the paper public")
    parts.append(f"{sp['wait_for_run_h']} h waiting for the next run")
    parts.append(f"{sp['run_h']} h the run itself")
    return "; ".join(parts)


def render(R, date):
    rp, pipe, sch = R["replay"], R["pipeline"], R["schedule"]
    real = R["really_happened_2026_11_10"]
    wk = rp["papers_this_week"]["meta"]
    week_label = ""
    if wk:
        week_label = (f"the newest {wk['returned']} papers arXiv's query returned, about {wk['stamps_span_days']} days; "
                      f"{wk['relevant']} relevant")
    sched_words = (f"papers + news at {', '.join(sch['papers_and_news_at_utc'])} UTC"
                   + (f", news only at {', '.join(sch['news_only_at_utc'])} UTC" if sch["news_only_at_utc"] else ""))
    L = [
        f"# Response time: from \"it went public\" to \"Arena has a scored attack\" ({date})", "",
        "**This is a replay, not a live measurement.** The scheduled hunt has never run on GitHub. The",
        "numbers below come from real publish times, the real length of two hunts on one laptop, and",
        f"the current schedule (`{sch['workflow']}`: {sched_words}).",
        f"Made by `tools/hunter/response_time.py`, computed {R['computed_utc']}. All data: `evidence/response-time-{date}/result.json`.", "",
        "\"Scored attack\" means: the attack ran on a local sandbox against every guard on the list and",
        "its result was written. \"Results exist\" means the whole run has ended, because the workflow",
        "only hands results out at the end.", "",
        "## The short answer", "",
        "| Source | Clock starts when | Replay result | Where the mean goes |", "|---|---|---|---|",
        f"| Papers (the {rp['papers_attacked']['from_public']['n']} the real hunt attacked) | arXiv makes the paper public | {line(rp['papers_attacked']['from_public'])} | {where(rp['papers_attacked']['split_mean_h'], False)} |",
        f"| Papers (same {rp['papers_attacked']['from_public']['n']}) | the paper's arXiv stamp | {line(rp['papers_attacked']['from_stamp'])} | {where(rp['papers_attacked']['split_mean_h'], True)} |",
    ]
    if wk:
        L += [f"| Papers ({week_label}) | arXiv makes the paper public | {line(rp['papers_this_week']['from_public'])} | {where(rp['papers_this_week']['split_mean_h'], False)} |",
              f"| Papers (same {wk['relevant']}) | the paper's arXiv stamp | {line(rp['papers_this_week']['from_stamp'])} | {where(rp['papers_this_week']['split_mean_h'], True)} |"]
    L += [
        f"| Hack news (the {rp['news_attacked']['from_newest_post']['n']} items the real hunt attacked) | the newest post the item cites | {line(rp['news_attacked']['from_newest_post'])} | {where(rp['news_attacked']['split_mean_h'], False)} |",
        f"| Hack news (same items) | the oldest post the item cites | {line(rp['news_attacked']['from_oldest_post'])} | |",
        f"| Hack news (all {rp['news_all_scored']['from_newest_post']['n']} items with a post time) | the newest post the item cites | {line(rp['news_all_scored']['from_newest_post'])} | {where(rp['news_all_scored']['split_mean_h'], False)} |",
        "",
        f"A papers + news run is taken to last {pipe['papers_and_news_run_seconds_used'] / 60:.1f} minutes (the real papers hunt, "
        f"{pipe['papers_run']['wall_seconds']} s, plus the real news hunt, {pipe['news_run']['wall_seconds']} s); a news-only run",
        f"{pipe['news_only_run_seconds_used'] / 60:.1f} minutes. The last column says where each row's hours go. Counted from when a",
        "paper is public, or from a post, most of the wait is the gap until the next run. Counted from a paper's arXiv stamp, most",
        "of it is arXiv's own queue before it makes the paper public, which no schedule can shorten.", "",
    ]
    if wk and wk.get("cap_hit"):
        L += [f"**Cap hit.** arXiv's query returns at most {wk['query_cap']} papers, and it returned {wk['returned']}, all inside 7 days. So the",
              f"week rows cover only the newest {wk['returned']} (stamps spanning about {wk['stamps_span_days']} days), not the whole week.", ""]
    L += [f"Elfa use on this schedule: {len(sch['papers_and_news_at_utc']) + len(sch['news_only_at_utc'])} news hunts a day, each at most 2 calls of about 5 credits:",
          f"at most {sch['elfa_calls_per_day_at_most']} calls, about {sch['elfa_credits_per_day_about']} credits a day.", "",
          "## What really happened on 2026-11-10 (no simulation)", "",
          "These hunts were started by hand, so they do not measure a schedule. They do show the real age",
          "of each source when its first attack result was written.", ""]
    ts = [pipe[k]["time_source"] for k in ("papers_run", "news_run")]
    if sum(t["file_time"] for t in ts):
        L += [f"The first-result times below are the result files' **modified times** ({sum(t['file_time'] for t in ts)} files): the runs",
              "record no time of their own for each result. A copy of the files that changes those times (a fresh clone) makes this",
              "section impossible to rebuild, and the script then stops instead of writing it.", ""]
    L += ["| Paper | arXiv stamp (UTC) | First result (UTC) | Into the run | Age from stamp | Age from public |", "|---|---|---|---|---|---|"]
    for p in real["papers"]:
        L.append(f"| {p['arxiv_id']} | {p['stamp_utc']} | {p['first_result_utc']} | {p['seconds_into_run']} s | {p['age_from_stamp_h']} h | {p['age_from_public_h']} h |")
    L += ["", "| News item | Newest cited post (UTC) | First result (UTC) | Into the run | Age from newest post | Age from oldest post |", "|---|---|---|---|---|---|"]
    for n in real["news"]:
        L.append(f"| {n['item_id']} | {n['newest_post_utc']} | {n['first_result_utc']} | {n['seconds_into_run']} s | {n['age_from_newest_h']} h | {n['age_from_oldest_h']} h |")
    L += ["",
          f"The newest post in any Elfa item was {real['its_age_when_the_news_run_started_h']} h old when the news hunt started",
          f"({real['newest_post_elfa_cited_utc']}). That is the only measure here of how fresh Elfa's summaries are.", "",
          "## What the schedule decides", "",
          "**Papers.** arXiv makes new papers public once a day, at 20:00 US Eastern: 01:00 UTC in winter, 00:00 UTC in summer.",
          "So what matters is how soon after that hour the papers run starts, not how many runs there are. Mean hours from",
          "\"public\" to results, same papers, winter as they really were, summer by moving each one to the same Eastern",
          "weekday and time in a July week:", "",
          "| Papers run at | Winter: mean | Summer: mean |", "|---|---|---|"]
    for o in R["papers_by_schedule"]:
        L.append(f"| {o['option']} | {o['winter_from_public_mean_h']} h | {o['summer_from_public_mean_h']} h |")
    cur, after = R["papers_by_schedule"][0], R["papers_by_schedule"][2]
    L += ["",
          f"The current 01:17 UTC run is the first one after the winter release. In summer the release is an hour earlier, so the",
          f"same run gives {cur['summer_from_public_mean_h']} h instead of {after['summer_from_public_mean_h']} h for a run moved to 00:17 UTC.", "",
          "**News.** Posts arrive all day, so news waits for whichever run comes next. \"Any time of day\" is plain arithmetic: an",
          "item that appears at a random moment waits on average half of the gap it falls into, at worst the longest gap, plus the run.", "",
          "| News runs at | Any time of day: mean | worst | Replay, from newest post: mean | longest |", "|---|---|---|---|---|"]
    for o in R["news_by_schedule"]:
        L.append(f"| {o['option']} | {o['any_time_of_day_mean_h']} h | {o['any_time_of_day_worst_h']} h | {o['replay_from_newest_post_mean_h']} h | {o['replay_from_newest_post_worst_h']} h |")
    L += ["", "## On demand", "",
          "Asking for one named paper does not wait for the schedule. Two real runs on the laptop:", ""]
    for o in R["on_demand"]:
        L.append(f"- `{o['record']}`: {o['wall_seconds']} s, {o['attacks_run']} attacks run")
    L += ["", "## What this does not show", "",
          "- **Nothing here ran on GitHub.** GitHub adds time to start a machine and build the code, and its",
          "  scheduled runs can start late. None of that is measured, so real numbers will be somewhat higher.",
          "- **Small sample.** One papers hunt and one news hunt, one day, one laptop.",
          f"- **arXiv rule.** \"Public\" is worked out from arXiv's own table ({R['arxiv_rule_source']}).",
          "  Holidays and moderation holds are left out, and it is assumed arXiv's search lists a paper as",
          "  soon as it is announced. Both can only make the real wait longer.",
          "- **Summer figures** move this week's papers to a July week; they are not papers from a real summer week."]
    if wk:
        L.append(f"  One check on that rule: arXiv was asked at {wk['fetched_utc']}; the newest paper it listed was stamped "
                 f"{wk['newest_stamp_age_at_fetch_h']} h earlier, and {len(wk['papers_listed_before_the_table_says_public'])} "
                 f"of {wk['within_7_days']} papers were listed before the table says they are public.")
    L += ["- **Elfa.** When Elfa first had each summary is not known. An item cannot exist before its newest",
          "  post, so \"from the newest post\" is the shortest the wait could be, and \"from the oldest post\"",
          "  is the wait since the story started. Post times are read from the post id in the link; no post",
          "  was opened. Telegram links carry no time and are left out.",
          "- **A news item is a retelling of posts**, an unchecked lead. \"Arena scored an attack built from",
          "  it\" does not mean the hack happened as told, and \"held\" does not mean a guard is safe.",
          "- **Picked items only.** A hunt attacks at most 5 papers and 5 news items. Anything ranked lower",
          "  waits for a later run or is never attacked.", ""]
    return "\n".join(L)


if __name__ == "__main__":
    main()
