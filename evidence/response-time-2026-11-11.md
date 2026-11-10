# Response time: from "it went public" to "Arena has a scored attack" (2026-11-11)

**This is a replay, not a live measurement.** The scheduled hunt has never run on GitHub. The
numbers below come from real publish times, the real length of two hunts on one laptop, and
the current schedule (`.github/workflows/hunt.yml`: papers + news at 01:17 UTC, news only at 07:17, 13:17, 19:17 UTC).
Made by `tools/hunter/response_time.py`, computed 2026-11-10T22:02:40Z. All data: `evidence/response-time-2026-11-11/result.json`.

"Scored attack" means: the attack ran on a local sandbox against every guard on the list and
its result was written. "Results exist" means the whole run has ended, because the workflow
only hands results out at the end.

## The short answer

| Source | Clock starts when | Replay result | Where the mean goes |
|---|---|---|---|
| Papers (the 5 the real hunt attacked) | arXiv makes the paper public | mean 0.7 h, median 0.7 h, shortest 0.7 h, longest 0.7 h (n = 5) | 0.3 h waiting for the next run; 0.4 h the run itself |
| Papers (same 5) | the paper's arXiv stamp | mean 38.8 h, median 38.6 h, shortest 9.5 h, longest 73.6 h (n = 5) | 38.1 h arXiv's own queue before it makes the paper public; 0.3 h waiting for the next run; 0.4 h the run itself |
| Papers (the newest 100 papers arXiv's query returned, about 3.9 days; 30 relevant) | arXiv makes the paper public | mean 0.7 h, median 0.7 h, shortest 0.7 h, longest 0.7 h (n = 30) | 0.3 h waiting for the next run; 0.4 h the run itself |
| Papers (same 30) | the paper's arXiv stamp | mean 43.6 h, median 39.3 h, shortest 6.8 h, longest 78.3 h (n = 30) | 42.9 h arXiv's own queue before it makes the paper public; 0.3 h waiting for the next run; 0.4 h the run itself |
| Hack news (the 4 items the real hunt attacked) | the newest post the item cites | mean 2.9 h, median 2.5 h, shortest 1.0 h, longest 5.5 h (n = 4) | 2.7 h waiting for the next run; 0.2 h the run itself |
| Hack news (same items) | the oldest post the item cites | mean 11.1 h, median 9.7 h, shortest 3.6 h, longest 21.3 h (n = 4) | |
| Hack news (all 24 items with a post time) | the newest post the item cites | mean 3.7 h, median 3.9 h, shortest 0.6 h, longest 5.9 h (n = 24) | 3.5 h waiting for the next run; 0.2 h the run itself |

A papers + news run is taken to last 24.2 minutes (the real papers hunt, 693.0 s, plus the real news hunt, 757.2 s); a news-only run
12.6 minutes. The last column says where each row's hours go. Counted from when a
paper is public, or from a post, most of the wait is the gap until the next run. Counted from a paper's arXiv stamp, most
of it is arXiv's own queue before it makes the paper public, which no schedule can shorten.

**Cap hit.** arXiv's query returns at most 100 papers, and it returned 100, all inside 7 days. So the
week rows cover only the newest 100 (stamps spanning about 3.9 days), not the whole week.

Elfa use on this schedule: 4 news hunts a day, each at most 2 calls of about 5 credits:
at most 8 calls, about 40 credits a day.

## What really happened on 2026-11-10 (no simulation)

These hunts were started by hand, so they do not measure a schedule. They do show the real age
of each source when its first attack result was written.

The first-result times below are the result files' **modified times** (102 files): the runs
record no time of their own for each result. A copy of the files that changes those times (a fresh clone) makes this
section impossible to rebuild, and the script then stops instead of writing it.

| Paper | arXiv stamp (UTC) | First result (UTC) | Into the run | Age from stamp | Age from public |
|---|---|---|---|---|---|
| 2611.08811v1 | 2026-11-06T00:06:13Z | 2026-11-10T16:21:22Z | 370 s | 112.3 h | 39.4 h |
| 2611.11266v1 | 2026-11-08T09:40:52Z | 2026-11-10T16:22:19Z | 426 s | 54.7 h | 15.4 h |
| 2611.12636v1 | 2026-11-09T16:13:20Z | 2026-11-10T16:23:16Z | 483 s | 24.2 h | 15.4 h |
| 2611.11506v1 | 2026-11-08T17:20:48Z | 2026-11-10T16:24:31Z | 559 s | 47.1 h | 15.4 h |
| 2611.11305v1 | 2026-11-08T11:05:45Z | 2026-11-10T16:24:50Z | 578 s | 53.3 h | 15.4 h |

| News item | Newest cited post (UTC) | First result (UTC) | Into the run | Age from newest post | Age from oldest post |
|---|---|---|---|---|---|
| n-59ee7b1817 | 2026-11-10T17:21:20Z | 2026-11-10T19:42:53Z | 641 s | 2.4 h | 11.5 h |
| n-f473f3d4ba | 2026-11-09T12:28:41Z | 2026-11-10T19:43:37Z | 684 s | 31.2 h | 33.8 h |
| n-ae93287baa | 2026-11-07T08:00:00Z | 2026-11-10T19:43:56Z | 704 s | 83.7 h | 99.6 h |
| n-00c44f696f | 2026-11-10T10:35:05Z | 2026-11-10T19:44:38Z | 746 s | 9.2 h | 14.4 h |

The newest post in any Elfa item was 1.9 h old when the news hunt started
(2026-11-10T17:38:43Z). That is the only measure here of how fresh Elfa's summaries are.

## What the schedule decides

**Papers.** arXiv makes new papers public once a day, at 20:00 US Eastern: 01:00 UTC in winter, 00:00 UTC in summer.
So what matters is how soon after that hour the papers run starts, not how many runs there are. Mean hours from
"public" to results, same papers, winter as they really were, summer by moving each one to the same Eastern
weekday and time in a July week:

| Papers run at | Winter: mean | Summer: mean |
|---|---|---|
| current schedule (papers at 01:17 UTC) | 0.7 h | 1.7 h |
| the old schedule (05:17 UTC) | 4.7 h | 5.7 h |
| one daily run 17 min after arXiv's release (01:17 UTC winter, 00:17 UTC summer) | 0.7 h | 0.7 h |
| every hour at :17 | 0.7 h | 0.7 h |

The current 01:17 UTC run is the first one after the winter release. In summer the release is an hour earlier, so the
same run gives 1.7 h instead of 0.7 h for a run moved to 00:17 UTC.

**News.** Posts arrive all day, so news waits for whichever run comes next. "Any time of day" is plain arithmetic: an
item that appears at a random moment waits on average half of the gap it falls into, at worst the longest gap, plus the run.

| News runs at | Any time of day: mean | worst | Replay, from newest post: mean | longest |
|---|---|---|---|---|
| current schedule (01:17, 07:17, 13:17, 19:17 UTC) | 3.2 h | 6.4 h | 3.7 h | 5.9 h |
| the old schedule (05:17 UTC) | 12.4 h | 24.4 h | 14.4 h | 23.8 h |
| every hour at :17 | 0.9 h | 1.4 h | 0.9 h | 1.4 h |

## On demand

Asking for one named paper does not wait for the schedule. Two real runs on the laptop:

- `evidence/hunts/2026-11-10-paper-abc6e6.json`: 273.2 s, 4 attacks run
- `evidence/hunts/2026-11-10-paper-cd8587.json`: 107.8 s, 2 attacks run

## What this does not show

- **Nothing here ran on GitHub.** GitHub adds time to start a machine and build the code, and its
  scheduled runs can start late. None of that is measured, so real numbers will be somewhat higher.
- **Small sample.** One papers hunt and one news hunt, one day, one laptop.
- **arXiv rule.** "Public" is worked out from arXiv's own table (https://info.arxiv.org/help/availability.html).
  Holidays and moderation holds are left out, and it is assumed arXiv's search lists a paper as
  soon as it is announced. Both can only make the real wait longer.
- **Summer figures** move this week's papers to a July week; they are not papers from a real summer week.
  One check on that rule: arXiv was asked at 2026-11-10T21:33:33Z; the newest paper it listed was stamped 26.7 h earlier, and 0 of 100 papers were listed before the table says they are public.
- **Elfa.** When Elfa first had each summary is not known. An item cannot exist before its newest
  post, so "from the newest post" is the shortest the wait could be, and "from the oldest post"
  is the wait since the story started. Post times are read from the post id in the link; no post
  was opened. Telegram links carry no time and are left out.
- **A news item is a retelling of posts**, an unchecked lead. "Arena scored an attack built from
  it" does not mean the hack happened as told, and "held" does not mean a guard is safe.
- **Picked items only.** A hunt attacks at most 5 papers and 5 news items. Anything ranked lower
  waits for a later run or is never attacked.
