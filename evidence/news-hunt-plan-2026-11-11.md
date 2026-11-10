# News source for the hunter: plan (written before any code and before the real run, 2026-11-10 local / Nov 11 plan id)

Goal (Dami, Nov 11): a second source for the paper hunter. Besides recent papers, it reads recent
hack news from the Elfa AI API. Everything after the source stays the same: Muse turns one news
item into attacks written as data in the fixed step vocabulary, the existing validator checks them,
and they run on the LOCAL sandbox only, against the guards in `guards/registry.json`.

## What Elfa is, in plain words

Elfa watches crypto posts on X and Telegram. Its `/v2/data/event-summary` endpoint takes a few
keywords and a time window and returns short written summaries of what people posted about, each
with the links to the posts it summarised. It is a retelling of tweets, so every summary is an
**unchecked lead**: it says people talked about a hack, not that the hack happened as told.

Checked today with one free call (`/v2/key-status`, costs 0 credits; usage stayed at 0 across two
calls): free tier, overage off (it fails closed, never bills), 852 credits left this month.
Known from the Sep 2 test: event-summary costs 5 credits per call and takes 30-120 s, so the
timeout is 150 s. `keyword-mentions` has no text and `trending-narratives` is broken; not used.

Note found today: the key-status reply contains the key itself and the account email. The hunt
never calls key-status and never caches its reply.

## Design

1. `tools/hunter/news.py` (stdlib only): one function per event-summary call, a hard cap of
   **2 calls per hunt** (counted in the hunt file like the Muse cap; the cap cannot be raised by a
   flag), 150 s timeout, reply capped at 2 MB. The raw reply of each call is cached in the hunt's
   evidence folder (`evidence/hunts/<hunt id>/elfa-<n>.json`). The key is loaded like
   `MUSE_API_KEY`: env `ELFA_API_KEY`, else `~/.config/arena/news.env` (mode 600). It goes in
   the `x-elfa-api-key` header only, never in a URL, a log or a file.
2. **Keywords** (Elfa takes a comma list; `searchType=or`; window 7 days by default):
   - call 1, *agents and payments*: `AI agent drained`, `agent wallet exploit`, `prompt injection`,
     `x402 exploit`, `agent overspend`
   - call 2, *contract exploits that look like payment bugs*: `double spend`, `replay attack`,
     `approval exploit`, `allowance exploit`, `smart contract hack`
3. **Untrusted text.** Each summary is cleaned (control characters out, whitespace collapsed,
   at most 1500 characters), the quote markers `<<<NEWS` / `NEWS>>>` are removed from it so it
   cannot close its own quoted block, and phrases that look like instructions are flagged with the
   same pattern used for papers. It reaches Muse only inside a block marked untrusted. Links are not
   sent to Muse. **No URL from a summary is ever fetched**: links are kept only if they are plain
   https post links (x.com, twitter.com, t.me) and are written to the evidence as text.
4. **Dedupe across runs**: a news item is used once. Its post links go into the same used-list as
   the papers (`evidence/hunts/used-papers.json`, keys `news:<link>`). An item any of whose links
   was used before is skipped.
5. **Scoring before attacking**, the same 0-15 as papers: novelty (Muse) + distance from the
   library (computed here from attack families) + reported success (Muse). Muse also says whether
   the item maps to a payment guard at all. An item **does not map** when Muse says so OR when its
   only family is `other` (decided by code, not only the model). Those are logged as "doesn't map"
   with the reason, and no attack is asked for. Most hacks (key theft, bridges, oracle
   manipulation) should land here.
6. **Attacks** from news carry `meta.source = "news"` and `meta.news = {item_id, date, links}`.
   The links come from Elfa's reply, never from the model. Same validator, same dedupe, same
   run on every guard, same "join the library only after running cleanly on every guard".
7. **Command**: `./run-arena.sh hunt --source papers|news|all`. Default stays `papers`, so the
   old command does exactly what it did. For `--source news`, combining library attacks and memory
   re-runs default to off (they are not about the news); they can be turned on with the old flags.
8. **Missing key**: if `ELFA_API_KEY` is absent, the news source is skipped with a log line and
   the hunt still runs (papers, if asked for, and the canary).
9. **Board**: cells carry the attack's source; attacks from the news show "from the news" with
   the date and one post link.
10. **CI**: `ELFA_API_KEY` is an optional secret; the scheduled hunt uses `--source all`. Same
    permissions (`contents: read`), same pinned action SHAs. `ci-local.sh` uses a canned news
    reply instead of Elfa (no network). The artifact secret scan also refuses `ELFA_API_KEY=` and
    `x-elfa-api-key`.

## Checks and expected outcomes

| # | Check | Expected |
|---|---|---|
| N1 | unit tests, including: a summary with injected instructions and a fake closing marker; Muse reply asking for an owner actor; Elfa cap; no key; dedupe by link; doesn't-map logging | all pass; injected summary flagged, its marker removed, the owner-actor attack rejected by the validator |
| N2 | `validate.py --self-test` and `validate.py` on the library | schema and validator agree with the new `news` source; all library files still valid |
| N3 | `ci-local.sh` (offline, canned news + canned Muse) | drift check passes; news item attacked; artifact secret-scanned |
| N4 | ONE real news hunt: `./run-arena.sh hunt --source news` | at most 2 Elfa calls (10 credits), at most 20 Muse calls. My expectation: 5-20 items returned; most of them are about key theft, phishing, bridges or price manipulation and get logged as "doesn't map"; 0-3 items map, mostly to prompt injection or a replay/double pay. Any attack from them is most likely a variant of attacks already in the library, so I expect breaks only on the 3 leaky-on-purpose controls and 0 on vault-a, native-fixed, guard-fixed. Zero usable items is a valid result and will be reported as such |
| N5 | `./verify.sh fast` after | same pass count as before; saved scores unchanged; files verify rewrites are compared with HEAD and restored |

The real hunt runs once. If a prompt is changed after seeing its result, that is said plainly and
any later run is marked tuned.

## Not in scope

- Checking whether a news item is true. The hunt file and the docs call it an unchecked lead.
- Reading the posts behind the links. Only Elfa's summary text is used.
- Testnet or mainnet. Local sandbox only.

## Deviations during the build

1. **Scoring is capped at 20 items per hunt.** Not in the plan. The real Elfa replies returned 24
   new items; the 4 past the cap are logged "not scored: left for a later hunt" and are NOT marked
   used, so a later hunt can still pick them up.
2. **Untrusted text in the markdown evidence is escaped** (`[ ] < > | ` ! \`), so a summary cannot
   form a link, an image or HTML that a markdown viewer would load. Not in the plan; same aim as
   "no URL is ever fetched".
3. **An existing test had a hidden size limit.** `test_memory_and_picks` asked for at most 50
   library re-runs; once the real hunt added 6 attacks, the library passed 50 and the test's
   attack fell off the list. The code was right; the test now asks for room for every pick.
4. **One wording fix after the real run, not a re-run.** The hunt file said "Nothing picked: every
   library attack has been tried" under the memory section, but memory re-runs were simply off for
   `--source news`. I fixed the wording in `hunt.py` and re-rendered the markdown from the saved
   hunt JSON (one line changed). No prompt was changed; the run is not tuned.

## Outcomes (filled in after the run, 2026-11-10 local)

| # | Result |
|---|---|
| N1 | 42 unit tests pass (29 old + 13 new in `tools/hunter/tests/test_news.py`). The injected summary was flagged (2 phrases), both quote markers removed, the owner-actor attack rejected by the validator, model-supplied links rejected |
| N2 | `validate.py --self-test` ok; 48 library files valid (42 before + 6 from the news hunt) |
| N3 | `ci-local.sh` passed with `HUNT_SOURCE=all`: drift check ok, canned Elfa (no network), 3 new items: 1 mapped and attacked, 2 "doesn't map" (including the injected one); the news attack ran on all 6 guards; artifact secret-scanned, 146 files |
| N4 | Real hunt `2026-11-10-news-21d429` (below) |
| N5 | `./verify.sh fast` after the real hunt: 5 passed, 0 failed. It rewrote 10 tracked result files and 2 logs; their scores and step outcomes equal HEAD once timestamps and fresh sandbox account names are set aside (0 differences), and all were restored from git. The 4 hash-committed evidence files are byte-identical (sha256 checked before and after) |

**Real hunt `2026-11-10-news-21d429`**, one run, untuned:

- Elfa: 2 calls (61 s, 65 s), **10 credits measured** (key-status usage went 0 -> 10; 842 of
  this month's 852 left). 31 items returned, 7 repeated across the two queries, 24 new, 20 scored.
- Mapping: 9 of 20 scored items mapped to a payment guard by Muse's score, 11 did not (Binance
  theft and its aftermath, phishing approvals, a bridge kill switch, Kaspa block times, product
  news). Of the 5 attacked, 1 more turned out not to map when Muse was asked for attacks (a budget
  proposal, no mechanism). So **4 items made attacks**, all from the agent/payment query, none from
  the contract-exploit query.
- What mapped is mostly **commentary about prompt injection**, not incidents: 7 of the 9 "maps"
  are injection talk. Muse's "maps" was looser than I expected. The one reported loss among them
  (agents moved about $150K after a Morse-code instruction; an unchecked lead) became 2 injection
  attacks.
- Muse: 6 of 20 calls. 10 attacks proposed, 0 rejected, 4 duplicates dropped (2 within the hunt,
  2 equal to library attacks: `scripted-06-pay-removed-payee` and an earlier paper attack).
- **6 attacks run x 6 guards = 36 attempts: 0 broke anything**, including the 3 leaky-on-purpose
  controls. 5 of the 6 are injection attacks (run as the pays a fully fooled agent makes; every
  guard refuses over-cap, cancelled, expired and removed-payee invoices), 1 is a race of split pays
  against the daily cap. The canary was OK (the known race broke the 3 leaky controls, the rest
  held), so the bench was not blind.
- All 6 joined `sequences-paper/` as `valid-nothing-broke`.

Against my expectation: more items (31, not 5-20), more "maps" (9, not 0-3), and the leaky
controls did not break on any news attack (I expected the news to produce at least one race
variant that hits them; the one race it wrote attacks the cap, which those controls keep).
