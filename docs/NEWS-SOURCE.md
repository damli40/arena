# News source for the hunter

The hunter has two places to find attack ideas: recent security papers (arXiv) and recent hack
news. This page is about the news.

```
./run-arena.sh hunt --source news     # news only
./run-arena.sh hunt --source all      # papers, then news
./run-arena.sh hunt                   # papers only (the default, unchanged)
```

## What it reads

[Elfa AI](https://elfa.ai) watches crypto posts on X and Telegram. Its `/v2/data/event-summary`
endpoint takes a few keywords and a time window (7 days by default) and returns short written
summaries of what people posted, each with links to the posts. The hunter asks two questions:

| query | keywords |
|---|---|
| `agents-and-payments` | AI agent drained, agent wallet exploit, prompt injection, x402 exploit, agent overspend |
| `contract-exploits` | double spend, replay attack, approval exploit, allowance exploit, smart contract hack |

Only the summary text is used. The posts behind the links are never opened.

## What happens to an item

1. **Cleaned.** Control characters out, whitespace collapsed, at most 1500 characters. The quote
   markers `<<<NEWS` / `NEWS>>>` are removed so the text cannot close its own quoted block. Phrases
   that look like instructions to a model ("ignore previous instructions", "you are now") are
   flagged in the hunt file, with the same pattern used for paper text.
2. **Deduped.** An item whose post link appeared in an earlier hunt is skipped. The links are kept
   in the same used-list as the papers (`evidence/hunts/used-papers.json`, keys `news:<link>`).
3. **Scored.** One Muse call scores every new item (up to 20): does it map to a payment guard at
   all, and if so novelty + distance from the attacks already in the library + how clearly it
   reports the attack worked (0-15, the same scale as papers). An item maps only if Muse says so
   and names a mechanism a payment guard has (a race, a repeat pay, expiry, a cap, injection, ...);
   the code checks the second part. Most hacks (stolen keys, phishing, bridges, oracles, price
   manipulation) **don't map**. They are logged as "doesn't map" with the reason. No attack is
   forced out of them.
4. **Attacked.** The top 5 items that map get one Muse call each (plus one repair try). Muse sees
   the summary only inside a block marked untrusted, and answers in the fixed step vocabulary.
   The same validator, duplicate check and sandbox run apply as for papers. A news attack carries
   `meta.source: "news"` and `meta.news: {item_id, date, links}`; the links come from Elfa's reply,
   never from the model. It joins `sequences-paper/` (the folder for everything the hunter found)
   only after it ran cleanly on every guard.

## Cost and caps

| what | cap |
|---|---|
| Elfa event-summary calls | 2 per hunt (hard cap; `--max-elfa-calls` can only lower it) |
| Elfa credits | about 5 per call, so about 10 per news hunt. The free tier has 1000 a month, fails closed when they run out, and never bills |
| Elfa timeout | 150 s per call (a call takes 30-120 s) |
| news items attacked | 5 per hunt (`--max-news-items`) |
| Muse calls | 20 per hunt, shared with papers (1 scoring + up to 2 per attacked item) |

The key: `ELFA_API_KEY` in the environment (CI secret) or `~/.config/arena/news.env` (mode 600),
the same way the Muse key lives in `~/.config/arena/model.env`. Without it, the news source is
skipped with a log line and the rest of the hunt runs. The raw Elfa replies are cached next to the
hunt's evidence (`evidence/hunts/<hunt id>/elfa-*.json`).

## The caveat: an unchecked lead

A news summary is a retelling of tweets. It says people posted about a hack, not that the hack
happened as told, and the summary can be wrong. A news attack shows that a mechanism someone posted
about can be tried against a guard. It is not a reproduction of that incident, and the board marks
it "from the news (unchecked lead)".
