# Fetch benchmark: gold set and decoys

This folder holds the answer key for a fetcher that does not exist yet.

The hunter reads new papers and news, then turns them into attacks. Today it fetches with two small
functions that can come back empty and still look fine. A planned fetch layer will replace them. Before
anyone writes it, this folder fixes what "fetched well" means, so the fetcher cannot be tuned to pass.

## What is here

- `gold.public.json`: 50 items. 22 are gold: real items the fetcher must put in its queue. 28 are
  decoys: real items it must keep out of lane G.
- `COMMITMENT.json`: the hash of 22 more items (10 gold, 12 decoys) kept outside this repo.

Each item has a title, a link, a date, the lanes it belongs in, and the reason. There is no full text.

The three lanes:

- **G**, guard attack: a payment action going wrong through ordering, repetition, limits, expiry or
  caller identity. In practice, one of Arena's attack families.
- **T**, Arena's own threat model: something Arena runs on (NEAR AI Cloud, GitHub Actions, Elfa, arXiv,
  the NEAR sandbox) is compromised.
- **O**, out of scope for the guard library.

An item can list two lanes when either answer is fair. A fetcher's lane is right if it is in the list.

## Where the items come from

| Group | Total | Labelled `biased` |
|---|---|---|
| Papers and news the hunter already picked (13 attacked, 1 picked but its model call timed out) | 14 gold | yes |
| Papers the hunter never saw: its arXiv search returns at most 100 results, which on Nov 10 and 11 covered about 3.8 of 7 days, so papers from Nov 3 to 5 were cut off | 10 gold | no |
| NEAR incidents and advisories, each checked against its primary source (a project post, the finder's post, or OSV) | 8 gold | no |
| Papers and news the hunter saw and turned down | 40 decoys | mostly yes |

`biased: true` means the current hunter's own filter picked or judged the item. Those items show the
fetcher agrees with today's filter; they say little about what today's filter misses.

## How to check the private part never changed

The private items will be published after 5 scored fetcher versions, together with the random seed that
chose which items went private. When they are, anyone can run, with no network:

```
python3 -I -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" gold.private.json
```

and compare the output with `private_file_sha256` in `COMMITMENT.json`. If the private file was edited
after this commit, even by one character, the hashes differ. The git history shows when
`COMMITMENT.json` was committed, so the private part was fixed before any fetcher was scored.

The seed can be checked the same way against `seed_sha256`. With the seed, the split can be re-run:
each item's rank is `sha256("<seed>:<item id>")`, items are sorted by rank within gold and within decoys,
and the lowest 30% went private.

## Limits

- One person labelled every item. The hash proves the labels did not change; it does not prove they are
  right.
- The arXiv cut-off was reconstructed by re-running the hunter's query on Nov 12. The records keep only
  the top 10 papers each hunt scored, not all 100 it received, so the exact edge is inferred.
- News items are Elfa AI summaries of posts on X. Their dates come from the X post id; the posts were not
  opened.
- 32 gold items, not the plan's 40. Candidates that did not fit cleanly as gold or decoy were left out
  rather than forced in.
