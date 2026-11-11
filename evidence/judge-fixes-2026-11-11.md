# Fixes from two independent reviews, checked on a fresh copy (2026-11-11)

After the build was frozen (`dd0a5ae`), two reviewers with no prior context judged it: one did what
the hackathon's screeners do (run the README, check each claim), one scored it on the judging
criteria. These are the problems both confirmed, what changed, and the fresh-copy run that checks
the result.

## What changed

| Problem found | Change | Commit |
|---|---|---|
| The first documented command (`./verify.sh fast`) overwrote 13 committed evidence files when run on the date the evidence carries, so a judge saw a dirty tree | Fresh runs now write to `runs/<time>/` (gitignored). `ARENA_RECORD=1` writes into `evidence/` on purpose | `c208b45` |
| `tools/injection/rescore.py` printed "every recipient is an approved creditor" as fixed text | The line is now computed from the data, and a different line prints if it is not true | `c208b45` |
| 11 hunter tests failed on a fresh copy until the harness was built | Tests stub only the missing guard file, so they pass before any build | `f4621fe` |
| Name checks used `re.match(...$)`, which accepts a trailing newline (`"pay\n"`) | `fullmatch`, with tests | `f4621fe` |
| Stale numbers and pointers (a `reconcile` row, TLA check count, verify timings, a testnet date, paper reads) and two files that read as private working notes | Fixed or reworded | `7bd7ee6` |
| Missing limits: the score uses the guard's own invoice status; expiry is not scored without timestamps; on-chain results do not carry the guard's mode; the proof tools' prerequisites were buried; mapping help calls a hosted model | Stated in README Limits, a "You need" list, and `docs/CHECK-YOUR-GUARD.md` (`--no-muse` stops the call) | `acb1632` |

Not changed here, by design: scoring logic and every reported number, the on-chain contract, and
committed evidence bodies.

## Fresh-copy run

Commit `acb1632` exported with `git archive` into an empty folder, put under a new git repository so
`git status` shows any file a run changes, then these commands in this order. One Mac, Apple
silicon; Rust and the sandbox were already installed. (A first attempt failed during an internet
outage: the build could not download the sandbox. This is the second, complete run.)

| # | Command | Exit | Time | Key line |
|---|---|---|---|---|
| 1 | hunter tests, before anything was built | 0 | 1 s | `Ran 79 tests`, `OK` |
| 2 | `./verify.sh fast` | 0 | 420 s | `verify: 5 passed, 0 failed (mode=fast)`, logs in `runs/<time>-verify-fast/` |
| 3 | `./run-arena.sh replay sequences-paper/p210408638-1-reentrancy-async-double-pay.json --target control` | 0 | 15 s | `UNAUTHORISED PAYOUT = 200   (beyond-authorised 200 + above-cap 0)` |
| 4 | `ARENA_AGENT=compromised python3 -I tools/injection/run.py && python3 -I tools/injection/rescore.py` | 0 | 78 s | `Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).` |
| 5 | `(cd harness && cargo test --release)` | 0 | 16 s | `62 passed; 0 failed; 1 ignored` |
| 6 | `python3 -I tools/check/tests/test_check.py` | 0 | 3 s | `Ran 105 tests`, `OK` |
| 7 | hunter tests, after building | 0 | 1 s | `Ran 79 tests`, `OK` |
| 8 | `node --test tools/lookup/test.mjs` | 0 | 5 s | `pass 37`, `fail 0` |
| 9 | `./arena check targets/vault-a/vault_a.wasm` | 0 | 277 s | `arena: held 51/51 (...)` |
| 10 | `./arena check targets/leaky-control-v2/leaky_control.wasm` | 1 | 277 s | `arena: broke 5 of 51 (...)`, the same 5 attacks as before |
| 11 | `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json` | 0 | 311 s | `arena: held 53/53 (...)` |
| 12 | `git status --porcelain` after all of the above | | | empty: no committed file changed |

## What this does not cover

- One machine, not Linux. The full `./verify.sh`, `proofs/run.sh`, `tla/run.sh` and the mutation
  table were not re-run.
- The reviewers' other points that need a product or wording decision (on-chain mode, results that
  never expire, the anonymous guards being hard to re-run) are not addressed here.
