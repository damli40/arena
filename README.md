<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/arena-mark-on-dark.svg">
    <img src="docs/img/arena-mark-on-light.svg" alt="Arena logo" width="80" height="80">
  </picture>
</p>


# Arena

**Can your guard survive the arena?**

Your AI agent pays your bills, and a payment guard (a NEAR contract that limits what the agent may pay) stops it spending too much. Arena attacks such guards on a throwaway local NEAR sandbox and scores each attack held or broke from the final token balances, never from what the guard or the agent reports. It finds two ways you still lose money: NEAR runs one call across several blocks, so a guard that records a payment after the transfer comes back can pay one bill twice; and an agent fooled by an email can pay bills you never meant to pay, inside the guard's rules. A hunter adds attacks from new papers and hack news as data, never code, and an admission gate checks that each attack catches the flaw it names.

**Headline result:** on NEAR testnet, a guard with a flaw planted on purpose paid 200 tokens on one 100-token invoice in 5 of 5 trials, and the fixed guard paid 100 in 5 of 5 (`evidence/testnet-2026-11-11.md`).

**Track:** AI Security & Defense (`security`). **Status:** working prototype on a local NEAR sandbox, with the double-pay result confirmed on NEAR testnet. **Website:** https://arena-guard-bench.netlify.app. **AI reviewers:** start with `ARENA.md`, section "For AI reviewers".

## Try it in 2 minutes (no login, no install)

1. **See the double pay on the public explorer.** Open [call A](https://testnet.nearblocks.io/txns/G66wuWfTVB9ryzgPYmBk4ksYap4SUhhF8Hes2hAGN5CQ) and [call B](https://testnet.nearblocks.io/txns/AFGE2DVFpcBLzF6nQ8pzWKCxVVkUqWejeoqrXYG94KuJ). Both call `pay` for the invoice `inv-vulnerable_fixture-3` in block 277089399, and each moves 100 test tokens to the receiver: 200 paid on one 100-token invoice (NEAR testnet, 2026-11-10 UTC; trial 5 of 5 in `evidence/testnet-2026-11-11.md`).
2. **Look up a guard live.** Open [the lookup with the planted-flaw guard filled in](https://arena-guard-bench.netlify.app/lookup.html?account=r11bvf3-guard.arena-race-funder-1111.testnet). It reads NEAR testnet and answers `broke`. The "fixed guard" button answers `held`.
3. **See the board.** [The results board](https://arena-guard-bench.netlify.app/board.html) shows every attack a hunt ran against each guard, on a local NEAR sandbox, 2026-11-10 to 2026-11-11. It is a recording, not live.

## Check it in 5 minutes (Python 3 and Node 18+, no build, no key)

Run from the repo root. Each command finishes in seconds; the two lookups read NEAR testnet, so they need the internet.

```
python3 -I tools/admission/manifest.py --check
#   manifest: up to date                        (every library count matches the repo; exit 0)
python3 -I -m unittest discover -s tools/admission/tests
#   OK                                          (README and EVALUATE quote the manifest's numbers)
python3 -I tools/hunter/validate.py --self-test
#   self-test: ok (validator vs schema/attack.schema.json)
python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-13-papers-abc826.json
#   recheck: all checks pass (Intel and NVIDIA signatures are not checked offline)
python3 -I tools/injection/rescore.py
#   ... Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).
node tools/lookup/cli.mjs r11bvf3-guard.arena-race-funder-1111.testnet
#   status:    broke                            (planted-flaw guard, read live from testnet; exit 1)
node tools/lookup/cli.mjs r11cfx4-guard.arena-race-funder-1111.testnet
#   status:    held                             (fixed guard; exit 0)
```

With Rust installed, `./verify.sh fast` (about 8 minutes cold) ends `verify: 5 passed, 0 failed (mode=fast)`: the planted-flaw guard pays 200 on a 100 invoice, and the bench catches a leaky-on-purpose guard. `./run.sh t2_` shows the fixed guard paying 100 (`RESULT fixed race payouts per trial: [100, 100, 100, 100, 100]`). To run Arena on your own guard: `./arena check your_guard.wasm` (see "Check it yourself" below and the [how-to page](https://arena-guard-bench.netlify.app/docs.html)).

## Every result: claim, evidence, command

Commands marked *key* need a model API key; *private* means the inputs stay outside this repo (see "What this does not show"). `EVALUATE.md` gives each command's expected line and our time.

| Claim | Evidence | Re-check |
|---|---|---|
| Planted-flaw guard: two `pay` calls at once for one 100-token invoice pay 200, in 5 of 5 trials, on the local sandbox and on NEAR testnet | `evidence/testnet-2026-11-11.md` (first run: `evidence/testnet-2026-11-09.md`) | `./verify.sh fast`; the lookup above |
| The fixed guard pays 100 in 5 of 5, on both, with the current build (`0382023b…`); the other call is refused with `payment already in flight` | `evidence/testnet-2026-11-11.md`, `evidence/verify-2026-11-11.md` | `./run.sh t2_` |
| Worst case under the broad rules: z3 searched every sequence of up to 10 pay requests; its answer, replayed twice on a local chain, paid 500 tokens against the owner's intent in one run and 0 beyond policy | `evidence/proofs-2026-11-10.md` | `proofs/run.sh proof2`, then `proofs/crosscheck.sh` |
| 10 mistakes planted in our own guard (vault-a), one at a time: our attacks caught 7. The other 3 sit on paths no attack walks down | `evidence/mutation-table-2026-11-11.md` | `tools/mutation/run.sh` (about 40 min) |
| A review of our proofs found a bug in our own fix (`reconcile` reopened a paid bill after an outside top-up, so the guard paid 200 on a 100 bill). We fixed it and re-ran: `proofs/run.sh` 30 of 30 then, 33 of 33 after three later checks were added; near-tla 25 of 25 as planned | `evidence/proofs-adversarial-review-2026-11-11.md`, `evidence/proofs-inductive-2026-11-11.md`, `evidence/proofs-all-2026-11-11.md` row 5 | `proofs/run.sh`, `tla/run.sh` |
| 33 of 54 library attacks validated by the admission gate | `evidence/MANIFEST.md` | `python3 -I tools/admission/manifest.py --check` |
| Fully fooled agent (a script that obeys every injection), 5 scenario runs: 0 tokens paid beyond policy; 450 against the owner's intent summed, at most 200 in one run | `evidence/injection-intent-by-recipient.md` | `ARENA_AGENT=compromised python3 -I tools/injection/run.py`, then `python3 -I tools/injection/rescore.py` |
| Real model (Muse Spark 1.3): 25 trials, then 30 against an attacker model that rewrote its email after each failure: 0 fooled in the 52 trials where it read the email; 0 tokens against the owner's intent | `evidence/injection-2026-11-09-model.md`, `evidence/injection-2026-11-09-adaptive.md` | *key*: `ARENA_MODEL_PROVIDER=muse python3 -I tools/injection/run.py` (the 25 trials) |
| Real model on NEAR AI Cloud (glm-5.3-flash), the same 5 scenarios, 2 trials each: 0 fooled in 10; 0 tokens against the owner's intent | `evidence/injection-2026-11-11-nearai-model.md` | *key*: `python3 -I tools/injection/run.py` |
| The learning attacker also shown the guard's rules and source (`--know-guard`, NEAR AI model, 3 rounds of 3 tries per guard, 2026-11-13): vault-a fooled 0 of 9; direct-pay test guard fooled 1 of 9 (kai paid 40, inside the guard's rules, never asked for by the owner); paid beyond its rules: 0 in both | `evidence/injection-2026-11-13-adaptive-guard-aware-vault-a.md`, `evidence/injection-2026-11-13-adaptive-guard-aware-direct-fixture.md` | *key*: `python3 -I tools/injection/adaptive.py 3 3 --know-guard` |
| Three other teams' guards (A, B, C), tests written from each guard's own claims: 29 of 29 held, 0 tokens paid beyond policy | `evidence/coverage-table.md` | *private* |
| A fourth team's guard (Guard G), which pays directly with no invoices: 12 attacks, 11 held, 1 stopped by NEAR's access key, 0 broke. 25 of 25 self-tests on a broken fixture gave the result each defect demands. Two AI-proposed configs each had one wrong field, and the gate caught both: neither came out held | `evidence/direct-2026-11-11.md` | self-tests: `EVALUATE.md` rows 14 to 17; the guard itself: *private* (account withheld) |
| Four other teams' guards: 34 of 38 money claims hold up to small bounds, 3 for the contract's part, 1 fails | `evidence/proofs-all-2026-11-11.md` row 4 | *private* |
| `./arena check` on GitHub's Linux runner: held 49/49 on vault-a, the same as on macOS | `evidence/github-action-2026-11-13.md` | `./arena check targets/vault-a/vault_a.wasm` |

![How Arena works: the hunter and the admission gate grow the attack library; ./arena check runs the library against your guard on a throwaway local NEAR sandbox; the scorer reads final balances and writes a report card; results are published to a contract on NEAR testnet that a lookup or another contract can read before paying](docs/architecture/arena.png)

*The attack library grows on its own track (hunter proposals and hand-written attacks, all through the admission gate); `./arena check` runs it against your guard and scores it from the final balances. Source: `docs/architecture/arena.excalidraw`.*

## What this does not show

- **NEAR Intents and Chain Signatures ran against local stand-ins only:** the real Intents contract on a local sandbox with Arena's own bridge stand-in for withdrawals, and a stand-in signer that signs nothing. No real bridge, no real MPC signing, no mainnet.
- **Other teams' guards are published as counts only.** Their code and harnesses stay private, so you cannot re-run those results from this repo.
- **Arena reads each payment as one whole invoice amount.** A guard that pays part of an invoice could score held where a part-payment reading would be broke (see "Limits").
- **Held means the attacks Arena ran found nothing.** It is not a promise about attacks Arena did not run.

NEAR function-call access keys are reported separately: the agent signs with a key that may call `pay` on the guard and nothing else, and attacks NEAR refuses at that key count as "stopped by the agent's access key", never as held.

## What we proved, and the limits of each proof

A proof checks every way the calls can line up, up to a stated bound, not just the runs we tried. We needed proofs because testing missed things: our attacks caught 7 of 10 planted mistakes.

| What we proved | Result | Tool |
|---|---|---|
| The fixed guard never pays a bill twice when pay messages race | on the real code, holds for every order of up to 4 pay calls; on the model, for any number of calls. The broken guard fails, as it should | Kani, plus NEAR's own near-tla (up to 3 pay calls) |
| Tight rules never pay more than the owner meant | holds for up to 10 payment requests, in our test setup | z3 |
| The code we proved is the code that ran on testnet | our guard's source, rebuilt from a clean copy with the pinned Rust, gives exactly the testnet wasm (`0382023b…`); a one-line change gives a different hash | a reproducible build |
| Direct-pay rules (per-payment cap, daily cap, payee list, approval threshold) never pay beyond their own policy | holds for every policy, every amount and every order of up to 8 steps, for the design where a refund counts on its own day. The design where a refund comes off today's total pays above the daily cap across a midnight | z3 |
| Five reusable money rules: no double pay, payee list, per-payment cap, approval threshold, daily budget | 116 lines of spec in `proofs/properties/`, with a harness template you copy for your own guard. Each rule catches its own planted flaw. On our guard (real code, every order of 3 pay calls) no-double-pay holds | Rust, every case up to the bound |
| Four other teams' guards: 34 of 38 money claims hold, 3 for the contract's part, 1 fails | each claim checked on each team's real code, every case up to a small bound (bounds in "Limits"). The 3 partial claims rest on a NEAR key rule our model does not include. The counterexample: one of the four guards can pay above its daily cap when a refund lands after midnight (we do not say which). 64 of 64 planted flaws caught | Rust, every case up to the bound |
| The result is public | saved on NEAR testnet, so anyone can look a guard's results up (a lookup must also read the guard's mode; see "Limits"). Receipts for the current build were published Nov 10; results another contract can read before paying, Nov 11 (`evidence/results-testnet-2026-11-11.md`) | arena-receipts |

**What "proved" means here:** the "any number of calls" proof covers a careful copy of the guard's logic (the model), not the contract itself. We ran the real code beside the model and they matched in every case we checked: every order of up to 4 pay calls (4,555 states), and every order of 2 pay calls in a fuller world where callbacks die, `reconcile` runs and outside tokens arrive (21,345 states). It is a proof up to these limits.

## Check it yourself

You need:

- **Rust**, through rustup: `curl https://sh.rustup.rs -sSf | sh`. The repo pins the toolchain (`rust-toolchain.toml`), so rustup fetches the right version on first build.
- **The NEAR sandbox**: nothing to install. The scripts download it on the first run (needs the internet).
- **Python 3**, for `arena check`, the prompt-injection scripts and the tool tests.
- **Node 18 or newer**, for the lookup and its tests (`tools/lookup/`).
- For the proofs only: **Kani** (`cargo install --locked kani-verifier && cargo kani setup`), **z3** (`python3 -m venv proofs/.venv && proofs/.venv/bin/pip install z3-solver`), and **Java 17 or newer** for `tla/run.sh` (`brew install openjdk@21`; the other near-tla setup steps are in `tla/README.md`).

Tested on macOS (Apple silicon). `./arena check` has also run once on GitHub's Linux runner, through the pull-request check (`evidence/github-action-2026-11-13.md`).

```
./verify.sh fast     # the headline: the double pay, and the bench catching it. 5 checks
./verify.sh          # every local sandbox result in this README. 43 checks
proofs/run.sh        # Kani on the model, the real code beside it, and z3. 33 checks
tla/run.sh           # near-tla, NEAR's own model of how calls run. 25 checks
```

Each check prints PASS or FAIL. The last line of `verify.sh` is `verify: 5 passed, 0 failed (mode=fast)` or `verify: 43 passed, 0 failed (mode=full)`, and each script exits 0 only if every check passes. Measured times: `fast` 481 s on a fresh copy with no build folders (Nov 9), 196 s with the builds there; the full `verify.sh` 943 to 965 s (four runs); `proofs/run.sh` 1,504 s; `tla/run.sh` about 46 min, most of it in `fixed_2inv` and `h1_open_world_2faults`. `tla/run.sh <name>` runs the named checks alone (the quick trio `vuln_race fixed_1inv h1_outside_transfer_reconcile` takes about 15 s), and `proofs/run.sh proof2` runs z3 alone. Each run writes its logs to a new folder `runs/<UTC time>/` (not tracked by git), so running the checks never changes a committed file; set `ARENA_RECORD=1` to write into `evidence/` instead. Every `verify.sh` run appends one line to `verify-summary.log` in its run folder.

The prompt-injection results, after `./verify.sh` has built the harness:

```
ARENA_AGENT=compromised python3 -I tools/injection/run.py    # fully fooled agent, no API key needed
python3 -I tools/injection/rescore.py                        # tokens by recipient vs the owner's intent
```

`run.py` writes its trials to `runs/<UTC time>/`. `rescore.py` reads the saved trials in `evidence/`, makes no model or chain calls, writes its table to `runs/<UTC time>/` (the same bytes as `evidence/injection-intent-by-recipient.md`), and ends with `Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).` The real-model run uses glm-5.3-flash on NEAR AI Cloud by default and needs `NEARAI_API_KEY` in `~/.config/arena/nearai.env` (or set `ARENA_MODEL_PROVIDER=muse` and put `MUSE_API_KEY` in `~/.config/arena/model.env`); without a key, read the saved runs in `evidence/`.

## Test your own guard

These tools are for guard builders. Each one runs on the local sandbox unless it says testnet.

| Do this | You see | Read |
|---|---|---|
| `./arena check your_guard.wasm` (add `--config your.json` if your guard pays in plain NEAR or starts differently) | `arena: held N/N` or `arena: broke K of N`, a one-page report in `arena-report/report.html`, exit code 0 held, 1 broke, 2 could not finish or a wrong command (`--fail-on` sets what counts as broke) | `docs/CHECK-YOUR-GUARD.md` |
| The same check on our planted-flaw guard that pays the agent: `./arena check targets/planted-outflow/planted_outflow.wasm` | `broke 11 of 49 (...; 3 stopped by the agent's access key ...; 1800 tokens paid outside the five receivers ...)`. Money that goes to any account the attack was not meant to reach counts as broke; money the check cannot find ends it incomplete, never held | `evidence/check-outflow-2026-11-11.md`, `evidence/invoice-fixes-2026-11-12.md` |
| A guard that asks NEAR Chain Signatures to sign a transaction for another chain: add `"signs_via": "chain-signatures"` to its config (`examples/configs/chainsig-guard.json`) | `held 55/55` for our honest test guard; `broke 3 of 55 (... 3 unauthorised signing requests (a count, not an amount) ...)` for our planted one. The signer is Arena's stand-in: it records each request and signs nothing, so no real MPC signing and nothing sent to another chain | `evidence/check-chainsig-2026-11-11.md` |
| The same check on a guard that withdraws from NEAR Intents toward another chain: `./arena check targets/withdraw-planted/withdraw_planted.wasm --config examples/configs/intents-withdraw-guard.json --no-muse` | `broke 3 of 57 (...; 3 stopped by the agent's access key ...; 500 tokens paid outside the five receivers ...)`, each BROKE line naming the foreign address, for example `200 tokens toward eth:0xbad..., not on the owner's list`. Our honest copy, `targets/withdraw-honest`, holds 57/57. Arena checks where a withdrawal is sent and what destination it names, read from its own bridge stand-in; nothing reaches another chain | `evidence/check-withdraw-2026-11-12.md` |
| Copy `examples/workflows/arena-check.yml` into your repo's `.github/workflows/` | the check on every pull request, with read-only access. Ran on GitHub's Linux runner on 2026-11-13: held 49/49 on vault-a, the same as on macOS (`evidence/github-action-2026-11-13.md`) | `docs/CHECK-YOUR-GUARD.md` |
| Replay a saved attack: `./run-arena.sh replay sequences-paper/<file>.json --wasm your_guard.wasm` | the attack's result against your guard, with no model call | `docs/ADD-AN-ATTACK.md` |
| Look up a guard on NEAR testnet before paying it: `node tools/lookup/cli.mjs <account>` | `status: held`, `broke`, `not_tested` or another answer; only `held` is a pass | `docs/CHECK-BEFORE-YOU-PAY.md` |
| Opt your guard in on NEAR testnet, or ask for a result from another contract before paying | the contract stores who signed and which code; it never says "safe" | `docs/ON-CHAIN.md`, `docs/REGISTER-A-GUARD.md` |

## The hunter

A language model reads new security papers and hack news and proposes attacks as data: a list of steps from a small fixed vocabulary, never code. A validator rejects anything else, and the bench runs the rest against Arena's own guards and guards whose owners opted in.

- **What it found so far.** The repo holds 9 hunt records. They proposed 46 attacks from 10 papers (11 reads: 2104.08638 was read in two hunts) and news items; 26 were saved and 2 broke a guard, both guards built to be broken (`evidence/MANIFEST.md`, "Hunts").
- **Where it runs.** A GitHub Actions workflow (`.github/workflows/hunt.yml`), switched on since 2026-11-13, with four hunts a day on its schedule (papers and news at 01:17 UTC, news only three more times). Results leave as a downloadable file; the workflow never commits. Its paper run on 2026-11-13 (https://github.com/damli40/arena/actions/runs/43466826430) checked NEAR's attestation on GitHub's runner, considered 5 new papers and proposed no attack, and its canary broke all three planted-flaw guards and held on the fixed ones (`evidence/hunts/2026-11-13-papers-abc826.md`). Its news run the same day (https://github.com/damli40/arena/actions/runs/43522805712) read Elfa news summaries; its record is in the repo as a redacted copy (`evidence/hunts/2026-11-13-news-c87c9e.md`), counted above. The first scheduled run (2026-11-14, 01:17 UTC) failed a self-check before hunting; the cause and the workflow fix are in ARENA.md.
- **Which model.** Papers go to glm-5.3-flash on NEAR AI Cloud, and each such run saves NEAR's attestation report (2 records so far: `2026-11-11-papers-e3db55` and `2026-11-13-papers-abc826`; re-check offline with `python3 -I tools/hunter/recheck_attestation.py <record>.json`). The report shows which model answered, not that an attack is good. News stays on Muse Spark, which has no attestation, because the attested model's news attacks failed the validator more often (`evidence/news-model-2026-11-14.md`).

Details, keys and threat model: `ARENA.md` and `EVALUATE.md` section 4.

## Attack admission: which attacks catch something

Running cleanly on every guard does not show an attack can catch anything. An attack counts as validated when `tools/admission/admit.py` has run it on a guard known to be good (it must hold) and on a copy with exactly the one flaw the attack names (it must break, by the exact amount, the way the attack says), three times each, and kept the raw runs. Attack admission: **33 of 54** attacks validated, 0 partially validated, 21 unvalidated. Every count is in `evidence/MANIFEST.md`, generated by `tools/admission/manifest.py`.

- **What the 54 are.** 48 attack files plus 4 prompt-injection scenarios from `tools/injection/scenarios.json` (52 for a guard paying in tokens or NEAR), plus 2 NEAR Intents files.
- **Races.** 11 of the validated are races. A race counts when the harness's per-receipt block numbers show every later pay was checked in a block strictly before the first pay's transfer result came back, and two separate judges of that ordering (`tools/admission/admit.py` and `tools/race/ordering.py`) agree on every stored run (96 of 96: `evidence/admit-all-2026-11-13/two-judges/` for 8 races, and `evidence/integrate-2026-11-13/two-judges/` for ai-01, c261110-1 and p210408638-1, re-run on a clean tree). Six of the 11 are double pays, caught by M5 (vault-a without its in-flight mark before the transfer) or by the guard fixture that records a payment in its callback (one, `ai-03`, by the fixture alone). Five are cap races, caught by `race-m3`, a copy of vault-a that counts the day's spend when a transfer's result comes back: sent together, the pays all fit under the cap; sent one after the other, `race-m3` holds, so the flaw is a race flaw (`evidence/admit-all-2026-11-13/survey/`).
- **Owner methods.** `bypass-04`, an outsider sending owner methods from its own key, is validated against M12 (the owner check removed), a planted copy added on 2026-11-13 with its plan written before the build (`evidence/mutation-plan-2026-11-13.md`).
- **Narrower than the title.** Some attacks validate one check (for example the already-paid check), the prompt-injection attacks run scripted steps with no agent reading the email, two races titled as cap breaches validate the double pay alone, and one attack depends on 20 s expiry timing. Each limit is printed after "LIMIT:" in `evidence/MANIFEST.md`.
- **The 21 unvalidated** still run on every guard, and each row of `evidence/MANIFEST.md` says why, measured on the planted copies: 7 break nothing a single planted flaw can show, 3 are races that the matching flaw breaks just as well with the calls one after the other, 3 are stopped by NEAR's access key before any guard code runs, 3 are judged by the owner's intent alone, which the gate does not decide, 1 tests NEAR Intents' own rules, and the 4 scenarios are not step files.
- **Saved is not admitted.** Of the 25 hunter attacks in `sequences-paper/`, the ones the gate admitted count; the rest are unvalidated.
- **Hidden set.** 14 more admitted attacks (set 4, 2026-11-12) are kept out of the repo and committed by hash (`hidden-set/COMMITMENT.json`). Before the commit, a check refuses any hidden attack with the same steps as an attack file tracked on any branch, or the same steps apart from gas and wait values. Other variants of public attacks (different invoices, order or actors) can still be in the set, so a guard tuned to the public library may still pass some hidden attacks. Its runs on our own guards are in `evidence/hidden-set/`; the set has no race variant yet. How to check both without seeing the set: `EVALUATE.md` section 4b.

## The two numbers Arena reports, never combined

| Number | What it counts | Where the rule comes from |
|---|---|---|
| **Tokens paid beyond policy** | tokens that left the guard in breach of the guard's own written rules. A non-zero value is a guard failure | the policy file, fixed before any test (`policy/`, or the guard's `CLAIMS.md`) |
| **Tokens paid against the owner's intent** | tokens a recipient got beyond what the owner intended for them, even when the guard's rules allowed it | the owner's intended allocation, written before any run (`tools/injection/scenarios.json`, field `intended`) |

Both come only from final balances on the chain, never from what the guard or the agent reports. The agent never sees `intended`; only the scorer reads it. Arena also prints the honest payments that settled, so a guard that refuses everything cannot look perfect.

## Why this is a NEAR problem

NEAR runs one contract call across several blocks. A payment guard checks "is this invoice paid?" in block N, the tokens move in block N+1, and the guard records the result in block N+2. A second `pay` for the same invoice that arrives before N+2 still sees "not paid", and pays again. The fix is to record the payment before starting the transfer, and to undo it only if the transfer fails. On testnet, the two `pay` checks ran in the same block in every trial on Nov 9, and in 7 of 10 on Nov 10. In the other 3 they ran one block apart twice and two blocks apart once. In 9 of those 10 trials the block numbers show both checks ran before the first result was recorded. In the tenth, the later check ran in the same block as that result, so block numbers alone cannot show which came first; the broken guard paying twice shows the check did (`evidence/testnet-2026-11-09.md`, `evidence/testnet-2026-11-11.md`; that file is named for the Nov 11 guard build it tested, and its runs started Nov 10, 15:58 UTC; its "one block apart" paragraph is wrong for row 3, corrected in `evidence/race-ordering-2026-11-11.md` section 2).

## Other teams' guards

We name them only by letter. Before any run, for each guard, we wrote down what it claims (`targets/entrant-X/CLAIMS.md`) and its build fingerprint (`targets/entrant-X/FROZEN.txt`), then scored only those claims. Anything beyond its claims is marked "not claimed" and never counted as a failure.

| Guard | What it is | Tests of its own rules | Held | Tokens paid beyond policy | Not evaluated |
|---|---|---|---|---|---|
| A | invoice payer with payee list and daily cap, token | 7 | 7 | 0 | cross-chain payments, escrow |
| B | vault in native NEAR with caps, approvals, pause | 10 | 10 | 0 | a refund callback that lands after UTC midnight |
| C | company treasury with a server-bill pot and a profit pot | 12 | 12 | 0 | swaps and withdrawals that need sealed hardware (a TEE) and NEAR's shared signing network |

That is 29 tests, and 29 held. Each guard also made one normal payment to show it works, and all 3 went through. Guard A faced one more test, on a rule it never promised, and it held. So the coverage table has 33 rows: 29, plus 3, plus 1.

Guard G has no invoices, so it runs on the direct-pay path (results in the claim table above, `evidence/direct-2026-11-11.md`). Its code is not in this repo; `targets/entrant-G/fetch.py` reads it from testnet and refuses any build but the frozen one.

Guards A to C all held for the same reason: each records the payment before it moves the money. Their source code, built files and test runners are not in this repo, to keep them anonymous. Per-test detail, including the two corrections we made during the runs: `evidence/coverage-table.md`.

**10 more teams' guards, where the agent names who gets paid:** 10 checked, 0 broke, 10 held on
every rule they claim. In one of them, one owner-change attack could not count, because that guard
has no way to remove a payee. In all 10 the forged-callback attack was not run, because no config
maps a callback, so a re-run today ends `could not finish 1` (exit 2), not `held`. One more team's guard moves no money, so Arena cannot test it. We publish counts
only: no letters, names or code. How to read these and what you can re-run: `EVALUATE.md` section 6.

## Limits

- **Local sandbox, except one result.** We ran only the planted-flaw guard and its fix on testnet, on the current build (`0382023b…`). The race never reaches the `reconcile` fix, so testnet did not test that fix. We tested the three other teams' guards on the local sandbox.
- **The proofs have limits.** The "any number of calls" proof covers the model only. The model matches the real code in every case we checked: up to 4 pay calls (4,555 states), and 2 pay calls in the full world with faults (21,345 states). near-tla checks up to 3 pay calls. The z3 results cover our 7-invoice test setup and up to 10 payment requests, and, for the direct-pay rules, up to 8 steps. The checks of real code run the Rust source on near-sdk's simulated chain, not the wasm inside NEAR's VM. For our guard the source is tied to the deployed wasm by a byte-for-byte rebuild; a bug in the Rust-to-wasm compiler or in NEAR's VM would still not show up.
- **The other teams' guards were checked only up to small bounds, and privately.** 2 to 5 payment requests, a few owner actions, one midnight; more did not finish in our time on a shared machine. The source and harnesses stay outside this repo, so you cannot re-run them from here (`EVALUATE.md`, entry 26). Guard G's source was not rebuilt byte for byte (its pinned SDK was not in our local cache and we did not fetch it): the check ran the team's logic on a newer SDK with one call-site edit, and the build has the same functions and error codes as the deployed one. The wasm wrappers' own checks (`#[private]`, `#[payable]`) are not exercised.
- **What is measured, not proved.** How an AI model behaves when an email tries to fool it is measured in trials: a model is not code we can enumerate, so no bound covers it. What happened on testnet is an observation of one chain on one day. Both are labelled as measurements.
- **A receipt lookup needs the mode.** The broken and fixed guards share one code fingerprint, so a lookup must also read the guard's mode.
- **29 of 29 held means each guard kept the rules it wrote down, in these tests.** We built each guard's tests from its claims, so the three guards faced different tests, and we could not test some paths locally (table above). It does not prove a guard free of flaws.
- **The 450 tokens are five separate runs added up, from a scripted agent that obeys every injection.** No single run paid more than 200. The 500 is a different number: the worst single run z3 found under the same rules, which we replayed on a local test chain. The real model resisted in every run we made; that does not show it always will. All 450 tokens went to creditors the owner had approved. None reached an attacker's account. In one scenario the intended recipient got nothing.
- **One model played both attacker and victim** in the adaptive test, with one goal and one guard.
- **The agent never sees a refusal.** In the injection test, `pay` returns "submitted" and the chain runs after the conversation.
- **Races are tested on the local sandbox only, at a few chosen spacings.** In Arena's own race tests (`tools/race/run.py`, on Arena's reference guards), Arena times the second payment so its check runs in the same block as the first or one block later, and reads back from the chain which block each check and result ran in; a try that misses the asked-for block is thrown away, never scored. In a 40-try timing test it landed where asked 40 of 40 times. For later payments a slow test token holds the first payment's answer back (NEAR's pause-and-resume for calls), so checks 4 and 8 blocks later still run before any answer; spacings of 2 and 3 blocks are not tested (`evidence/race-ordering-2026-11-11.md`, `EVALUATE.md` rows 29 to 32). `./arena check`, the hunter and admission still send a race's calls together, with no block check. On testnet, 3 of 10 trials on Nov 10 had the two checks in different blocks (one block apart twice, two blocks apart once).
- **Corrections, all kept in the evidence files:** Guard B's reserve test was invalid on its first run; we fixed it and re-ran all 11 tests. We added Guard C's two deposit tests after its first run. The adaptive test crashed once on an API timeout, and we resumed it from its saved rounds.
- **NEAR Intents is tested on the local sandbox only.** For a guard that pays into NEAR Intents (`"pays_in": "intents"`), Arena runs the pinned release build of the Intents contract (defuse v0.4.2) on the local sandbox and reads who it credited (`evidence/check-intents-2026-11-11.md`). For a guard that withdraws from Intents toward another chain (`"pays_by": "ft_withdraw"`), Arena checks where a withdrawal is sent and what destination it names; it does not test delivery on the other chain, real bridges, or the MPC network. The destination is read by Arena's own bridge stand-in, which records it and sends nothing anywhere (`evidence/check-withdraw-2026-11-12.md`). Destination addresses are compared as exact text, so an EVM address (an Ethereum-style 0x address) that differs from the owner's list only in letter case counts as off the list, and an honest guard that sent it would be scored broke. This can give a false broke, never a false held. Tokens Arena cannot place end the check incomplete, never held. Not tested: solvers or swaps, or the real Intents contract on mainnet (NEAR Intents has no testnet).
- **"Beyond policy" is read from the chain only, step by step, and that has two costs.** Arena reads every receiver's balance before and after each step of an attack. Tokens count toward an invoice only if they reached its receiver while the agent's `pay` for that invoice was running. The guard's own `get_invoice` answer is shown in the log but never scored (`evidence/invoice-fixes-2026-11-12.md`). One cost: a guard that holds a payment and sends it during a later `pay` for a different invoice of the same receiver cannot be told apart from one that paid the later invoice. Arena tries both readings. A held payment counts toward nothing, because it arrived outside its own `pay`. So if the later invoice should not be paid, the attempt is broke under both readings, although the guard's money may be right (a false failure). If the later invoice should be paid, one reading is held and one is broke, and the check ends incomplete. The other cost: money that arrives while no `pay` to that receiver is running, while an earlier `pay` to it is still unpaid, is first credited to that unpaid bill; anything above it counts as broke ("at least N"), and if all of it could be that bill the check ends incomplete, never held: the chain does not say which bill it was. None of our guards does either.
- **Arena reads each payment as one whole invoice amount.** When several `pay` calls to one receiver could explain the money it gained in a step, Arena tries every set of whole invoice amounts that adds up to the gain, and splits the gain only if no set fits. A guard that sends part of an invoice, while a whole-amount reading also fits, could be scored held where a part-payment reading would be broke. None of our guards sends part of an invoice.
- **With more than 5 invoices of one receiver in one step, and no whole-amount reading, Arena tries only the kindest order.** No setup Arena ships has that: ada, the receiver with the most invoices, has 3.
- **An expiring invoice needs a readable pay time, or the check cannot finish.** Arena reads the time of the block where the guard's `pay` ran. If it cannot read it and tokens would count toward an expiring invoice, the attack is "cannot observe" and the check ends incomplete. It is never counted as allowed.
- **An attack that NEAR refuses in full tested the agent's key, not the guard.** The agent's key may call only `pay` on the guard, so NEAR refuses some attacks before any guard code runs (three on a token guard: `bypass-01`, `bypass-02`, `bypass-03`). The check reports them as "stopped by the agent's access key", outside the held count. `bypass-04` sends bypass-02's owner calls from the outsider, whose key reaches the guard, so the guard's owner check is tested.
- **Chain Signatures requests are scored against a stand-in signer, as a count.** For a guard with `"signs_via": "chain-signatures"`, Arena puts its own stand-in in place of `v1.signer` (`contracts/signer-standin`). It records which hashes the guard asked to have signed and returns a fake signature. Arena counts unauthorised requests: hashes off the owner's list (`policy/chain-signatures-allowed.json`), repeats, a different path or key, and requests the guard made because the outsider asked; it never turns that count into tokens, because it cannot know what an unknown hash was worth. It does not test real MPC signing, delivery on another chain, or real transaction encodings: the hashes use Arena's own format, not an Ethereum transaction. The stand-in follows our reading of `v1.signer`'s request rules, not a copy of them, so it may accept or refuse a request the real one would not; a refused request inside the guard's transaction makes the check "could not finish". Only our two test guards have run (`evidence/check-chainsig-2026-11-11.md`).
- **An attacker can force "could not finish" on an honest Chain Signatures guard.** For example, it can leave too little gas for the guard's call to the signer, or fill the stand-in's storage with a huge `path`. Both block a verdict; neither can make a guard read as held.
- **Arena credits a signing request to the step whose transaction made it.** If the outsider queues a request in one step and the agent's next step makes the guard sign it, the request is credited to the agent, so a hash on the list passes.
- **On chain, a result is not tied to the guard's mode or to an opt-in.** The contract's answer does not read the guard's mode, so a contract asking about a wasm that has results under more than one mode must name the suite (`docs/ON-CHAIN.md`). `publish_result` does not check the opt-in table, so a result on chain does not show that the guard's owner agreed to be tested. In practice, Arena's publishing script (`tools/receipts/publish.py`) sends results only for Arena's own guards, plus one record of the attack library's counts; Guards A, B and C have an older receipt on chain, by letter and code fingerprint, but no result a contract can query (`evidence/results-testnet-2026-11-11.md`).
- **"Validated" is only as strong as the attack's written checks.** "Broke through the named mechanism" means the checks the attack's spec lists passed on every counted run (one check is the minimum), and the flaw counts as matched because the broken copy's flaw label equals the one the spec names; nobody checked which line of code fired.
- **In direct-pay mode, an AI-proposed config also picks which rules the guard claims.** A rule it leaves out is marked not applicable and is never tested, so a proposal that claims fewer rules than the guard enforces tests fewer rules. If every attack is not applicable, the check says could not finish (exit 2), never held. Check the `claims` list in the report before you rely on a result.
- **The direct-pay callback check has limits.** The gate confirms the callback only by seeing the guard call that method on itself after a payment, with the id the payment returned, of the same JSON type. Each forged call (attack i03) sends exactly what the guard sent itself for the payment it forges against, so per-payment values (amount, nonce, receiver) match; only the caller differs. Held on i03 now means one thing: every forged call was refused by a caller check, either near-sdk's `Method <name> is private` or the refusal text the config names (`direct.callback.refusal_text`). Any other failure, such as a bare wasm trap, a promise-result error or out of gas, ends could not finish (exit 2), because Arena cannot tell it from a forge that never reached the guard's logic. So an honest guard can come out could not finish: one whose own refusal is a bare trap, one whose callback quietly does nothing, or one whose payment returns the id with a different JSON type than its callback takes (self-test S26). If the config names a different method that the guard also calls on itself and that does nothing with the payment, i03 can still come out held. A guard with no callback at all always ends could not finish, because i03 cannot run. Pressing Ctrl-C stops the check with Python's interrupt exit (130 in a shell), which is not a result.
- **The config author is trusted to name a real caller check.** `direct.callback.refusal_text` is matched as a substring of the error, and the `Method ... is private` pattern can match text a guard writes itself. Only hand-written configs set `refusal_text`.
- **i03 forges a callback only after a payment settled, never while one is in flight.**
- **A correct guard whose "already settled" check runs before its caller check gets could not finish on i03.** The forged call is refused, but not by the caller check.
- **A `refusal_text` that is not a string gives could not finish.**
- **The double-pay guard (`contracts/guard`, mode `vulnerable_fixture`) is a labelled test case.** Never deploy it.
- **Direct-pay guards: one tested so far, fixed amounts.** Guard G is the only external guard on the direct-pay path. Arena's amounts and receivers are fixed, so a guard that special-cases them could pass the gate. Re-running Guard G needs network access to fetch its code.

## Screens

![Arena home page: the headline and "The arena today" panel](docs/img/home-hero.png)

*The home page: 54 attacks in the library, 33 of them validated.*

![Two real ./arena check results in a terminal](docs/img/arena-check-terminal.png)

*Two real runs: Arena's reference guard held 49 of 49 attacks; the leaky-on-purpose guard broke on 5.*

![The results board](docs/img/board.png)

*The board: every attack a hunt has run, against every guard in the table.*

## Where to look next

| For | Read |
|---|---|
| Every claim, with the command that checks it | `EVALUATE.md` |
| Checking your own guard, and the config file | `docs/CHECK-YOUR-GUARD.md` |
| Looking a guard up before you pay it | `docs/CHECK-BEFORE-YOU-PAY.md` |
| Opting in on chain, and asking for a result from a contract | `docs/ON-CHAIN.md`, `docs/REGISTER-A-GUARD.md` |
| Writing an attack by hand | `docs/ADD-AN-ATTACK.md` |
| The hunter's runs, and its model on NEAR AI Cloud | `evidence/hunts/`, `evidence/nearai-2026-11-11.md` |
| The guard tests (t1 to t12), the bench on Arena's own guards, replays, the agent's access key, older limits | `docs/bench-details.md` |
| The guard's fix and `reconcile` design | `docs/guard-tests.md` |
| The proofs and their limits | `evidence/proofs-2026-11-10.md`, `evidence/proofs-inductive-2026-11-11.md`, `proofs/README.md`, `tla/README.md` |
| The rebuild, the direct-pay proof, the property library and the other teams' counts | `evidence/proofs-all-2026-11-11.md`, `evidence/repro-build-2026-11-11.md`, `proofs/properties/README.md` |
| The planted mistakes, one row each | `evidence/mutation-table-2026-11-11.md` |
| The receipts on NEAR testnet | `evidence/receipts-testnet-2026-11-11.md` (first set: `evidence/receipts-testnet-2026-11-10.md`) |
| How the harness sets up and scores a run | `harness/README.md` |
| What every evidence file is | `evidence/README.md`, then `evidence/INDEX-2026-11-12.md` for files added after Nov 11 |
| Each other team's claims and fingerprint | `targets/entrant-A/`, `targets/entrant-B/`, `targets/entrant-C/`, `targets/entrant-G/` |
| Testing guards that work differently (no invoices), the gate and its self-tests | `docs/GUARD-CAPABILITIES.md` |

Built with Rust 1.86, near-sdk 5.27, near-workspaces 0.24 and near-sandbox (nearcore 2.14); the other teams' guards were built from their source with Rust 1.99.1. AI coding agents wrote parts of the code, under review. All code was written from Nov 8, 2026, inside the hackathon window (Nov 1 to 14). MIT licence (`LICENSE`).

