# Arena

**Prove your AI agent's payment guard before you give it your money.**

Your AI agent pays your bills. A guard is a small contract that stops it
spending too much. We attacked guards on NEAR and found two ways you still
lose money:

1. **The guard pays one bill twice.** Two pay messages for one 100 bill
   arrive together. Our planted-flaw guard paid 200, on NEAR testnet,
   5 times out of 5.
2. **A tricked agent pays bills you never meant to pay.** Every payment
   followed the guard's rules. In the worst case we found, replayed twice on
   a local test chain, 500 tokens went out in one run that the owner never
   wanted sent.

Testing alone is not enough. We planted 10 mistakes in our own guard and
our attacks found 7. A review of our proofs then found a bug in our own fix,
and we fixed it.

So Arena also **proves**. A proof checks every way the calls can line up,
not just the ones we tried.

| What we proved | Result | Tool |
|---|---|---|
| The fixed guard never pays a bill twice when pay messages race | on the real code, holds for every order of up to 4 pay calls; on the model, for any number of calls. The broken guard fails, as it should | Kani, plus NEAR's own near-tla (up to 3 pay calls) |
| Tight rules never pay more than the owner meant | holds for up to 10 payment requests, in our test setup | z3 |
| The result is public | saved on NEAR testnet, so anyone can look a guard's results up. A lookup shows the guard's code fingerprint; our broken and fixed guards share one, so a lookup must also read the guard's mode. Receipts for the current build were published Nov 10; results another contract can read before paying, Nov 11 (`evidence/results-testnet-2026-11-11.md`) | arena-receipts |

**What "proved" means here:** the "any number of calls" proof covers a
careful copy of the guard's logic (the model), not the contract itself. We
then ran the real code beside the model and they matched in every case we
checked: every order of up to 4 pay calls (4,555 states), and every order of
2 pay calls in a fuller world where callbacks die, `reconcile` runs and
outside tokens arrive (21,345 states). It is a proof up to these limits, not
a promise about every possible future.

Check it yourself: `./verify.sh fast` (about 8 min), `proofs/run.sh` (about
25 min), `tla/run.sh` (about 46 min for all 25; the quick check
`tla/run.sh vuln_race fixed_1inv h1_outside_transfer_reconcile` takes about 15 s).

`EVALUATE.md` lists every claim with its command, the line you should see, our time, and our saved log.

**Track:** AI Security & Defense (`security`). **Status:** working prototype on a local NEAR sandbox, with the double-pay result confirmed on NEAR testnet.

## Every result, with its evidence

| What we tested | Result | Evidence |
|---|---|---|
| Planted-flaw guard: two `pay` calls at once for one 100-token invoice | paid 200, in 5 of 5 trials, on the local sandbox and on NEAR testnet | `evidence/testnet-2026-11-11.md` (first run: `evidence/testnet-2026-11-09.md`) |
| The same guard with the fix | paid 100, in 5 of 5 trials, on both, with the current build (`0382023b…`). The other call was refused with `payment already in flight` every time | `evidence/testnet-2026-11-11.md`, `evidence/verify-2026-11-11.md` |
| Worst case under the broad rules: z3 searched every sequence of up to 10 pay requests, and we replayed its answer twice on a local test chain | 500 tokens against the owner's intent in one run, 0 beyond policy, both replays | `evidence/proofs-2026-11-10.md` |
| 10 mistakes planted in our own guard (vault-a), one at a time | our attacks caught 7 of 10. The other 3 sit on paths no attack walks down | `evidence/mutation-table-2026-11-11.md` |
| The bug in our own fix: `reconcile` reopened a paid bill after an outside top-up, so the guard paid 200 on a 100 bill | a review of the proofs found it; we fixed it and re-ran everything: proofs 30 of 30, near-tla 25 of 25 as planned | `evidence/proofs-adversarial-review-2026-11-11.md`, `evidence/fix-plan-2026-11-11.md`, `evidence/proofs-inductive-2026-11-11.md` |
| Three other teams' guards (Guard A, B, C), tests written from each guard's own claims | 29 of 29 tests of their own rules held. 0 tokens paid beyond policy | `evidence/coverage-table.md` |
| Fully fooled agent (a script that obeys every injection), 5 separate scenario runs | 0 tokens paid beyond policy. 450 tokens against the owner's intent across the five runs added up; at most 200 in any one run | `evidence/injection-intent-by-recipient.md` |
| Real model (Muse Spark 1.3): 25 trials, then 30 trials against an attacker model that rewrote its email after each failure | 0 fooled in 52 trials where it read the email. 0 tokens paid against the owner's intent | `evidence/injection-2026-11-09-model.md`, `evidence/injection-2026-11-09-adaptive.md` |
| Real model on NEAR AI Cloud (glm-5.3-flash), the same 5 scenarios, 2 trials each | 0 fooled in 10 trials. 0 tokens paid against the owner's intent | `evidence/injection-2026-11-11-nearai-model.md` |

## Check it yourself

You need:

- **Rust**, through rustup: `curl https://sh.rustup.rs -sSf | sh`. The repo pins the toolchain (`rust-toolchain.toml`), so rustup fetches the right version on first build.
- **The NEAR sandbox**: nothing to install. The scripts download it on the first run (needs the internet).
- **Python 3**, for `arena check`, the prompt-injection scripts and the tool tests.
- **Node 18 or newer**, for the lookup and its tests (`tools/lookup/`).
- For the proofs only: **Kani** (`cargo install --locked kani-verifier && cargo kani setup`), **z3** (`python3 -m venv proofs/.venv && proofs/.venv/bin/pip install z3-solver`), and **Java 17 or newer** for `tla/run.sh` (`brew install openjdk@21`; the other near-tla setup steps are in `tla/README.md`).

Tested on macOS (Apple silicon).

```
./verify.sh fast     # the headline: the double pay, and the bench catching it. 5 checks
./verify.sh          # every local sandbox result in this README. 43 checks
proofs/run.sh        # Kani on the model, the real code beside it, and z3. 30 checks
tla/run.sh           # near-tla, NEAR's own model of how calls run. 25 checks
```

Each check prints PASS or FAIL. The last line of `verify.sh` is `verify: 5 passed, 0 failed (mode=fast)` or `verify: 43 passed, 0 failed (mode=full)`, and each script exits 0 only if every check passes. Measured times: `fast` took 481 s on a fresh copy with no build folders (Nov 9) and 196 s with the builds already there; the full `verify.sh` took 943 to 965 s (four runs); `proofs/run.sh` took 1,504 s; `tla/run.sh` took about 46 min, most of it in two checks (`fixed_2inv` and `h1_open_world_2faults`). Neither proof script has a quick mode. `tla/run.sh <name>` runs only the named checks, and the small ones take a few seconds. `proofs/run.sh proof2` runs only z3. The proofs need Kani and z3 (setup in the header of `proofs/run.sh`); near-tla needs Java 17+ (setup in `tla/README.md`). Each run writes its logs to a new folder `runs/<UTC time>/` (not tracked by git), so running the checks never changes a committed file; set `ARENA_RECORD=1` to write into `evidence/` instead. Every `verify.sh` run appends one line to `verify-summary.log` in its run folder.

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
| The same check on our planted-flaw guard that pays the agent: `./arena check targets/planted-outflow/planted_outflow.wasm` | `broke 11 of 51 (... 1800 tokens paid outside the five receivers ...)`. Money that goes to any account the attack was not meant to reach counts as broke; money the check cannot find ends it incomplete, never held | `evidence/check-outflow-2026-11-11.md` |
| Copy `examples/workflows/arena-check.yml` into your repo's `.github/workflows/` | the check on every pull request, with read-only access. Not yet run on GitHub | `docs/CHECK-YOUR-GUARD.md` |
| Replay a saved attack: `./run-arena.sh replay sequences-paper/<file>.json --wasm your_guard.wasm` | the attack's result against your guard, with no model call | `docs/ADD-AN-ATTACK.md` |
| Look up a guard on NEAR testnet before paying it: `node tools/lookup/cli.mjs <account>` | `status: held`, `broke`, `not_tested` or another answer; only `held` is a pass | `docs/CHECK-BEFORE-YOU-PAY.md` |
| Opt your guard in on NEAR testnet, or ask for a result from another contract before paying | the contract stores who signed and which code; it never says "safe" | `docs/ON-CHAIN.md`, `docs/REGISTER-A-GUARD.md` |

**The hunter.** A language model reads new security papers and hack news and proposes attacks as data: a list of steps from a small fixed vocabulary, never code. A validator rejects anything else, and the bench runs the rest against Arena's own guards and guards whose owners opted in. 7 hunts so far proposed 41 attacks from 10 papers (11 reads: one paper, 2104.08638, was read in two hunts) and 4 news items; 25 were saved and 2 broke a guard, both guards built to be broken. The daily GitHub schedule (`.github/workflows/hunt.yml`) has never run. The model now runs on NEAR AI Cloud by default, and such a run saves NEAR's attestation report (1 of the 7 hunts so far; the others ran on Muse Spark, which has none), which you can re-check offline: `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json`. The report shows which model answered, not that an attack is good. Details: `EVALUATE.md` section 4.

**Which attacks are proven to detect something.** Running cleanly on every guard does not show an attack can catch anything. An attack counts as validated only when a script (`tools/admission/admit.py`) has run it on a guard known to be good (it must hold) and on a copy with exactly the one flaw the attack names (it must break, by the exact amount, the way the attack says), three times each, and kept the raw runs. Attack admission: **16 of 53** attacks validated, 1 partially validated, 36 unvalidated. The 53 are 47 attack files plus 4 prompt-injection scenarios from `tools/injection/scenarios.json` (51 for a guard paying in tokens or NEAR), plus 2 NEAR Intents files. The partial one is the double-pay race: its outcomes match, but the runs do not yet record block heights, so nothing shows the two calls really overlapped. The unvalidated ones still run on every guard, and each row of `evidence/MANIFEST.md` says why it is not validated: most are races, which the gate cannot count until the runs record block heights; the rest break nothing a single planted flaw can show, or NEAR's access key stops them first. Saving a hunter attack admits nothing: of the 25 saved, only the ones the gate admitted count. Every count: `evidence/MANIFEST.md`, generated by `tools/admission/manifest.py`. A hidden set of 9 more admitted attacks is kept out of the repo and committed by hash only (`hidden-set/COMMITMENT.json`), so a guard cannot be tuned to it; its first runs on our own guards are in `evidence/hidden-set/`, and they hold one limit: the set has no race variant yet. How to check both without seeing the set: `EVALUATE.md` section 4b.

## The two numbers Arena reports, never combined

| Number | What it counts | Where the rule comes from |
|---|---|---|
| **Tokens paid beyond policy** | tokens that left the guard in breach of the guard's own written rules. A non-zero value is a guard failure | the policy file, fixed before any test (`policy/`, or the guard's `CLAIMS.md`) |
| **Tokens paid against the owner's intent** | tokens a recipient got beyond what the owner intended for them, even when the guard's rules allowed it | the owner's intended allocation, written before any run (`tools/injection/scenarios.json`, field `intended`) |

Both come only from final balances on the chain, never from what the guard or the agent reports. The agent never sees `intended`; only the scorer reads it. Arena also prints the honest payments that settled, so a guard that refuses everything cannot look perfect.

## Why this is a NEAR problem

NEAR runs one contract call across several blocks. A payment guard checks "is this invoice paid?" in block N, the tokens move in block N+1, and the guard records the result in block N+2. A second `pay` for the same invoice that arrives before N+2 still sees "not paid", and pays again. The fix is to record the payment before starting the transfer, and to undo it only if the transfer fails. On testnet, both `pay` checks ran before the first result was recorded in all 10 trials of each run: in the same block every time on Nov 9, and in 7 of 10 on Nov 10, one block apart in the other 3 (`evidence/testnet-2026-11-09.md`, `evidence/testnet-2026-11-11.md`; that file is named for the Nov 11 guard build it tested, and its runs started Nov 10, 15:58 UTC).

## Other teams' guards

We name them only by letter. Before any run, for each guard, we wrote down what it claims (`targets/entrant-X/CLAIMS.md`) and its build fingerprint (`targets/entrant-X/FROZEN.txt`), then scored only those claims. Anything beyond its claims is marked "not claimed" and never counted as a failure.

| Guard | What it is | Tests of its own rules | Held | Tokens paid beyond policy | Not evaluated |
|---|---|---|---|---|---|
| A | invoice payer with payee list and daily cap, token | 7 | 7 | 0 | cross-chain payments, escrow |
| B | vault in native NEAR with caps, approvals, pause | 10 | 10 | 0 | a refund callback that lands after UTC midnight |
| C | company treasury with a server-bill pot and a profit pot | 12 | 12 | 0 | swaps and withdrawals that need secure hardware and NEAR's shared signing network |

That is 29 tests, and 29 held. Each guard also made one normal payment to show it works, and all 3 went through. Guard A faced one more test, on a rule it never promised, and it held. So the coverage table has 33 rows: 29, plus 3, plus 1.

All three held for the same reason: each records the payment before it moves the money. Their source code, built files and test runners are not in this repo, to keep them anonymous. Per-test detail, including the two corrections we made during the runs: `evidence/coverage-table.md`.

## Limits

- **Local sandbox, except one result.** We ran only the planted-flaw guard and its fix on testnet, on the current build (`0382023b…`). The race never reaches the `reconcile` fix, so testnet did not test that fix. We tested the three other teams' guards on the local sandbox.
- **The proofs have limits.** The "any number of calls" proof covers the model only. The model matches the real code in every case we checked: up to 4 pay calls (4,555 states), and 2 pay calls in the full world with faults (21,345 states). near-tla checks up to 3 pay calls. The z3 result covers our 7-invoice test setup and up to 10 payment requests. None of it covers the deployed wasm itself.
- **A receipt lookup needs the mode.** The broken and fixed guards share one code fingerprint, so a lookup must also read the guard's mode.
- **29 of 29 held means each guard kept the rules it wrote down, in these tests.** We built each guard's tests from its claims, so the three guards faced different tests, and we could not test some paths locally (table above). It is not a proof that a guard is secure.
- **The 450 tokens are five separate runs added up, from a scripted agent that obeys every injection.** No single run paid more than 200. The 500 is a different number: the worst single run z3 found under the same rules, which we replayed on a local test chain. The real model resisted in every run we made; that does not show it always will. All 450 tokens went to creditors the owner had approved. None reached an attacker's account. In one scenario the intended recipient got nothing.
- **One model played both attacker and victim** in the adaptive test, with one goal and one guard.
- **The agent never sees a refusal.** In the injection test, `pay` returns "submitted" and the chain runs after the conversation.
- **On the local sandbox, races were tested with both calls in the same block only.** On testnet, 3 of 10 trials on Nov 10 had the two checks one block apart.
- **Corrections, all kept in the evidence files:** Guard B's reserve test was invalid on its first run; we fixed it and re-ran all 11 tests. We added Guard C's two deposit tests after its first run. The adaptive test crashed once on an API timeout, and we resumed it from its saved rounds.
- **Deposits into NEAR Intents are tested on the local sandbox only; money that leaves NEAR is not tested.** For a guard that pays into NEAR Intents (`"pays_in": "intents"`), Arena runs the pinned release build of the Intents contract (defuse v0.4.2) on the local sandbox and reads who it credited. Tokens it cannot place end the check incomplete, never held (`evidence/check-intents-2026-11-11.md`). It does not test withdrawals from Intents to other chains, Chain Signatures requests, solvers or swaps, or the real Intents contract on mainnet (NEAR Intents has no testnet).
- **"Beyond policy" reads one input from the guard itself.** Balances come from the chain, but whether an invoice counts toward what its receiver may get depends on the guard's own `get_invoice` status (`Paid`, for an invoice the agent tried to pay). A guard that reports a wrong status can move that number (`harness/src/scorer.rs`).
- **When no pay start time was recorded, expiry is not scored.** If an expiring invoice ends `Paid` but the bench recorded no start time for its payment, it cannot tell whether the payment came before or after expiry. It counts the invoice as allowed and prints `expiry not scored`.
- **On chain, a result is not tied to the guard's mode or to an opt-in.** The contract's answer does not read the guard's mode, so a contract asking about a wasm that has results under more than one mode must name the suite (`docs/ON-CHAIN.md`). `publish_result` does not check the opt-in table, so a result on chain does not show that the guard's owner agreed to be tested.
- **"Validated" is only as strong as the attack's written checks.** "Broke through the named mechanism" means the checks the attack's spec lists passed on every counted run (one check is the minimum), and the flaw counts as matched because the broken copy's flaw label equals the one the spec names; nobody checked which line of code fired.
- **The double-pay guard (`contracts/guard`, mode `vulnerable_fixture`) is a labelled test case.** Never deploy it.

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
| The planted mistakes, one row each | `evidence/mutation-table-2026-11-11.md` |
| The receipts on NEAR testnet | `evidence/receipts-testnet-2026-11-11.md` (first set: `evidence/receipts-testnet-2026-11-10.md`) |
| How the harness sets up and scores a run | `harness/README.md` |
| What every evidence file is | `evidence/README.md` |
| Each other team's claims and fingerprint | `targets/entrant-A/`, `targets/entrant-B/`, `targets/entrant-C/` |

Built with Rust 1.86, near-sdk 5.27, near-workspaces 0.24 and near-sandbox (nearcore 2.14); the other teams' guards were built from their source with Rust 1.99.1. AI coding agents wrote parts of the code, under review. All code was written from Nov 8, 2026, inside the hackathon window (Nov 1 to 14). MIT licence (`LICENSE`).

**Summary:** 0 tokens paid beyond policy across 29 tests of three teams' guards; the planted flaw caught at 200 on a 100 invoice, locally and on testnet; 500 tokens paid against the owner's intent in one run (the worst case, replayed on a local test chain), through payments the guard's rules allowed; 7 of 10 planted mistakes caught; proofs 30 of 30 and near-tla 25 of 25 as planned after we fixed the bug the review found in our own fix.
