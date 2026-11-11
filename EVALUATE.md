# Evaluate Arena

This file is for anyone, person or coding agent, who wants to check Arena's claims by running
them. Each claim below has the command to run, the line you should see, how long it took us, and
the saved log of our own run.

If a command does not print what this file says, that is a bug in Arena or in this file. The
saved log shows what we got.

## Before you start

| You need | For |
|---|---|
| Rust through rustup, Python 3 | everything in sections 1 to 4 |
| Node 18 or newer | the lookup (section 5) |
| Kani and z3 | `proofs/run.sh` only |
| Java 17 or newer | `tla/run.sh` only |

- Tested on macOS, Apple silicon. Nothing here has been run on Linux or on GitHub's runners.
- The contract folders pin Rust 1.86.0 in `rust-toolchain.toml`, and the first build downloads the
  NEAR sandbox, so the first run needs the internet.
- No command in sections 1 to 4 needs an API key, a wallet or testnet. They run on a **local NEAR
  sandbox**: a private copy of NEAR on your machine, with no real money.
- Section 5 reads NEAR testnet. It sends no transaction and needs no key.

## 1. The shortest path (about 8 minutes)

```
./verify.sh fast
```

Last line: `verify: 5 passed, 0 failed (mode=fast)`. Exit code 0.

It builds the contracts and the harness, then shows the main result: the planted-flaw guard pays
200 on a 100 invoice when two `pay` calls arrive together, the fixed guard pays 100, and the bench
scores both from final balances. Measured: 481 s on a fresh copy with no build folders, 197 s
when the builds are already there.

## 2. Each claim, and how to check it

| # | Claim | Command | You should see | Our time | Our saved run |
|---|---|---|---|---|---|
| 1 | Two `pay` calls at once make the planted-flaw guard pay 200 on a 100 invoice. The fixed guard pays 100. | `./verify.sh fast` | `verify: 5 passed, 0 failed (mode=fast)` | 481 s cold, 197 s warm | `evidence/verify-2026-11-11.md` |
| 2 | Every local sandbox result in the README. | `./verify.sh` | `verify: 43 passed, 0 failed (mode=full)` | 946 s | `evidence/verify-2026-11-11.md`, `evidence/verify-summary.log` |
| 3 | The fixed guard never pays one invoice twice when pay calls race. Checked on a model of the guard for any number of calls, and on the real code for every order of up to 4 pay calls. | `proofs/run.sh` | 30 checks, each `PASS` | 1,504 s | `evidence/proofs-inductive-2026-11-11.md`, `evidence/proofs-2026-11-10.md` |
| 4 | The same property in near-tla, NEAR's own model of how calls run, up to 3 pay calls. | `tla/run.sh` (all 25), or `tla/run.sh vuln_race fixed_1inv h1_outside_transfer_reconcile` (3 of them) | 25 checks as planned, or the 3 quick ones | about 46 min, or about 15 s | `evidence/tla-2026-11-11/` |
| 5 | We planted 10 mistakes in our own guard, one at a time. Our attacks caught 7. | `tools/mutation/run.sh` | `summary.tsv` with M1, M2, M4, M5, M6, M7, M8 caught and M3, M9, M10 not | one mutant: 573 s, including the two baseline checks; all ten: 2,410 s (about 40 min). Our re-run on Nov 11 matched the saved table row for row | `evidence/mutation-table-2026-11-11.md` |
| 6 | An agent that obeys every injected instruction pays 0 tokens beyond the guard's rules, and 450 tokens against the owner's intent across five runs. | `ARENA_AGENT=compromised python3 -I tools/injection/run.py` then `python3 -I tools/injection/rescore.py` | rescore ends `Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).` | 80 s, then under 1 s | `evidence/injection-intent-by-recipient.md` |
| 7 | One command checks a guard against the whole attack library and says held or broke. | section 3 | `arena: held 51/51 ...` for vault-a, `arena: broke 5 of 51 ...` for the leaky guard | 277 s each | `evidence/check-fixes-2-2026-11-11.md`, `evidence/check-outflow-2026-11-11.md` |
| 8 | The same check works for a guard that pays in plain NEAR, not a token. | section 3 | `arena: held 48/48 ...` for native-fixed, `arena: broke 5 of 48 ...` for native-control | about 230 s each | `evidence/check-native-2026-11-11.md` |
| 9 | If a guard pays any account the attack was not supposed to reach (the agent, the outsider, an account the attack named), the check says broke and names who got it. Money it cannot find makes the check incomplete, never held. | section 3 | `arena: broke 11 of 51 (... 1800 tokens paid outside the five receivers ...)` for planted-outflow | about 280 s | `evidence/check-outflow-2026-11-11.md` |
| 10 | The hunter's saved attacks replay from their JSON files, with no model call. | section 4 | section 4 | about 15 s per replay | `evidence/hunts/` |
| 11 | The double-pay result and its fix are saved on NEAR testnet, and anyone can look them up. | section 5 | section 5 | 1 to 2 s | `evidence/receipts-testnet-2026-11-11.md`, `evidence/testnet-2026-11-11.md` |
| 12 | A guard owner can sign a note on NEAR testnet saying "Arena may test this exact code", and another contract can ask for a result before it pays. | section 5 | `opt-in:    opted_in` in the lookup | 1 to 2 s | `evidence/onchain-2026-11-11.md`, `evidence/results-testnet-2026-11-11.md`, `docs/ON-CHAIN.md` |
| 13 | When the hunter's model runs on NEAR AI Cloud, the run saves NEAR's attestation report (a record, signed inside NEAR's sealed hardware, of which model and configuration answered). | `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json` | `recheck: all checks pass (Intel and NVIDIA signatures are not checked offline)`, exit 0 | under 1 s | `evidence/nearai-2026-11-11.md` |

Claim 6 needs the harness built first; `./verify.sh fast` does that.

Unit tests for the tools (no sandbox, no model, no key). The lookup tests also read NEAR testnet;
set `ARENA_LOOKUP_OFFLINE=1` to skip those.

```
python3 -I tools/check/tests/test_check.py
python3 -I -m unittest discover -s tools/hunter/tests
node --test tools/lookup/test.mjs
```

The on-chain contract's own sandbox tests (opt-in, results, a contract asking before it pays):

```
(cd receipts && cargo build --release --target wasm32-unknown-unknown)
(cd receipts/host && cargo test --release --test onchain)
```

One of them, the upgrade test, shows as `ignored`: it needs the contract's earlier build, see
`evidence/onchain-2026-11-11.md`.

A note on counting: `evidence/check-2026-11-11.md` and `check-plan-2026-11-11.md` say `52/52`.
That older count included the honest payment the check makes before any attack. There are 51
attacks; `evidence/check-fixes-2-2026-11-11.md` records the correction. The old files are kept as
they were, as a record of what the check said at the time.

## 3. Break a guard yourself

There are two ways. Both run on the local sandbox only.

### Plant one of our mistakes

`vault-a` is Arena's own reference guard. `tools/mutation/mutate.py` holds 10 small edits to it,
M1 to M10. Each one removes or weakens one rule. M0 is an unchanged copy.

```
tools/mutation/run.sh M5
```

M5 removes the "payment in flight" mark that the guard sets before it moves tokens. The script
copies vault-a, applies the edit, writes the diff to `mutants/M5/MUTATION.md`, builds it, and runs
the 10 scripted attacks against it. You should see M5 caught by `02-race-double-pay`, with 100
tokens paid beyond the policy. Logs land in `evidence/mutation-<today>/`; set `MUT_DATE=<name>` to
choose another folder name, so you do not write over a saved table.

The script first checks two things, and stops if either fails: the unchanged vault-a scores 0 on
all 10 attacks, and the leaky reference guard is caught.

Three mutants are **not** caught: M3, M9 and M10. The table says why for each
(`evidence/mutation-table-2026-11-11.md`). Run `tools/mutation/run.sh M3` to see a miss.

To plant a mistake of your own, add an entry to `tools/mutation/mutate.py` and run it the same
way.

### Check any guard with one command

```
./arena check targets/vault-a/vault_a.wasm
./arena check targets/leaky-control-v2/leaky_control.wasm
```

The first should end `arena: held 51/51 (0 not applicable; rules claimed: all 4 (payees, cancel,
expiry, daily_cap); 2450 tokens paid against the owner's intent)`, exit code 0. The second should
end `arena: broke 5 of 51 (...)`, exit code 1, and list the 5 attacks. Each writes
`arena-report/report.html`, a one-page report that needs no internet. Each took us 277 s.

A guard that pays in plain NEAR, not a token, needs one line in its config (`"pays_in": "native"`):

```
./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json
./arena check targets/native-control/native_control.wasm --config examples/configs/native-guard.json
```

The first should end `arena: held 48/48 (...; scored from NEAR balances)`, exit code 0. The second
should end `arena: broke 5 of 48 (...)`, exit code 1. Three token-only attacks do not apply to a
guard that holds no tokens, so the native suite has 48. About 230 s each.

A guard that pays the wrong person. `targets/planted-outflow/` is a copy of vault-a with one
planted flaw: a second `pay` on a paid invoice sends the amount to whoever called, the agent.

```
./arena check targets/planted-outflow/planted_outflow.wasm
```

It should end `arena: broke 11 of 51 (0 not applicable; rules claimed: all 4 (payees, cancel,
expiry, daily_cap); 1800 tokens paid outside the five receivers; 2450 tokens paid against the
owner's intent)`, exit code 1. Before the fix in `evidence/check-outflow-2026-11-11.md`, this
same guard scored `held 51/51`, because the check only read five receivers' balances.

To check your own guard, see `docs/CHECK-YOUR-GUARD.md`. You pass your `.wasm`, and a small config
if your guard starts differently or lacks a rule.

Things to know when you read a result:

- **"Held" means these attacks found nothing. It does not mean the guard is safe.**
- An attack on a rule the guard does not claim is reported as **not applicable**, never as held.
- The two numbers are never added together. "Beyond policy" is the guard breaking its own rules.
  "Against the owner's intent" is money the rules allowed but the owner did not mean to send.
  vault-a holds on the first and still shows 2450 on the second, because its owner's rules are wide.
- Exit codes: 0 held, 1 broke, 2 the check could not finish, 64 bad usage. A check that could not
  finish is never reported as held.

## 4. The hunter's attacks, and where each came from

The hunter is the part of Arena that reads new security papers and hack news and turns them into
attacks. A language model proposes each attack as **data**: a list of steps from a fixed, small
vocabulary (`call`, `view`, `race`, `wait_blocks`, `wait_seconds`, `add_key`). The model writes no
code. A validator rejects anything outside that vocabulary before the bench runs it.

What is in the repo:

- **25 saved attacks** in `sequences-paper/`, one JSON file each. 14 are call sequences and 11 are
  prompt-injection scenarios.
- **7 hunt records** in `evidence/hunts/`, one `.md` and one `.json` per run.

Each attack file has a `meta` block. You can read where the attack came from without trusting us:

| Field | What it tells you |
|---|---|
| `source`, `parents` | the paper or news item it came from, or the two attacks it was combined from |
| `author` | which model proposed it, through which tool |
| `found_in_hunt` | the hunt record that made it |
| `steps_sha256` | a fingerprint of the steps, so an edit after the fact shows |
| `broke_guards`, `held_guards` | which of Arena's own guards it broke or did not |
| `validation` | whether it ran cleanly and what it found |

Each hunt record stores the command that ran, the git commit, the list of uncommitted files at the
time, the harness fingerprint, and the result of a known-answer test run first: the double-pay
attack must break the three planted-flaw guards and must not break the three fixed ones, or the
hunt's results are not trusted.

What the 7 hunts did, in total: the model proposed 41 attacks from 10 papers and 4 news items, 25
were saved, and **2 of the 25 broke a guard**. Both broke only guards we built to be broken
(`guard-vulnerable`, `leaky-control-v2`, `native-control`). None broke a fixed guard. Most paper
attacks found nothing, and the records say so. The two Nov 11 hunts saved nothing new and broke
nothing; one of them ran on NEAR AI Cloud and its attestation can be re-checked (claim 13).

Replay one that broke a guard, with no model and no key:

```
./run-arena.sh replay sequences-paper/p210408638-1-reentrancy-async-double-pay.json --target control
./run-arena.sh replay sequences-paper/p210408638-1-reentrancy-async-double-pay.json --target vault
```

The first runs it against the leaky guard and should print a line starting
`UNAUTHORISED PAYOUT = 200` (all 200 beyond what the owner authorised). The second runs it against
vault-a and should print `UNAUTHORISED PAYOUT = 0`. About 15 s each.

To add an attack by hand, see `docs/ADD-AN-ATTACK.md`.

**What has not happened yet:** `.github/workflows/hunt.yml` schedules the hunter to run on GitHub
every day. That schedule has **never run**, because this repo has not been on GitHub. All 7 hunt
records come from runs on one Mac. The "hours from paper to attack" figure in
`evidence/response-time-2026-11-11.md` is a replay of what the schedule would do, not a
measurement of it.

The design borrows ideas from AutoRedTeamer (Andy Zhou et al., NeurIPS 2025, arXiv 2503.15754). No
code was copied. See `docs/DESIGN-CREDIT.md`.

## 5. Look up a result on NEAR testnet

```
node tools/lookup/cli.mjs <guard account on testnet>
```

It reads the guard's code fingerprint, the results Arena published for that code, and the guard's
mode, then prints one sentence. Only the status `held` is a pass; every other answer, including a
network error, is not. Exit code 0 for held, 1 for anything else, 2 for bad input or a network error.

Two accounts to try. Both run the same code (sha256 `0382023b…`); only their mode differs.

```
node tools/lookup/cli.mjs r11cfx4-guard.arena-race-funder-1111.testnet
node tools/lookup/cli.mjs r11bvf3-guard.arena-race-funder-1111.testnet
```

The first (the fixed guard) should start `Held the double-pay race test (5 of 5 runs held, 0 paid
over the limit)` and show `status:    held` and `opt-in:    opted_in`, exit code 0. It also lists the
`vulnerable_fixture` result for the same code as `not counted`, because this guard reports mode
`fixed`. The second (the planted-flaw guard) should start `Broke the double-pay race test (0 of 5
runs held; worst run paid 100 over the limit)` and show `status:    broke`, exit code 1. Each took
us 1 to 2 s.

`on chain:` is the result stored in Arena's own contract, which a wallet contract can read before it
pays (`docs/ON-CHAIN.md`). The fixed guard shows `on chain:  held` for mode `fixed`, and the
planted-flaw guard `on chain:  broke` for mode `vulnerable_fixture`. Those results were published
on Nov 11, for Arena's own guards only: `evidence/results-testnet-2026-11-11.md`, with transaction
links.

See `docs/CHECK-BEFORE-YOU-PAY.md` for more and `docs/ON-CHAIN.md` for what is stored.

## 6. What you cannot re-run from this repo

- **Guards A, B and C.** These are three other teams' guards. Their source, built files and test
  runners are not in this repo, to keep them anonymous. You can read what each one claims
  (`targets/entrant-A/`, `-B/`, `-C/`) and the per-test results (`evidence/coverage-table.md`), but
  not re-run them.
- **The real-model runs** need a model API key: `NEARAI_API_KEY` for NEAR AI Cloud (the default),
  or `MUSE_API_KEY` with `ARENA_MODEL_PROVIDER=muse`. Without one, read the saved trials in
  `evidence/`.
- **The testnet race itself** needs a funded testnet account. The saved run is
  `evidence/testnet-2026-11-11.md`, with transaction links.
- **New hunts** need the same model key, and an Elfa key (`ELFA_API_KEY`) for news. The saved
  attacks replay without either.

## 7. Known limits

The README's "Limits" section is the full list. The ones that matter most when you judge a result:

- Everything is on a local sandbox except the double-pay race and its fix.
- The "any number of calls" proof covers a model of the guard, not the deployed wasm. The model
  was compared with the real code for up to 4 pay calls.
- Three planted mistakes go uncaught (M3, M9, M10).
- "Held" for Guards A, B and C means each kept its own written claims under tests built from those
  claims. The three guards faced different tests.
- `./arena check` trusts the guard's own view methods in its preflight step.
- Nothing has run on Linux or on GitHub.
- Money that leaves NEAR or goes into NEAR Intents is not tested: no deposits into the Intents
  contract, no withdrawals to other chains, no Chain Signatures requests.

## How the evidence files are named

The tag `2026-11-11` in a file name is a run tag, not always the day the file was made. It was
first used on Nov 10 2026 for the second run of that day, after a fix, so that run would not
overwrite the first run's logs. Files made on Nov 11 carry the same tag. `evidence/README.md`
explains this and says which file answers which question.
