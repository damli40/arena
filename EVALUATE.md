# Evaluate Arena

This file is for anyone, person or coding agent, who wants to check Arena's claims by running
them. Each claim below has the command to run, the line you should see, how long it took us, and
the saved log of our own run.

If a command does not print what this file says, that is a bug in Arena or in this file. The
saved log shows what we got. We ran 12 of these commands from a fresh copy with no build folders;
every exit code and key line matched (`evidence/clean-copy-2026-11-11.md`).

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
scores both from final balances. Measured: 481 s on a fresh copy with no build folders, 196 s
when the builds are already there.

Its logs go to a new folder, `runs/<UTC time>-verify-fast/`, which git ignores, and every check
reads that run's own logs. `run-arena.sh` and the prompt-injection scripts do the same
(`runs/<UTC time>/`), and `arena check` writes to `./arena-report`, also ignored, so these leave
`git status` clean. To write a new saved run into `evidence/` on purpose, set `ARENA_RECORD=1`.
`tools/mutation/run.sh` (section 3) still writes into `evidence/mutation-<today>/`.

## 2. Each claim, and how to check it

| # | Claim | Command | You should see | Our time | Our saved run |
|---|---|---|---|---|---|
| 1 | Two `pay` calls at once make the planted-flaw guard pay 200 on a 100 invoice. The fixed guard pays 100. | `./verify.sh fast` | `verify: 5 passed, 0 failed (mode=fast)` | 481 s cold, 196 s warm | `evidence/verify-2026-11-11.md` |
| 2 | Every local sandbox result in the README. | `./verify.sh` | `verify: 43 passed, 0 failed (mode=full)` | 943 to 965 s (four runs) | `evidence/verify-2026-11-11.md`, `evidence/verify-summary.log` |
| 3 | The fixed guard never pays one invoice twice when pay calls race. Checked on a model of the guard for any number of calls, and on the real code for every order of up to 4 pay calls. | `proofs/run.sh` | 30 checks, each `PASS` | 1,504 s | `evidence/proofs-inductive-2026-11-11.md`, `evidence/proofs-2026-11-10.md` |
| 4 | The same property in near-tla, NEAR's own model of how calls run, up to 3 pay calls. | `tla/run.sh` (all 25), or `tla/run.sh vuln_race fixed_1inv h1_outside_transfer_reconcile` (3 of them) | 25 checks as planned, or the 3 quick ones | about 46 min, or about 15 s | `evidence/tla-2026-11-11/` |
| 5 | We planted 10 mistakes in our own guard, one at a time. Our attacks caught 7. | `tools/mutation/run.sh` | `summary.tsv` with M1, M2, M4, M5, M6, M7, M8 caught and M3, M9, M10 not | one mutant: 573 s, including the two baseline checks; all ten: 2,410 s (about 40 min). Our re-run on Nov 11 matched the saved table row for row | `evidence/mutation-table-2026-11-11.md` |
| 6 | An agent that obeys every injected instruction pays 0 tokens beyond the guard's rules, and 450 tokens against the owner's intent across five runs. | `ARENA_AGENT=compromised python3 -I tools/injection/run.py` then `python3 -I tools/injection/rescore.py` | rescore ends `Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).` | 80 s, then under 1 s | `evidence/injection-intent-by-recipient.md` |
| 7 | One command checks a guard against the whole attack library and says held or broke. | section 3 | `arena: held 51/51 ...` for vault-a, `arena: broke 5 of 51 ...` for the leaky guard | about 275 s each | `evidence/check-fixes-2-2026-11-11.md`, `evidence/check-outflow-2026-11-11.md` |
| 8 | The same check works for a guard that pays in plain NEAR, not a token. | section 3 | `arena: held 48/48 ...` for native-fixed, `arena: broke 5 of 48 ...` for native-control | about 230 s each | `evidence/check-native-2026-11-11.md` |
| 9 | If a guard pays any account the attack was not supposed to reach (the agent, the outsider, an account the attack named), the check says broke and names who got it. Money it cannot find makes the check incomplete, never held. | section 3 | `arena: broke 11 of 51 (... 1800 tokens paid outside the five receivers ...)` for planted-outflow | about 280 s | `evidence/check-outflow-2026-11-11.md` |
| 9b | A guard that pays into NEAR Intents is scored from who Intents credited. Our honest Intents guard holds; our planted copy, which lets the caller pick who is credited, breaks, and the report names who got the credit. | section 3 | `arena: held 53/53 ...` for intents-honest (exit 0), `arena: broke 2 of 53 (... 300 tokens paid outside the five receivers ...)` for intents-planted (exit 1) | about 315 s each | `evidence/check-intents-2026-11-11.md` |
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

You should see `Ran 105 tests` and `OK (skipped=1)`, then `Ran 85 tests` and `OK`, then `pass 37`
and `fail 0`. The hunter tests pass on a fresh copy before anything is built. These counts are for
the current commit: `evidence/clean-copy-2026-11-11.md` records 98 and 77 at the older commit it ran.

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
`arena-report/report.html`, a one-page report that needs no internet. Each took us about 275 s.

A guard that pays in plain NEAR, not a token, needs one line in its config (`"pays_in": "native"`):

```
./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json
./arena check targets/native-control/native_control.wasm --config examples/configs/native-guard.json
```

The first should end `arena: held 48/48 (...; scored from NEAR balances)`, exit code 0. The second
should end `arena: broke 5 of 48 (...)`, exit code 1. Three token-only attacks do not apply to a
guard that holds no tokens, so the native suite has 48. About 230 s each.

A guard that pays by depositing the token into NEAR Intents needs `"pays_in": "intents"` and an
`"$intents"` init argument (full example in `examples/configs/intents-guard.json`):

```
./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json
./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json
```

The first should end `arena: held 53/53 (...; pays via NEAR Intents: local release build, no
withdrawals to other chains)`, exit code 0. The second should end `arena: broke 2 of 53 (...)`,
exit code 1, with `BROKE intents-01-agent-names-outsider-beneficiary: 200 tokens beyond the rules
(paid 200 tokens to the outsider (credited inside NEAR Intents))`. 53 = the 51 attacks plus 2 in
`sequences-intents/`. Arena starts its own copy of NEAR Intents for each attack, on the local
sandbox. About 315 s each.

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
- Exit codes: 0 held, 1 broke, 2 the check could not finish or the command was wrong. "Broke"
  here means over the `--fail-on` line, which by default is any token beyond policy. With
  `--fail-on against-intent`, vault-a's `held 51/51` exits 1, because 2450 tokens went against the
  owner's intent; with `--fail-on never`, every finished check exits 0. A check that could not
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
- **Saved is not validated.** Attack admission: **21 of 53** attacks validated, 4 partially validated, 28 unvalidated
  (`evidence/MANIFEST.md`). Saving admits nothing: of the 25 saved hunter attacks, only those the manifest lists as validated count. Validated means
  `tools/admission/admit.py` ran the attack three times on a known-good guard (held) and three times on
  a copy with the one flaw the attack names (broke by the exact amount, through the named mechanism),
  on pinned wasm bytes, and kept the raw runs in `evidence/admission/`. Re-check any stamp without a
  sandbox: `python3 -I tools/admission/admit.py --recheck sequences-scripted/03-sequential-second-pay.json`.

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
hunt's results are not trusted. One record has no known-answer result:
`2026-11-11-news-d340fd`, a news-only hunt that found nothing to run, so it ran no attack at all.

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

### 4b. Attack admission and the hidden test set: check each claim

Each row: the claim, the command (from the repo root of a fresh `git archive` export, no network,
no private files), the line it prints, the exit code, and the time we measured on one Mac (Apple silicon).
One exception: the `check-public` row needs a full `git clone` (all history). In a `git archive` export or
a `--depth 1` clone it prints `0 of 18 consistent`, because it checks each run's commit against git history.

**Merge note.** This branch must reach main as a fast-forward or a merge commit, never rebased or squashed:
the hidden-set run files name the commits they ran at, and `check-public` fails once those commits are not
in main's history.

| Claim | Command | Line it prints | Exit | Time |
|---|---|---|---|---|
| 21 of 53 attacks validated, 4 partially, 28 unvalidated, and the committed count files are what the code computes | `python3 -I tools/admission/manifest.py --check` | `manifest: up to date` (the counts are in `evidence/MANIFEST.md`, line "Admission: 21 of 53 validated, ...") | 0 | 1 s |
| A stamp belongs to this file (validator passes; evidence folder, attack id, steps and spec hashes match; each stored run recorded these calls) and follows from the stored raw runs (re-judged, no sandbox) | `python3 -I tools/admission/admit.py --recheck sequences-scripted/03-sequential-second-pay.json` | `recheck scripted-03-sequential-second-pay: stored runs give validated (every reference matched in 3 counted runs; matched known-bad: mutant:M4); stamp agrees` | 0 | under 1 s |
| The double-pay race is only partially validated: no block heights recorded (the same holds for the 3 double-pay race attacks given specs on 2026-11-12; 6 other races had their specs withdrawn, see the reasons row) | `python3 -I tools/admission/admit.py --recheck sequences-scripted/02-race-double-pay.json` | `recheck scripted-02-race-double-pay: stored runs give partially-validated (outcomes matched, race ordering not shown: ...steps[].receipts absent...); stamp agrees` | 0 | under 1 s |
| A hunter attack admitted on 2026-11-12 is validated against mutant M3 (a daily cap checked per payment instead of as a running total) as well as M2. Limit: it depends on an invoice that expires 20 s after setup being paid as the 2nd call inside those 20 s (a merge review re-ran it 9 of 9 under load; the margin is set by block time, and a miss fails toward unvalidated, never a false validated) | `python3 -I tools/admission/admit.py --recheck sequences-paper/p261108811-3-stealth-thought-no-disclosure.json` | `recheck p261108811-3-stealth-thought-no-disclosure: stored runs give validated (every reference matched in 3 counted runs; matched known-bad: mutant:M2, mutant:M3); stamp agrees` | 0 | under 1 s |
| Every attack outside the validated count says why, and a person's reason can never sit on an attack the gate has judged | `python3 -I tools/admission/manifest.py --check`, then read the `why` column of `evidence/MANIFEST.md` (reasons from `tools/admission/unvalidated.json`) | `manifest: up to date`; of the 28 unvalidated, 7 rows `race-ordering-unprovable`, 6 `race-not-what-is-tested`, 4 `no-one-flaw-finds-it`, 3 `stopped-by-access-key`, 3 `intent-only`, 1 `tests-another-contract`, 4 `not-an-attack-file` | 0 | 1 s |
| A hand-written, edited or copied "validated" stamp is refused, by the validator and by `--recheck` (stamp and spec copied onto another attack, steps edited with the hash recomputed, evidence folder of another attack, run files of another attack, validated claimed on partial runs); a race counts only if each later check ran in a block strictly before the earlier callback (the callback is the earliest guard receipt after the token transfer, not a later one) (same block = tie, never counted); a leg refused before any payment started is dropped rather than calling the whole race sequential; earlier evidence files are byte-identical; a recorded reason on a specced attack is refused; a hidden attack with the steps of ANY tracked file (hunt proposals under `evidence/hunts/` included) is refused, and a hidden run counts only after its commitment in git parent order | `python3 -I -m unittest discover -s tools/admission/tests` | `Ran 73 tests`, `OK` | 0 | 3 s |
| The gate itself reproduces a validation (local sandbox; needs the build from `./verify.sh fast`) | `python3 -I tools/admission/admit.py sequences-scripted/03-sequential-second-pay.json --runs 3` | `ADMISSION scripted-03-sequential-second-pay: validated (every reference matched in 3 counted runs; matched known-bad: mutant:M4)`; raw runs in `runs/evidence/admission/...` (gitignored) | 0 | 37 s |
| Every public hidden-set run file is consistent with the set it names, and git parent order puts each run after its commitment (its commit is an ancestor of HEAD, its tree was clean, and `COMMITMENT.json` at that commit names its set). Needs a full git clone: a `git archive` export or a `--depth 1` clone prints `0 of 18 consistent` | `python3 -I tools/hidden/hidden.py check-public` | `hidden-set public files: 18 of 18 consistent with the set each names (6 on current set 9748cbedd7a58c4c... (14 attacks); 6 on earlier set 835729d9f34fa123... (9 attacks); 6 on earlier set d314e04fc574c1f7... (14 attacks))` | 0 | under 1 s |
| The hunter drops a proposal with the same steps as a hidden attack and records that it matched. The record does not name the hidden attack, but it does name the hunter's own proposal, which is public, so a match reveals that hidden attack's steps: it must be retired at the next set | `python3 -I -m unittest discover -s tools/hunter/tests -p test_hidden_dupes.py` | `Ran 4 tests`, `OK` | 0 | under 1 s |

How an outsider checks the hidden set without seeing it: `hidden-set/COMMITMENT.json` holds the
set's sha256 (`9748cbed...`), its size (14) and its families. Set 4 (2026-11-12) is the third replacement
made before any of them merged. Sets 1 to 3 each held attacks with the same steps as attack files tracked
in the repository (exactly, or apart from a wait value) or on
a sibling branch that had not merged yet. The old check read only the library and the intents suite, on the
current branch, and only exact copies. Those attacks were retired and replaced. `hidden.py` now compares
every hidden attack with every attack-shaped `.json` tracked on any branch the repository knows, exactly
and up to gas and wait values, and refuses a match; it does not refuse other variants. Earlier
commitments are kept byte for byte in `hidden-set/previous/` (their `disjoint_from_public_library: true`
was wrong; `previous/NOTE.md` says so): set 1 (`835729d9...`) and set 3 (`d314e04f...`), whose run files
still check against them, and set 2 (`e35a4c1f...`), whose run files were removed because they recorded a
commit a rebase took off this branch. The order is checked by git parent order only: `check-public` requires each run's
`arena_commit` to be an ancestor of HEAD with a clean tree and `COMMITMENT.json` at that commit naming the
run's set. That trusts git history, which whoever controls the repository can rewrite before
publishing; it is not a timestamp. If a result is published on testnet, its `suite_version` must equal
the same hash. What you cannot check: the attacks themselves, or that we ran them honestly. Those wait
for the reveal (rule in `COMMITMENT.json`: after 5 guard code hashes or 30 days). Limit of the runs on
every set: the set has no race variant (a race can be admitted only once the harness on main records
per-receipt block heights, and it does not yet), so the double-pay guards (`guard:vulnerable_fixture`,
`leaky-control-v2`) held every attack that applies to them (13 of 14 on sets 3 and 4); only `intents-planted`
broke (100 beyond policy, 1 attack). Every one-flaw mutant a hidden attack is admitted against (M1, M2,
M3, M4, M6, M7, M8) is a copy of vault-a and is not among the six guards run, so these runs show the set
holds on good guards, not that it catches bad ones; the private admission runs show that. On the two
Intents guards, a "held" on a family whose rule the guard does not claim (cancel, expiry, payee list) is
not meaningful: `hidden.py run` does not apply `arena check`'s applicability rules.

What a class does not show, per attack (`tools/admission/limits.json`, printed after "LIMIT:" in the
`why` column of `evidence/MANIFEST.md`): `ai-08` and `p210408638-2-reentrancy` validate only the
already-paid check (M4), not a half-paid state or a callback window; the 8 prompt-injection attacks
that are validated run scripted steps only (the harness makes the pays the injected text asks for; no
agent reads the email), so only the guard's refusal is validated; `ai-04`, `nae93287b-1` and
`p261111305-3` catch only M2 through one invoice over the cap on its own, so their "fill the cap first"
part is not tested; `p261108811-3` depends on the 20 s expiry timing above. Six cap or payee races
(`n00c44f69-1`, `p210408638-1-tod`, `p210408638-2-tod`, `p261111266-2`, `p261112636-1`,
`p261112636-3`) had their specs withdrawn: each checked one outcome, and the flaw it matched (M3 or M1)
breaks it whether or not the calls overlap, so showing the ordering would not validate the race. Their
gate runs are kept in `evidence/admission/<id>/`.

What a recheck checks: the whole file passes the validator (steps, spec, and a stamp that names
this attack's own evidence folder, whose `admission.json` has the same attack id, steps sha256 and
spec sha256), every stored run recorded this attack's calls (method and invoice id at each step),
and the stored runs re-judge to the stamped class. Any failure prints one `REFUSED` line, exit 1.

What a recheck does not prove: the stored runs are bound only by the sha256s in each
`admission.json`, a file in the repo. Someone who writes plausible result files and recomputes the
hashes passes it. What binds the evidence is git history and re-running the gate (row 5).

Limit of "validated": it is only as strong as the attack's written checks. "Through the named
mechanism" means the checks the spec lists passed on every counted run (one check is the minimum),
and the flaw counts as matched because the broken copy's flaw label equals the one the spec names;
nobody checked which line of code fired.

One new one-flaw mutant was built on 2026-11-12 and is NOT a reference: M11 (vault-a with its gas
pre-check removed), pre-registered in `evidence/mutation-plan-2026-11-12.md` before the build. It paid
nothing on the 10 scripted attacks or on the two low-gas AI attacks (`evidence/mutation-M11-2026-11-12/README.md`):
NEAR rejects an under-gassed `pay` as a whole, so the low-gas attacks cannot reach a half-paid state on
vault-a. A reference no attack can break validates nothing, so it is not in `references.json`.

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
- Deposits into NEAR Intents are tested only against a local copy of its release build. Money that
  leaves NEAR is not tested: no withdrawals to other chains, no Chain Signatures requests.

## How the evidence files are named

The tag `2026-11-11` in a file name is a run tag, not always the day the file was made. It was
first used on Nov 10 2026 for the second run of that day, after a fix, so that run would not
overwrite the first run's logs. Files made on Nov 11 carry the same tag. `evidence/README.md`
explains this and says which file answers which question.
