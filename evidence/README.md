# Evidence index

Every number in the top-level README points at a file in this folder. This page says which file answers which question, and how to read the file names.

## Read this first: the `2026-11-11` tag is not a date

Files and folders ending in `-2026-11-11` were made on **Nov 10 or Nov 11 2026**. The tag marks the run, not the day.

On Nov 10 we fixed a bug in the guard and re-ran everything on the same day. To stop the second run from overwriting the first run's logs, the second run was given the tag `2026-11-11` (`ARENA_DATE` in `verify.sh`; the reason is written down in `fix-plan-2026-11-11.md`, step 3). Work done on Nov 11 kept the same tag. So:

| Tag in the file name | When it was made | Guard build |
|---|---|---|
| `2026-11-08`, `2026-11-09` | those days | `fcce82bf…` |
| `2026-11-10` | Nov 10, before the fix | `fcce82bf…` |
| `2026-11-11` | Nov 10 after the fix, or Nov 11 | `0382023b…` (current) |

Made on Nov 11: `check-native-2026-11-11.md`, `check-outflow-2026-11-11.md`, `onchain-2026-11-11.md`, `results-testnet-2026-11-11.md`, `nearai-2026-11-11.md`, `injection-2026-11-11-nearai-model.md`, and the two hunt records whose names start `hunts/2026-11-11-`. Every other file with this tag was made on Nov 10.

The names are kept because the receipts saved on NEAR testnet point at these paths and carry a hash of each file. Renaming a file, or editing its text, would break that link. The same tag appears in some code comments for the same reason.

## Which file answers which question

| Question | File |
|---|---|
| Did the planted-flaw guard pay twice on NEAR testnet, and did the fix hold? | `testnet-2026-11-11.md` (current build), `testnet-2026-11-09.md` (first run) |
| What do the proofs cover, and where do they stop? | `proofs-2026-11-10.md`, `proofs-inductive-2026-11-11.md`, `tla-2026-11-10.md`, `tla-2026-11-11/` |
| What bug did the review of the proofs find, and how was it fixed? | `proofs-adversarial-review-2026-11-11.md`, `fix-plan-2026-11-11.md` |
| How many planted mistakes did the attacks catch? | `mutation-table-2026-11-11.md` (7 of 10), `mutation-table.md` (the earlier 5 of 10, before the scorer change) |
| How much went out against the owner's intent? | `injection-intent-by-recipient.md`, `injection-narrow-policy.md`, `injection-2026-11-09-*.md` |
| How did three other teams' guards do? | `coverage-table.md` (Guards A, B, C) |
| What is saved on NEAR testnet? | `receipts-testnet-2026-11-11.md` (current build), `receipts-testnet-2026-11-10.md` (first set) |
| Did the full check suite pass on the current build? | `verify-2026-11-11.md`, `verify-summary.log` |
| Do the commands in `EVALUATE.md` work from a fresh copy with no build folders? | `clean-copy-2026-11-11.md` (12 commands, all matched, at commit `adaa69d`; test counts have grown since, see `EVALUATE.md`) |
| Did every check still pass, from a fresh copy, after adding NEAR Intents testing? | `clean-copy-intents-2026-11-11.md` (10 checks, all matched; then merged) |
| What did two independent reviewers find, and do the fixes hold on a fresh copy? | `judge-fixes-2026-11-11.md` (11 commands matched; no committed file changed by a run) |
| What did the paper-driven and news-driven attack runs find? | `hunts/` (one `.md` and one `.json` per run) |
| Which model writes the hunter's attacks, where does it run, and what does NEAR AI's attestation show? | `nearai-2026-11-11.md`; re-check a saved report offline with `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json` |
| What does a one-command guard check produce? | `check-2026-11-11.md`, `check-2026-11-11/` (one report card per guard). These say `52/52`: that count included the honest payment made before the attacks. There are 51 attacks; `check-fixes-2-2026-11-11.md` records the correction |
| What did the reviews of the one-command check find, and what was fixed? | `check-fixes-2026-11-11.md`, `check-fixes-2-2026-11-11.md` |
| Does the check score a guard that pays in plain NEAR and not a token? | `check-native-2026-11-11.md` |
| What happens when a guard pays an account the check was not watching? | `check-outflow-2026-11-11.md` |
| Does the check score a guard that pays into NEAR Intents, and does it name who Intents credited? | `check-intents-2026-11-11.md`, `check-intents-2026-11-11/` (made on Nov 11) |
| Does the check score a guard that asks Chain Signatures to sign, and does it count requests the owner did not allow? | `check-chainsig-2026-11-11.md`, `check-chainsig-2026-11-11/` (made on Nov 11), `clean-copy-chainsig-2026-11-12.md` (fresh copy), `clean-copy-chainsig-2026-11-12b.md`, `clean-copy-chainsig-2026-11-12c.md` (after the two reviews) |
| How does a guard owner opt in on chain, and how does a contract ask for a result before it pays? | `onchain-2026-11-11.md` (what is live on testnet), `../docs/ON-CHAIN.md` (how to use it) |
| Which results can a contract read on testnet today? | `results-testnet-2026-11-11.md` (Arena's own guards only; Guards A, B and C get none) |
| Does the model on NEAR AI resist the same injections as the first model? | `injection-2026-11-11-nearai-model.md` |
| How long from a paper or a hack report to a tested attack? | `response-time-2026-11-11.md` (a replay of the planned schedule, not a measurement of it) |

## Plans come before runs

Files named `*-plan*.md` were written before the run they describe. Each says what result would count as a pass and what would count as a fail, so a result can't be explained away afterwards.

## Raw logs

`*.log`, `*.out`, `*-raw.json` and the dated folders are the unedited output behind the `.md` summaries. Superseded logs keep their names and say `superseded` in the name.
