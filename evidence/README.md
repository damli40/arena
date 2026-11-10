# Evidence index

Every number in the top-level README points at a file in this folder. This page says which file answers which question, and how to read the file names.

## Read this first: the `2026-11-11` tag is not a date

Files and folders ending in `-2026-11-11` were made on **Nov 10 2026**.

On Nov 10 we fixed a bug in the guard and re-ran everything on the same day. To stop the second run from overwriting the first run's logs, the second run was given the tag `2026-11-11` (`ARENA_DATE` in `verify.sh`; the reason is written down in `fix-plan-2026-11-11.md`, step 3). So:

| Tag in the file name | When it was made | Guard build |
|---|---|---|
| `2026-11-08`, `2026-11-09` | those days | `fcce82bf…` |
| `2026-11-10` | Nov 10, before the fix | `fcce82bf…` |
| `2026-11-11` | Nov 10, after the fix | `0382023b…` (current) |

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
| What did the paper-driven and news-driven attack runs find? | `hunts/` (one `.md` and one `.json` per run) |
| What does a one-command guard check produce? | `check-2026-11-11/` (one report card per guard) |

## Plans come before runs

Files named `*-plan*.md` were written before the run they describe. Each says what result would count as a pass and what would count as a fail, so a result can't be explained away afterwards.

## Raw logs

`*.log`, `*.out`, `*-raw.json` and the dated folders are the unedited output behind the `.md` summaries. Superseded logs keep their names and say `superseded` in the name.
