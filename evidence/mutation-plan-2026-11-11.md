# Mutation plan, re-run with the per-invoice scorer (pre-registered 2026-11-10 10:50 WAT, before the run)

**What changed since `evidence/mutation-plan.md`.** Only the scorer (`harness/src/scorer.rs`, see
`evidence/fix-plan-2026-11-11.md`, step 2). The mutants, the 10 scripted attacks and vault-a are the
same. The old plan and table stay as they are; this file and `evidence/mutation-table-2026-11-11.md`
are the re-run.

**The scorer rule now.** A receiver is allowed only the invoices that were actually paid, that the policy
authorises (valid; expiring ones paid before expiry), that **the agent** started, and that show `Paid`.
Tokens beyond policy = what the receiver got − that allowance. The daily-cap term is unchanged.

**Harness used.** The working tree, not the last commit: `HARNESS_SRC=worktree tools/mutation/run.sh`,
because the scorer fix is not committed yet (Dami commits after checking). `HARNESS.txt` in the output
folder records git HEAD, the sha256 of `git diff HEAD -- harness`, and the sha256 of every pinned source
file. Output folder: `evidence/mutation-2026-11-11/` (`MUT_DATE=2026-11-11`).

| id | planted flaw (unchanged) | old result | expected now | why |
|---|---|---|---|---|
| baseline vault-a | none | 0 of 10 | **0 of 10** | vault-a refuses every bad call; honest pays are agent-started and `Paid` |
| baseline leaky-control-v2 | records after the callback | `race-double-pay` 100 | **`race-double-pay` 100, nothing else** | it keeps the agent-only check, so `07-outsider-pays` is refused |
| M0 | none (rebuild check) | 0 of 10, wasm `52a40f32…` | **0 of 10, same wasm** | |
| M1 | no payee check | caught, 400 | **caught, 400** | inv-removed authorises nothing (same as before) |
| M2 | no daily-cap check | caught, 100 | **caught, 100** | inv-big is valid and agent-paid, so only the cap term counts: 600 − 500 |
| M3 | cap per payment | survived, 0 | **survived, 0** | no attack sums valid invoices above 500 |
| M4 | no already-paid check | caught, 100 | **caught, 100** | sam 200 on inv-pay, credited 100 |
| M5 | no Pending before transfer | caught, 100 | **caught, 100** | race: sam 200, credited 100 |
| M6 | no expiry check | caught, **100** | **caught, 300** | inv-expire paid after expiry is credited 0; inv-mid was not paid, so it no longer absorbs 200 |
| M7 | cancelled invoices payable | **survived, 0** | **caught, 200** by `04-pay-cancelled` | inv-cancel is credited 0; inv-mid was not paid |
| M8 | no agent-only check | **survived, 0** | **caught, 100** by `07-outsider-pays` | the outsider started the pay, so inv-pay is credited 0; the log prints `NON-AGENT PAY` |
| M9 | cap released twice on failure | survived, 0 | **survived, 0** | no attack makes a transfer fail |
| M10 | removed payee revived | survived, 0 | **survived, 0** | needs the owner key |

**Predicted:** caught **7 of 10** (M1, M2, M4, M5, M6, M7, M8); survive 3 (M3, M9, M10), all three
because no attack reaches the flaw, not because the scorer missed money that moved.

**Validity gates (unchanged):** baseline vault-a 0 of 10; M0 wasm = `52a40f32…`; leaky-control-v2 caught
by `race-double-pay`; frozen targets unchanged before and after; `gen-scripted` output = `sequences-scripted/`.

**Not edited after the run.** Any difference from this table is reported in the table file.
