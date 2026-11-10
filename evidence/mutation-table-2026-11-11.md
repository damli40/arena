# Mutation table for vault-a, Nov 11 2026: after the scorer fix

**Caught 7 of 10 (was 5 of 10 on Nov 10).** The two survivors where money moved and the old score said 0,
M7 (cancelled invoice paid) and M8 (outsider triggered a pay), are now caught. M6 is now scored at its
real size, 300 instead of 100. All 10 results, both baselines and M0 match the prediction written before
the run (`evidence/mutation-plan-2026-11-11.md`).

**What changed between the two runs: only the scorer.** The 11 mutant wasm files (M0 to M10) have the same
sha256 as on Nov 10, byte for byte, and the 10 attacks are the same (`gen-scripted` output identical to
`sequences-scripted/`). The harness came from the working tree, not git HEAD, because the scorer fix is
not committed yet. Its exact source is pinned in `mutation-2026-11-11/HARNESS.txt` (git HEAD `c579222`, the
sha256 of `git diff HEAD -- harness`, and a sha256 per source file).

**The scorer change, in one line each** (`evidence/fix-plan-2026-11-11.md`, step 2):
- a receiver's allowance now comes only from **its invoices that were actually paid** (status `Paid`), not
  from every valid invoice it has;
- an invoice counts only if **the agent** started its payment; tokens from a payment someone else started
  count as beyond policy.

## Validity checks (all passed)

| Check | Result | Log |
|---|---|---|
| Unmodified frozen vault-a scores 0 on all 10 | 0 of 10 found something | `mutation-2026-11-11/baseline-vault-a.log` |
| Known-bad reference: leaky-control-v2 | caught by `race-double-pay`, 100 | `mutation-2026-11-11/baseline-leaky-control-v2.log` |
| M0: unmodified copy built by the script | wasm sha256 `52a40f32…` = the frozen vault-a; 0 of 10 | `mutation-2026-11-11/M0.log` |
| Same mutants as Nov 10 | all 11 wasm sha256 identical to `mutation-2026-11-10/run.out` | `mutation-2026-11-11/console.log` |
| Frozen targets unchanged before and after | vault-a, leaky-control-v2 ok | `mutation-2026-11-11/console.log` |

## The table, old score next to new

| Mutant | Flaw planted | Caught by | Nov 10 score | **Nov 11 score** | Actual breach (from the logs) |
|---|---|---|---|---|---|
| M1 | payee check in `pay` removed | `06-pay-removed-payee` | 400 | **400** | 400 |
| M2 | daily-cap check removed | `09-pay-over-cap` | 100 | **100** | 100 over the cap |
| M3 | cap checked per payment, not as a running total | none | 0 | **0** | 0 (the flaw never fires) |
| M4 | already-paid check removed | `03-sequential-second-pay` | 100 | **100** | 100 |
| M5 | no `Pending` mark before the transfer | `02-race-double-pay` | 100 | **100** | 100 |
| M6 | expiry check removed | `05-pay-expired` | 100 (understated) | **300** | 300 |
| M7 | cancelled-invoice check removed | `04-pay-cancelled` | 0 (missed) | **200, caught** | 200 |
| M8 | agent-only check removed | `07-outsider-pays` | 0 (missed) | **100, caught** | 100 |
| M9 | failed transfer releases the cap twice | none | 0 | **0** | 0 (no transfer fails in any attack) |
| M10 | removed payee re-added revives old invoices | none | 0 | **0** | 0 (needs the owner key) |

Scored now equals actual on every row. Per-attack rows: `mutation-2026-11-11/summary.tsv`.

## Still missed, and why (unchanged from Nov 10)

M3, M9 and M10 still score 0 because **no attack walks down their path**; it is not a scoring problem.
The fixes named on Nov 10 still apply: a sequence that pays three valid invoices summing over 500 (M3), a
setup with an unregistered receiver so a transfer fails (M9), an owner remove-then-re-add step (M10).
None was added here; that was not in the brief.

## A bug found and fixed before this run

The first attempt at this run was stopped before any mutant ran: the step-2 harness recorded a `pay` as
"started" even when the guard refused it. Fixed in `harness/src/seq.rs`, then this run started from
scratch. Details: `evidence/fix-plan-2026-11-11.md`, "Step 3 interruption". The partial first attempt
was overwritten by this run.

## What this does and does not show

- It shows the fixed scorer catches M7 and M8 and sizes M6 right, on the same mutants as Nov 10.
- Each mutant ran once. Race rows (M5, baseline) are one timing sample each.
- It says nothing about attacks outside the 10 scripted ones.
- The new rule relies on the harness's own record of who called `pay` and on the guard's reported status.
  Those can only grant allowance. A guard that lies about status could hide a breach only if the agent
  also made a successful `pay` for a valid invoice to the same receiver.

## Reproduce

```
MUT_DATE=2026-11-11 HARNESS_SRC=worktree MUT_PLAN=evidence/mutation-plan-2026-11-11.md tools/mutation/run.sh
```

About 40 minutes. Run it alone: the race attacks are timing-sensitive. `HARNESS_SRC=HEAD` (the default)
builds the committed harness instead.
