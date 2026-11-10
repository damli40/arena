# Mutation table for vault-a (run 2026-11-10)

> **Note added 2026-11-11.** This table is the Nov 10 run and its numbers stay as they were. The scorer was fixed after it (per-invoice allowance, caller checked). Re-run on the same mutants: **7 of 10 caught**, M7 200 and M8 100 now caught, M6 now 300. See `mutation-table-2026-11-11.md`.

**Caught 5 of 10.** Five planted flaws made the bench score a payment beyond policy. The other five scored 0 on all 10 attacks: the bench cannot see them. Every one of the 10 results matched the prediction written before any run (`evidence/mutation-plan.md`).

**How it works.** A mutant is a copy of `targets/vault-a` with one planted flaw. The bench runs its existing 10 scripted attacks against each mutant. "Caught" means at least one attack ended with `unauthorised > 0`, which counts tokens paid beyond the policy and is read from final token balances.

## Validity checks (all passed)

| Check | Result | Log |
|---|---|---|
| Unmodified frozen vault-a scores 0 on all 10 | 0 of 10 found something | `mutation-2026-11-10/baseline-vault-a.log` |
| Known-bad reference: leaky-control-v2 | caught by `race-double-pay`, 100 | `mutation-2026-11-10/baseline-leaky-control-v2.log` |
| M0: unmodified copy, built by the mutation script | wasm sha256 `52a40f32…` = the frozen vault-a, byte for byte; 0 of 10 | `mutation-2026-11-10/M0.log` |
| Attacks used = the repo's scripted suite | `gen-scripted` output identical to `sequences-scripted/` | `mutation-2026-11-10/run.out` |
| Frozen targets unchanged before and after | vault-a, leaky-control-v2 ok | `mutation-2026-11-10/run.out` |

Because of M0, each mutant's wasm differs from vault-a only by its one planted change.

## The table

| Mutant | Change (exact diff in `mutants/<id>/MUTATION.md`) | Rule broken | Caught? | Caught by | Tokens paid beyond policy: scored / actual |
|---|---|---|---|---|---|
| M1 | payee check in `pay` removed | removed payee's invoice authorises nothing | **yes** | `06-pay-removed-payee` | 400 / 400 (lin) |
| M2 | daily-cap check removed | ≤ daily_cap per UTC day | **yes** | `09-pay-over-cap` | 100 / 100 over the cap (kai got 600 against a cap of 500) |
| M3 | cap checked per payment, not as a running total | ≤ daily_cap per UTC day | no | none | 0 / 0 (no attack pays more than 150 in total) |
| M4 | already-paid check removed | one transfer per invoice | **yes** | `03-sequential-second-pay` | 100 / 100 (sam 200 on a 100 invoice) |
| M5 | not marked Pending before the transfer; recorded only in the callback | one transfer per invoice | **yes** | `02-race-double-pay` | 100 / 100 (sam 200) |
| M6 | expiry check removed | an expired invoice authorises nothing | **yes** | `05-pay-expired` | **100 / 300** (ada got 300 from an expired invoice) |
| M7 | cancelled-invoice check removed | a cancelled invoice authorises nothing | **no** | none | **0 / 200** (ada got 200 from a cancelled invoice) |
| M8 | agent-only check removed | only the agent may trigger payments | **no** | none | **0 / 100** (the outsider's `pay` succeeded, sam got 100) |
| M9 | failed transfer releases the cap reservation twice | ≤ daily_cap per UTC day | no | none | 0 / 0 (no transfer failed in any attack) |
| M10 | payee generation ignored (remove then re-add revives old invoices) | removed payee's invoice authorises nothing | no | none | 0 / 0 (path unreachable by testers) |

"Actual" is what the guard really paid in breach of the policy, read from the same log. Where actual > scored, the score understated the breach.

Per-attack rows: `mutation-2026-11-10/summary.tsv`. Full logs: `mutation-2026-11-10/<id>.log`. Result JSON per attack: `mutation-2026-11-10/<id>/`. Wasm fingerprints: `mutants/<id>/FROZEN.txt`, written before each run and checked again after it.

## Survivors, and why each got through

Two kinds of survivor need different fixes.

**The flaw fired and money moved, but the scorer did not count it (M7, M8).** These two are the serious ones: the bench watched the breach happen and scored 0.

- **M7, cancelled invoice paid: 200 tokens, scored 0.** The scorer gives each *receiver* an allowance equal to the sum of its valid invoices, whether or not those were paid. ada has a valid 200 invoice (inv-mid) and the cancelled 200 invoice (inv-cancel). When the mutant paid inv-cancel, ada's 200 fit inside inv-mid's allowance. The same blind spot makes M6 score 100 instead of 300. To fix it, score per invoice (an invoice that should not pay but shows `Paid` counts its full amount), or give the cancelled invoice a receiver with no valid invoice.
- **M8, outsider triggered a payment: 100 tokens, scored 0.** The rule "only the agent may trigger payments" is about *who called*, but the score only reads *who received*. The outsider paid a valid invoice to its rightful receiver, so the balances look honest. To fix it, count any payment started by a non-agent caller as beyond policy, from the transaction's signer (the harness already logs it), or have an outsider pay an invoice the agent has not paid yet and check for a `payment_started` event.

**The flaw never fired, because no attack goes down that path (M3, M9, M10).**

- **M3, cap per payment instead of a running total.** No scripted attack pays several valid invoices that sum above 500; the most is `race-two-invoices` at 150. An attack exists: pay inv-pay, inv-mid and inv-expire (100+200+300 = 600) before inv-expire runs out at ~20 s. Add that sequence.
- **M9, cap released twice on a failed transfer.** No attack makes `ft_transfer` fail. All receivers are registered with the token, and `08-gas-starve` is refused before any state changes (0 `payment_failed` events in M9.log). Catching this needs a setup with an unregistered receiver, then failing pays followed by honest pays that go over the cap.
- **M10, a removed payee is re-added and its old invoice revived.** Re-adding needs the owner key. Testers act only as the agent or the outsider, and setup never re-adds lin. No tester-only attack can reach this; it needs an owner step in setup (remove, then re-add a payee).

## What this does and does not show

- It shows the bench catches 5 kinds of planted flaw in vault-a, and names 5 it misses, including 2 where money moved in breach of policy and the score said 0.
- It does not measure attacks outside the 10 scripted ones (the AI tester's sequences were not run here).
- Each mutant ran once. The two race results (M5 caught; baseline 0) come from one run each, not repeated trials.
- Nobody else has reviewed this table yet; the numbers were copied from the logs named above. The mutants were written from reading the code, so they test only the flaws the author thought of.

## Reproduce

```
tools/mutation/run.sh            # pins harness from git HEAD, baseline + M0..M10; ~40 min (39m45s measured)
tools/mutation/run.sh M7 M8      # baseline + only these mutants
SKIP_BASELINE=1 tools/mutation/run.sh M4   # one mutant, appends to that day's summary.tsv
```

The script builds the committed harness (`git archive HEAD harness`) into `mutants/target/harness-pinned/` and copies the binary to `mutants/target/bin/arena-harness`, so edits to `harness/` in the working tree do not affect it. It uses a private copy of `test_token.wasm`. It builds each mutant with vault-a's own flags: toolchain 1.86.0 and `.cargo/config.toml` (`--cfg near`). Outputs go to `evidence/mutation-<date>/`. The mutations themselves are exact string replacements in `tools/mutation/mutate.py`; each must match exactly once, or the script stops.
