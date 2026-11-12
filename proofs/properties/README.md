# Property library: five money rules you can check on your own guard

A guard is the contract that limits what an AI agent can pay. This folder holds five rules a
guard should keep, written once, as short functions you can reuse. You point them at your guard
through a small harness, and the explorer tries every order of steps up to a bound you choose.

| Property | In plain words | Lines in `src/spec.rs` |
|---|---|---|
| `no-double-pay` | one payment id (or invoice) is delivered at most once, and never more than its invoice says | 15 |
| `payee-list-only` | the agent's payments reach only payees on the list (or the invoice's own receiver), and only the agent can start them | 15 |
| `never-beyond-cap` | no single payment, approved or not, is above the per-payment cap | 8 |
| `approval-threshold` | above the threshold, nothing is paid unless the owner approved it | 8 |
| `window-budget` | in each window (e.g. a UTC day), the agent's unapproved payments add up to at most the budget | 12 |

All five plus the `Payment` and `Policy` types: 116 lines (83 without blanks and comments). The
explorer and report printer (`src/lib.rs`): 112 lines including its unit test. No dependencies.

## What a property reads

Only a **ledger**: the payments your guard actually sent, which your harness reads from the
receipts your contract created, never from the guard's own counters. And the **policy** you
declare: the rules your guard claims. A rule you leave out (`None`) is not checked.

## Apply a property to your guard (about 100 lines of harness)

1. Copy `examples/template.rs`. It is a working harness for a toy guard; replace the toy with
   calls into your contract.
2. **World**: your guard plus the chain around it. `steps()` lists what may happen next (a pay
   request, a transfer succeeding or failing, a callback, the owner approving, a midnight).
   `apply()` runs one step. For a NEAR contract, run it on near-sdk's mocked chain
   (`unit-testing` feature) and read `created_receipts()`; `proofs/guard-real/src/lib.rs` shows
   how Arena does it for its own guard.
3. **Ledger**: turn the transfers that succeeded into `Payment` records.
4. **Policy**: fill in the rules your guard claims.
5. Run `explore(start, &policy, &["window-budget", ...])` and `print(...)`.
6. **Plant a flaw** for every property you check (one changed line in a copy of your guard)
   and confirm the property breaks. A property that no planted flaw can break is not tested.

Check the library itself: `proofs/properties/run.sh` (7 checks, under a minute, no network).

## Where it is applied

| Guard | Harness | Properties checked | Result |
|---|---|---|---|
| Toy guard (the template) | `examples/template.rs` (123 lines) | all 5 | hold with no flaw; each of 5 planted flaws breaks exactly its property |
| Arena's own guard, real source | `proofs/guard-real/src/bin/properties.rs` (97 lines, reusing the existing 647-line world) | `no-double-pay` (it has no list, cap, threshold or budget) | see `evidence/proofs-all-2026-11-11.md` |
| Four other teams' guards | private harnesses, kept outside this repo | the ones each guard claims | counts only, `evidence/proofs-all-2026-11-11.md` |

## What "holds" means here

Every reachable order of the steps your world allows, up to your bound, was run, and the
property held in every state reached. It is a bounded check, not a proof for every possible
run, and it is only as good as the world: a step your world never offers is never tested.
