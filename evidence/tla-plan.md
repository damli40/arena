# TLA+ plan: the guard's double-pay race, checked with near-tla (pre-registered 2026-11-10)

Written before TLC was run on the guard model. The results file (`evidence/tla-2026-11-10.md`)
must be read against this one. If a result differs from what is written here, the results
file says so; this file is not edited after the first run.

## What is being checked, in plain words

**Property:** *an invoice is never paid more than its amount, and a failed transfer leaves
it payable.*

Two halves, two invariants (an invariant is a statement TLC checks in every reachable state):

1. **NoOverpay.** The receiver of an invoice never holds more test tokens than the invoice's
   amount. The model reads the receiver's balance from near-tla's own NEP-141 token ledger
   (`tk[FT].bal`), not from the guard's notes, so the guard cannot "mark it paid" its way out
   of a violation. Each invoice has its own receiver, who starts with 0 tokens.

   ```tla
   NoOverpay == \A i \in Inv : tk[FT].bal[Rcv[i]] <= Amt[i]
   ```

2. **FailedStaysPayable.** Once nothing is in flight, an invoice whose receiver got nothing
   is back to `Approved` (it can be paid again). The one allowed exception: the guard's own
   callback was forced to fail (the stuck-`Pending` case), and the owner has not yet run
   `reconcile`. That exception is tracked by a ghost (a variable the model keeps only for
   checking, not part of the contract) `cbFailed`.

   ```tla
   FailedStaysPayable ==
       Idle => \A i \in Inv :
           tk[FT].bal[Rcv[i]] = 0 =>
               \/ st[i] = "Approved"
               \/ (st[i] = "Pending" /\ i \in cbFailed)
   ```

   `Idle` is near-tla's "no receipt, callback or result is in flight".

Also listed in every pass run: near-tla's library sanity checks `TokSupplyOK`, `TokTypeOK`
(token supply and balances add up), `NearConserved` (native NEAR is conserved) and
`NoOrphans` (every waiting callback can still get its input).

## What is modelled (from `contracts/guard/src/lib.rs`)

- `pay(id)` (lib.rs:169-211): the shared "not Paid" check; in `fixed` the "not Pending"
  check and the `Pending` write; `ft_transfer` with 1 yocto attached, then `on_transfer`.
- `on_transfer(id)` (lib.rs:215-226, :361-419): both modes' callbacks, reading the promise
  result the way `transfer_confirmed` (lib.rs:116-127) does.
- `reconcile(id)` and `on_reconcile` (lib.rs:230-306), fixed mode only: the `pending_count == 1`
  rule, the epoch check, the two stories ("the money left" / "the money did not leave").
- The token is near-tla's standard NEP-141 (`Tokens` module), not Arena's `test_token`.
- Receipts, callbacks, promise results, forced failures and the 1-yocto deposit refund come
  from near-tla's `NearAsync`, unmodified.

**Simplifications, decided now:**
- Invoices are approved at the start, and the ledger (`expected_balance`) starts equal to the
  guard's real token balance, as if the owner had called `sync_ledger` after funding with
  nothing pending. `approve_invoice` and `sync_ledger` are not modelled as steps.
- `transfers_started`, `confirmed_payouts`, logs and `pending_since_block` are not modelled
  (they drive no decision except the waiting rule below).
- **The waiting rule (`RECONCILE_MIN_BLOCKS`, lib.rs:44, :246-253) cannot be modelled as
  time.** In near-tla a receipt has no deadline: it may sit in the pool while blocks pass. So
  the rule is modelled as an **assumption** (`WaitRule`): `reconcile` runs only once the
  `pay` that made the invoice `Pending` has nothing left in flight. A mutant drops it (below).
- Fault mode only (gas is abstract). "The callback runs out of gas" is represented by
  forcing `on_transfer` to fail, which has the same effect: none of its writes happen.

## Bounds

| run | mode | invoices | `pay` transactions | `reconcile` transactions | forced failures |
|---|---|---|---|---|---|
| `vuln_race` | vulnerable_fixture | 1 | 2 | 0 | off |
| `fixed_1inv` | fixed | 1 | 3 | 1 | at most 1, of `ft_transfer` or `on_transfer` |
| `fixed_2inv` | fixed | 2 | 3 (any mix of invoices) | 1 | at most 1, of `ft_transfer` or `on_transfer` |

`fixed_2inv` exists so that `reconcile`'s "ambiguous: 2 invoices are Pending" refusal is
inside the bound. If it does not finish within 20 minutes on this machine, I will lower its
`pay` count to 2 and report that change in the results file as a deviation from this plan.

## Expected results

| run | expected | what that would mean |
|---|---|---|
| `vuln_race` | **violation of NoOverpay** | TLC finds an order of receipts in which the receiver gets 200 on a 100 invoice. I expect the shortest such order to be: both `pay` checks run, then both transfers, before either callback. |
| `fixed_1inv` | **pass** (no violation within the bounds) | every order of up to 3 pays and 1 reconcile, with any single forced failure, keeps both halves of the property. |
| `fixed_2inv` | **pass** | the same with two invoices. |

## Anti-vacuity checks (so a pass cannot come from "nothing interesting is reachable")

near-tla's method: a **witness** is a situation that must be reachable; TLC checks its
negation and must report it violated. A **mutant** is a deliberate break of the model that
some run must catch.

**Note on method.** near-tla automates these with `tools/run.py --anti-vacuity`. The brief for
this work allows running only the TLA+ checker from downloaded repositories, so I will not
run `run.py` or its audit. I will write the same witnesses and mutants by hand and run each
through TLC directly from `tla/run.sh`.

Witnesses, each expected **reached** in `fixed_1inv` (and `fixed_2inv` where noted):

| id | the situation | why it matters |
|---|---|---|
| `paid` | the receiver holds exactly the amount | a paying state exists, so NoOverpay is not trivially true |
| `race_setup` | two `pay` receipts are ready to run at once while the invoice is `Approved` | the fixed run reaches the exact start of the race that breaks the fixture |
| `refused_in_flight` | a `pay` receipt is ready while the invoice is `Pending` | the second `pay` really arrives inside the window |
| `repaid_after_failed_transfer` | one forced failure happened, it was not the callback, and the receiver holds the amount | a failed transfer was released and paid again |
| `stuck_pending` | nothing in flight, invoice `Pending`, callback had failed | the stuck case reconcile exists for |
| `reconcile_says_paid` | an `on_reconcile` is ready to run, and the balance it carries matches "the money left" | reconcile's Paid branch is reached |
| `reconcile_says_approved` | the same, with "the money did not leave" | reconcile's Approved branch is reached |
| `reconcile_ambiguous` (`fixed_2inv` only) | a `reconcile` receipt is ready while 2 invoices are `Pending` | the refusal rule is inside the bound |

Mutants, each expected to be **caught** (a violation) by `fixed_1inv`:

| id | change | expected to break |
|---|---|---|
| `no_pending_write` (the must-fail mutant) | `pay` in fixed mode no longer writes `Pending` | NoOverpay (it becomes the fixture's bug) |
| `no_release_on_failure` | `on_transfer` in fixed mode no longer puts a failed transfer back to `Approved` | FailedStaysPayable |
| `no_wait_rule` | drop the `WaitRule` assumption | NoOverpay: reconcile reads the balance before the transfer lands, says "the money did not leave", and a second `pay` goes out. The code's own comment (lib.rs:40-43) says the waiting rule "is a waiting rule, not a proof", so I expect this. |

## What would be a surprise

- `vuln_race` passes, or fails only on a sanity invariant: the model does not capture the bug
  the testnet run shows, and the model is wrong.
- `vuln_race` fails, but the trace does not have both `pay` checks before the first callback.
- `fixed_1inv` or `fixed_2inv` finds a violation of either half. That would be a real
  finding to replay on the compiled contract (sandbox), not something to explain away.
- Any witness not reached: the corresponding pass would be partly vacuous.
- `no_wait_rule` not caught: my claim that the waiting rule is load-bearing is wrong.
- A sanity invariant (`TokSupplyOK`, `NearConserved`, `NoOrphans`) fails: my use of the
  library is wrong.

## `tla/run.sh`

Exits 0 only if every row above comes out as expected: `vuln_race` violates NoOverpay, both
fixed runs pass, every witness is reached, every mutant is caught.
