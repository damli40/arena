# Proofs after the reconcile fix, Nov 11 2026: the full world, and "any number of calls"

Plan: `evidence/fix-plan-2026-11-11.md`, steps 3e, 3f, 3g. Machine clock read Nov 10 (WAT).
Guard source: `contracts/guard/src/lib.rs` as built into guard.wasm sha256 `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e` (`docs/guard-tests.md`).
Logs: `evidence/proofs-2026-11-11/` (console: `console.log`). TLA logs: `tla/build/`, summary below.

## The question, said plainly

The review (`proofs-adversarial-review-2026-11-11.md`, H1) found a way the "fixed" guard paid one invoice
twice: a transfer lands, its callback dies, someone sends the guard the same amount, `reconcile` reads
"balance unchanged" and reopens the invoice, the agent pays again. The guard now refuses to reopen on that
reading, and the owner closes a stuck invoice with `resolve_stuck`.

So the question is: **with the new code, can tokens sent for one invoice ever exceed its amount?** Three
tools answer it, each with a different limit:

| Tool | What it checks | Limit |
|---|---|---|
| Kani, bounded (the "full world") | every order of up to 2 pays, 1 dying callback, 1 reconcile, 1 `resolve_stuck`, 1 outside transfer, on the model | 2 pays |
| Real contract, exhaustive | the same world, run against the **real** guard source on near-sdk's mocked chain, model in lockstep | 2 pays |
| Kani, inductive step | **any number of calls**, on the model | the model (2 or 3 invoices) |
| TLA+ (TLC) | the same question in a separate spec built on near-tla's receipt model | 1 invoice, 3 pays, up to 2 forced failures |

## Result: `proofs/run.sh`, 30 passed, 0 failed (1,504 s)

### 1. Any number of calls (the new inductive proof, `proofs/guard-model/src/inductive.rs`)

**How it works, in plain words.** A bounded check tries every order of a few calls. This proof shows two
facts instead: (1) the starting state obeys a rule (the invariant), and (2) from **any** state that obeys
it, **any one** action leads to a state that still obeys it. Then every state reachable after any number
of calls obeys it, by induction. The rule includes "sent ≤ amount", so that holds after 1 call or a million.

**The rule (invariant), per invoice:**
- (a) tokens sent ≤ its amount;
- (b) at most one transfer or callback in flight for it;
- (c) an in-flight one carries exactly the invoice amount, and its stage matches what was sent (waiting
  transfer: nothing sent yet; callback after a success: the full amount sent; after a failure: nothing);
- (d) with nothing in flight, sent is either 0 or the full amount;
- (e) if the invoice is `Approved` (payable), nothing is in flight and nothing was ever sent for it.

**The actions (11), by anyone, at any time:** pay; a waiting transfer succeeding or failing; a callback
running, or dying (out of gas: dropped); `approve_invoice` on an existing id; `reconcile`; `on_reconcile`
with **any** balance and any epoch (this covers every possible balance reading, including after outside
transfers); `resolve_stuck` with either answer; `sync_ledger` and `on_sync_ledger` with any balance; an
outside transfer of any amount into the guard. "Any state" means every field is arbitrary (amounts, counters,
ledger, block heights, epochs). Over-covering like this is safe: it can only add ways to fail.

| Harness | Expected | Got | Time |
|---|---|---|---|
| `inductive_init_k2`, `inductive_init_k3` (start obeys the rule) | SUCCESSFUL | SUCCESSFUL | 0.7 s, 1.1 s |
| `inductive_step_fixed_k2` (any state, any action, 2 invoices) | SUCCESSFUL, all 11 actions reachable | **SUCCESSFUL**, 11 of 11 covers SATISFIED | 25.7 s |
| `inductive_step_fixed_k3` (3 invoices) | same | **SUCCESSFUL**, 11 of 11 | 62.6 s |
| `invariant_implies_no_overpay_k2` (rule ⇒ sent ≤ amount; rule not vacuous) | SUCCESSFUL, 5 covers | SUCCESSFUL; satisfiable incl. the H1 state (stuck Pending after the tokens moved) | 3.3 s |
| `inductive_step_old_reconcile_k2` (**must fail**: old arm put back) | FAILED on the step | FAILED on the step | 18.9 s |
| `inductive_step_vulnerable_k2` (**must fail**: planted-flaw mode) | FAILED | FAILED (pay with a payment in flight; step) | 13.1 s |

The two must-fail rows matter: they show the proof can fail, and fails exactly where the old bug was.

### 2. The full world, bounded (model and real source)

| Check | Expected | Got |
|---|---|---|
| Kani `fixed_full_n2` | SUCCESSFUL; dead callback, H1 reading, reconcile→Paid, resolve→Failed, resolve→Paid, outside transfer then reconcile: all reachable; double pay unreachable | **as expected** (121 s) |
| Kani `old_reconcile_full_n2` (must fail) | P1 fails; H1 reading and double pay reached | as expected |
| Kani `vulnerable_fixture_full_n2` (must fail) | P1 fails | as expected |
| Real source, fixed, 2 pays, full world | P1 holds, model agrees | **21,345 states, 718 end states, P1 HOLDS, P2 HOLDS, 0 model mismatches**, max sent [100, 50] (299 s) |
| Real source, old arm put back (`guard-real-mutant-reopen`), full world | P1 fails | P1 FAILS, max sent [200, 100], model agrees |
| Real source, vulnerable fixture, full world | P1 fails | P1 FAILS, model agrees |

"P1" = tokens sent for an invoice never exceed its amount. "P2" = no funds stuck once nothing is in flight.
"Model agrees" means the hand-written model and the real contract were in the same state at every one of
those states. That lockstep is what ties the inductive proof (about the model) to the real code.

### 3. Everything from before, re-run on the new source (unchanged results)

Base world (callbacks complete), real source: fixed N=3 1,044 states and N=4 4,555 states, P1 holds;
vulnerable N=3/N=4 and the no-Pending mutant fail; lockstep self-test disagrees as it must. Kani
`fixed_n3`, `fixed_n4` SUCCESSFUL; `vulnerable_fixture_n3/n4`, the mutant and the too-small bound fail as
planned; both playbacks reproduce the failure. z3 (Proof 2, owner policy): every query as planned. Same
numbers as `proofs-2026-11-10.md`, so the fix did not change the race behaviour.

## TLA+ (`tla/run.sh`)

**All 25 checks as planned** (one clean full run; console and summary in `evidence/tla-2026-11-11/`).
A separate spec, built on near-tla's model of NEAR receipts, so it does not share the Rust model's mistakes.

| Check | Before the fix (Nov 10/11) | After | States explored |
|---|---|---|---|
| `h1_outside_transfer_reconcile` (the H1 bug: outside top-up, then reconcile) | violation, 200 on 100 | **pass** | 102,045 |
| `h1_open_world_2faults` (new: 3 pays, both kinds of failure, up to 2, outside transfer) | not run | **pass** | 27,781,379 |
| `mut_reopen_on_balance` (new, must fail: the old arm put back) | n/a | violation, as it must | 98,724 |
| `mut_no_wait_rule` (waiting rule switched off) | violation | **pass (changed, see below)** | 1,314,926 |
| `mut_no_wait_rule_old_reconcile` (new, must fail: no waiting rule + old arm) | n/a | violation, as it must | 162,122 |
| 4 new witnesses (unchanged balance then resolved; resolved Failed; resolved Paid; pay refused on Failed) | n/a | all reached | — |
| everything else (race, fixed 1 and 2 invoices, other witnesses and mutants) | as planned | as planned | e.g. `fixed_2inv` 12,073,602 |

**The one expectation I changed after a run, and why.** `mut_no_wait_rule` was a must-fail check, and on
the new code it passed. The waiting rule stops `reconcile` reading the balance before the transfer has
run. Before the fix, that early reading ("unchanged") reopened the invoice, which is how the no-wait guard
paid twice. The fixed code changes nothing on that reading, so an early read is now harmless for
overpaying. To make sure that is the reason (and not a spec that can no longer fail), the new check
`mut_no_wait_rule_old_reconcile` puts the old arm back with the waiting rule off: it fails. So the waiting
rule mattered only through the arm the fix removed. It still matters for `resolve_stuck` (the owner should
not answer before the transfer's result is known), and that is not a property checked here.

## What this does NOT show (read before citing)

- **It is about the model and the source, not the deployed wasm.** The inductive proof is on the model.
  The model is tied to the real source only by the bounded lockstep runs (≤ 4 pays base, 2 pays full).
- **Per invoice id.** If the owner answers `resolve_stuck(sent=false)` for a transfer that did happen, then
  approves a **new** invoice for the same bill, that bill is paid twice. That is the owner's recorded
  decision, the stated trade-off of the fix (`docs/guard-tests.md`); the proof does not cover it.
- **Not modelled:** cancel / payee removal (they only refuse more), the daily cap and expiry, new invoice
  ids during the run (the K invoices exist from the start), NEAR's key permissions, gas beyond "a callback
  dies".
- **Time in the real-source full world** moves only when the owner waits (that is how the 100-block rule
  is reached there). Other timing is covered by the order exploration, not by a clock.
- **Two runner mistakes on the way, both mine, both fixed before the passing run:** the first
  `proofs/run.sh` attempt reported 7 FAIL because it called the inductive harnesses by the wrong path
  (`proofs::` instead of `inductive::harnesses::`); Kani said "Failed to match harness", not a proof
  failure. Fixed in `proofs/run.sh`; the passing run is the one reported here.
- Nothing ran on testnet.
