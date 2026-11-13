# tla: the guard's double-pay race, model-checked with near-tla

`Guard.tla` is a hand-written model of `contracts/guard/src/lib.rs` (`pay`, `on_transfer`,
`reconcile`, `on_reconcile`), built on [near-tla](https://github.com/near/near-tla)'s modules
for NEAR receipts, callbacks, forced failures and a standard NEP-141 token. TLC (the TLA+
model checker) tries every order of those receipts within small bounds and reports any order
that breaks the property:

> an invoice is never paid more than its amount, and a failed transfer leaves it payable.

Plan (written before running): `../evidence/tla-plan.md`. Results: `../evidence/tla-2026-11-11/` (the Nov 10 run: `../evidence/tla-2026-11-10.md`).

## Run

```sh
./run.sh                 # all 25 checks; exits 0 only if every one matches the plan
./run.sh vuln_race       # one check by name
python3 -I trace.py build/vuln_race/tlc.out   # a counterexample as one line per step
```

| check | what it does | expect | time on this Mac (10 cores, 4 TLC workers); Nov 11 times from `../evidence/tla-2026-11-11/console.log` |
|---|---|---|---|
| `./run.sh vuln_race` | `vulnerable_fixture`, 1 invoice, 2 pays | violation of NoOverpay | ~1 s |
| `./run.sh vuln_testnet_order` | same, with both pay checks forced before any transfer (the testnet order) | violation of NoOverpay | ~1 s |
| `./run.sh fixed_1inv` | `fixed`, 1 invoice, 3 pays, 1 reconcile, 1 forced failure | pass | ~12 s (Nov 11) |
| `./run.sh fixed_2inv` | `fixed`, 2 invoices, 3 pays, 1 reconcile, 1 forced failure | pass | ~13 min (789 s, Nov 11 run, 12,073,602 states; it took 9 s on Nov 10, on the model before the reconcile fix, 239,994 states) |
| `./run.sh fixed_1inv_2faults` | `fixed`, 1 invoice, 3 pays, 1 reconcile, 2 forced failures | pass | ~36 s (Nov 11) |
| `./run.sh wit_<id>` (13 checks) | anti-vacuity witnesses: situations that must be reachable (one, `wit_reconcile_says_approved_1fault`, expects pass) | reached | 1 to 13 s each (Nov 11) |
| `./run.sh mut_<id>` (5 checks) | mutants: deliberate breaks that must be caught (`mut_no_wait_rule` expects pass since the reconcile fix, see below) | violation | 1 to 72 s each (Nov 11) |
| `./run.sh h1_outside_transfer_reconcile` | **added Nov 10 as must-fail (review H1); PASS since the reconcile fix the same day**: `fixed`, waiting rule ON, 1 invoice, 2 pays, 1 reconcile, 1 forced callback failure, plus one outside account sending 100 tokens to the guard (`Donate = TRUE`) | was a violation of NoOverpay (200 on 100) on the old guard; `pass` now. The old arm is kept as the must-fail `mut_reopen_on_balance` | ~6 s (Nov 11) |
| `./run.sh h1_open_world_2faults` | `fixed`, 1 invoice, 3 pays, 1 reconcile, up to 2 forced failures of both kinds, plus an outside transfer | pass | ~27 min (1,594 s, Nov 11, 27,781,379 states) |
| `./run.sh vuln_race fixed_1inv h1_outside_transfer_reconcile` | quick check: the planted flaw pays twice, the fix holds, the reconcile bug stays fixed | exit 0 | ~15 s wall (Nov 10) |
| `./run.sh` | everything (25 checks) | exit 0 | ~46 min wall. On Nov 11 the 25 checks' TLC times add up to 2,561 s (about 43 min), 2,383 s (about 40 min) of it in `fixed_2inv` and `h1_open_world_2faults` |

TLC output for each check lands in `build/<check>/tlc.out`, and a one-line-per-check table in
`build/summary.tsv`. `build/` is not committed.

## Setup (once)

Everything downloaded lives in `vendor/`, which is gitignored.

```sh
brew install openjdk@21        # run.sh uses /opt/homebrew/opt/openjdk@21/bin/java; override with JAVA=...
mkdir -p vendor && cd vendor
git clone https://github.com/near/near-tla.git
git -C near-tla checkout dd4030103df1dfccccb755eca1e228d52d688572   # v0.1.3 + 1 docs commit
curl -sSfL -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
echo "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88  tla2tools.jar" | shasum -a 256 -c -
```

`run.sh` calls TLC directly. It does not use near-tla's Python runner (`tools/run.py`); the
witnesses and mutants that runner automates are written out in `run.sh` instead.

## Files

| file | what it is |
|---|---|
| `Guard.tla` | the model: guard handlers (with `lib.rs` line citations), transactions, the property, the witnesses |
| `run.sh` | writes one TLC config per check, runs TLC, compares with the plan |
| `trace.py` | prints a TLC counterexample as numbered steps (which receipt ran, invoice status, receiver balance) |
| `.gitignore` | keeps `vendor/` and `build/` out of git |

## What a pass means here

Every order of receipts TLC could build, within the bounds above, kept both invariants. Before
the Nov 10 reconcile fix, that held only under two assumptions: WaitRule (a `reconcile` reads the
balance only after the pay it is resolving has settled; the code enforces 100 blocks, not
settlement) and no token transfers into the guard from anyone else. On the old guard, dropping
either made `fixed` pay 200 on 100. Since the fix, both checks pass on the current guard:
`mut_no_wait_rule` (waiting rule off) and `h1_outside_transfer_reconcile` (an outside account
sends tokens to the guard), and `h1_open_world_2faults` passes with outside transfers and up to 2
forced failures. The old behaviour is kept as must-fail checks (`mut_no_wait_rule_old_reconcile`,
`mut_reopen_on_balance`); see "Nov 10, after the reconcile fix" below and
`../evidence/tla-2026-11-11/console.log`. It is a statement about this model of the Rust code,
under near-tla's rules for nearcore 2.14.0 (protocol 88), and nothing beyond those bounds. The
limits are in the evidence file.

## Corrections after adversarial review (2026-11-10)

Source: `../evidence/proofs-adversarial-review-2026-11-11.md` (H1, H2).

- "What a pass means here" used to say only: "Every order of receipts TLC could build, within
  the bounds above, kept both invariants." That left out the two conditions the pass rests on
  (WaitRule, and no outside token transfers into the guard). Both are now in that sentence.
- The model gained two constants, `Donate` and `GhostRec`, both `FALSE` in every original
  check. With them `FALSE` the model is the same as before: the four pass checks gave the same
  state counts on re-run (9,408 / 239,994 / 24,120 / 9,408).
- Two checks added: `h1_outside_transfer_reconcile` (must-fail) and
  `wit_repaid_after_reconcile` (witness). The suite is now 19 checks, not 17.

## Nov 10, after the reconcile fix

- `reconcile` on an unchanged balance changes nothing (stays `Pending`); new owner-only `resolve_stuck`
  (constant `MaxRes`, default 1), new status `Failed` that `pay` refuses.
- `h1_outside_transfer_reconcile` now passes. New: `h1_open_world_2faults` (pass, 27.8M states),
  `mut_reopen_on_balance` (must fail), `mut_no_wait_rule_old_reconcile` (must fail), 4 witnesses
  (`wit_unchanged_then_resolved`, `wit_resolved_failed`, `wit_resolved_paid`, `wit_refused_failed`).
  `wit_repaid_after_reconcile` was removed: that path no longer exists.
- **Changed expectation:** `mut_no_wait_rule` now passes. NoOverpay no longer depends on the waiting rule,
  because the only harm from an early balance read was the reopen the fix removed;
  `mut_no_wait_rule_old_reconcile` shows it. The sentence above, "drop the first and it does too
  (`mut_no_wait_rule`)", was true for the old guard only.
- The suite is now 25 checks. Results: `evidence/proofs-inductive-2026-11-11.md`, `evidence/tla-2026-11-11/`.
