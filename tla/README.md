# tla: the guard's double-pay race, model-checked with near-tla

`Guard.tla` is a hand-written model of `contracts/guard/src/lib.rs` (`pay`, `on_transfer`,
`reconcile`, `on_reconcile`), built on [near-tla](https://github.com/near/near-tla)'s modules
for NEAR receipts, callbacks, forced failures and a standard NEP-141 token. TLC (the TLA+
model checker) tries every order of those receipts within small bounds and reports any order
that breaks the property:

> an invoice is never paid more than its amount, and a failed transfer leaves it payable.

Plan (written before running): `../evidence/tla-plan.md`. Results: `../evidence/tla-2026-11-10.md`.

## Run

```sh
./run.sh                 # all 17 checks; exits 0 only if every one matches the plan
./run.sh vuln_race       # one check by name
python3 -I trace.py build/vuln_race/tlc.out   # a counterexample as one line per step
```

| check | what it does | expect | time on this Mac (10 cores, 4 TLC workers) |
|---|---|---|---|
| `./run.sh vuln_race` | `vulnerable_fixture`, 1 invoice, 2 pays | violation of NoOverpay | ~1 s |
| `./run.sh vuln_testnet_order` | same, with both pay checks forced before any transfer (the testnet order) | violation of NoOverpay | ~1 s |
| `./run.sh fixed_1inv` | `fixed`, 1 invoice, 3 pays, 1 reconcile, 1 forced failure | pass | ~2 s |
| `./run.sh fixed_2inv` | `fixed`, 2 invoices, 3 pays, 1 reconcile, 1 forced failure | pass | ~10 s |
| `./run.sh fixed_1inv_2faults` | `fixed`, 1 invoice, 3 pays, 1 reconcile, 2 forced failures | pass | ~2 s |
| `./run.sh wit_<id>` (8 checks) | anti-vacuity witnesses: situations that must be reachable | reached | ~1 s each |
| `./run.sh mut_<id>` (3 checks) | mutants: deliberate breaks that must be caught | violation | ~1-2 s each |
| `./run.sh` | everything | exit 0 | ~30 s wall |

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

Every order of receipts TLC could build, within the bounds above, kept both invariants. It is
a statement about this model of the Rust code, under near-tla's rules for nearcore 2.14.0
(protocol 88), and nothing beyond those bounds. The limits are in the evidence file.
