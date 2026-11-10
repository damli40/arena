# proofs: the PROVE step

Arena tests guards by attacking them. This folder checks two properties for **every** case inside a stated bound, and hands back a concrete failing case when there is one. Plan, written before any run: `evidence/proofs-plan.md`. Results: `evidence/proofs-2026-11-10.md`; after the Nov 11 reconcile fix, `evidence/proofs-inductive-2026-11-11.md`.

| Proof | Question | Tool | One command | Runtime (M-series Mac, after first build) |
|---|---|---|---|---|
| 1 | Can the `pay`/callback race pay one invoice twice (callbacks complete, no `reconcile`), in any order NEAR runs those receipts, up to 4 `pay` calls? | Kani (on a model) + an exhaustive run of the real contract | `proofs/run.sh proof1` | about 255 s; the full `run.sh` took 257 s on Nov 10 (6 Kani harnesses 121 s of solver time, 2 playbacks, 6 exhaustive runs 58 s); the first build of `guard-real` adds a few minutes |
| 1, full world (added Nov 11) | Same question, with one callback that dies (out of gas), `reconcile` reading the guard's real balance, the owner's `resolve_stuck`, and one outside transfer into the guard, up to 2 `pay` calls | Kani (on the model) + an exhaustive run of the real contract | part of `proofs/run.sh proof1` | Kani about 1 min per harness; real contract about 2.5 min |
| 1, any number of calls (added Nov 11) | From ANY state meeting an invariant, does ANY one action keep it? (Then it holds after any number of calls.) | Kani inductive step, on the model only, 2 and 3 invoices | part of `proofs/run.sh proof1` | under 1 min in total |
| 2 | Can the owner's policy pay more than the owner intended? | z3 | `proofs/run.sh proof2` | about 1-2 s |
| 2, cross-check | Does the chain pay what z3 predicted? | the Arena harness on a local sandbox | `proofs/crosscheck.sh` | about 17 s |

**After the fix (2026-11-11).** `reconcile` no longer reopens an invoice when the balance looks unchanged; the owner closes a stuck one with `resolve_stuck`. The full-world rows above check that path, and the old `reconcile` (put back in `guard-real-mutant-reopen/` and in the model) must fail. Scope, said plainly: these are statements about the model (any number of calls) and about the real source within a bound (2 pays in the full world), not about the deployed wasm on a live chain.

**Correction (2026-11-11).** Proof 1's question used to read "Can one invoice be paid twice, in any order NEAR runs the steps?". That was broader than what was checked: every callback runs to completion, and `reconcile` / `sync_ledger` are not in the checked world. The adversarial review (`evidence/proofs-adversarial-review-2026-11-11.md`, M1) found the fixed guard CAN pay twice on the `reconcile` path (H1, H2). Proof 2 is scoped to vault-a's 7 setup invoices with no owner action during the run (M2).

`proofs/run.sh` (no argument) runs both and exits 0 only if every outcome matches the plan. Logs go to `proofs/out/` (or `$OUT`).

## Setup (once)

```
cargo install --locked kani-verifier && cargo kani setup      # Kani 0.68.0, CBMC 6.11.0
python3 -m venv proofs/.venv && proofs/.venv/bin/pip install z3-solver   # z3 5.3.3
```

The cross-check also needs `harness/target/release/arena-harness` (built by `./verify.sh`).

## What is where

- `guard-model/`: a hand-written model of `contracts/guard`'s `pay`, `on_transfer`, `reconcile`/`on_reconcile`, `resolve_stuck` and `sync_ledger`, every line citing the source line it mirrors, and the Kani harnesses (`src/proofs.rs`) with the NEAR scheduler written out (`src/world.rs`). `src/bin/playback.rs` turns Kani's counterexample into a readable trace.
- `guard-real/`: the REAL `contracts/guard` source, compiled unchanged as a path dependency on near-sdk 5.27.0's mocked chain. `src/bin/exhaustive.rs` runs every schedule against it, with the model in lockstep. Kani could not compile this crate (internal compiler error, see the evidence file), which is why Proof 1 uses the model for Kani.
- `guard-real-mutant/`: the guard with one line deleted (line 194 since Nov 11, line 186 before: the `Pending` write). Must fail.
- `guard-real-mutant-reopen/`: the guard with the pre-Nov-11 `reconcile` arm put back (balance = ledger -> `Approved`). Must fail in the full world.
- `guard-model/src/inductive.rs`: the inductive-step proof (invariant, the 11 actions, harnesses).
- `z3/policy_proof.py`: Proof 2. Reads `harness/setup.rs`, `tools/injection/scenarios.json` and `evidence/narrow-policy.json`.
- `check_kani.py`: compares one Kani log with the plan.

Nothing here edits `contracts/`, `targets/`, `harness/` or `tools/`.
