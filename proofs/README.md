# proofs: the PROVE step

Arena tests guards by attacking them. This folder checks two properties for **every** case inside a stated bound, and hands back a concrete failing case when there is one. Plan, written before any run: `evidence/proofs-plan.md`. Results: `evidence/proofs-2026-11-10.md`.

| Proof | Question | Tool | One command | Runtime (M-series Mac, after first build) |
|---|---|---|---|---|
| 1 | Can one invoice be paid twice, in any order NEAR runs the steps? | Kani (on a model) + an exhaustive run of the real contract | `proofs/run.sh proof1` | about 255 s; the full `run.sh` took 257 s on Nov 10 (6 Kani harnesses 121 s of solver time, 2 playbacks, 6 exhaustive runs 58 s); the first build of `guard-real` adds a few minutes |
| 2 | Can the owner's policy pay more than the owner intended? | z3 | `proofs/run.sh proof2` | about 1-2 s |
| 2, cross-check | Does the chain pay what z3 predicted? | the Arena harness on a local sandbox | `proofs/crosscheck.sh` | about 17 s |

`proofs/run.sh` (no argument) runs both and exits 0 only if every outcome matches the plan. Logs go to `proofs/out/` (or `$OUT`).

## Setup (once)

```
cargo install --locked kani-verifier && cargo kani setup      # Kani 0.68.0, CBMC 6.11.0
python3 -m venv proofs/.venv && proofs/.venv/bin/pip install z3-solver   # z3 5.3.3
```

The cross-check also needs `harness/target/release/arena-harness` (built by `./verify.sh`).

## What is where

- `guard-model/`: a hand-written model of `contracts/guard`'s `pay` and `on_transfer`, every line citing the source line it mirrors, and the Kani harnesses (`src/proofs.rs`) with the NEAR scheduler written out (`src/world.rs`). `src/bin/playback.rs` turns Kani's counterexample into a readable trace.
- `guard-real/`: the REAL `contracts/guard` source, compiled unchanged as a path dependency on near-sdk 5.27.0's mocked chain. `src/bin/exhaustive.rs` runs every schedule against it, with the model in lockstep. Kani could not compile this crate (internal compiler error, see the evidence file), which is why Proof 1 uses the model for Kani.
- `guard-real-mutant/`: the guard with one line deleted (line 186, the `Pending` write). Must fail.
- `z3/policy_proof.py`: Proof 2. Reads `harness/setup.rs`, `tools/injection/scenarios.json` and `evidence/narrow-policy.json`.
- `check_kani.py`: compares one Kani log with the plan.

Nothing here edits `contracts/`, `targets/`, `harness/` or `tools/`.
