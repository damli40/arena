# Does the proved source build the wasm that ran on testnet? (2026-11-11)

**Answer: yes.** The guard source at commit `3065988` (unchanged since `f7bc2d9`, the `reconcile` fix), built
from a fresh `git archive` export with the pinned toolchain, gives sha256
`0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e`, 187,013 bytes. That is the hash of the guard
used in every testnet trial (`testnet-2026-11-11.md`), and a read-only RPC query today returned the same hash for
the code on both kept testnet guard accounts.

## Command

```
proofs/repro/build.sh --onchain     # build + compare + read the two testnet accounts' code (read only)
proofs/repro/build.sh --mutant      # must-fail: delete one line, the hash must change
```

About 15 s each after the crates are downloaded. Logs: `proofs-all-2026-11-11/repro-build.log`,
`proofs-all-2026-11-11/repro-build-mutant.log`.

## Lines you should see

```
built:    0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e (187013 bytes)
REPRO MATCH: source at this commit builds the testnet wasm
ONCHAIN MATCH: r11bvf3-guard.arena-race-funder-1111.testnet 0382023b...
ONCHAIN MATCH: r11cfx4-guard.arena-race-funder-1111.testnet 0382023b...
```

and for the mutant (the `Pending` write in `pay` deleted, the same line `proofs/guard-real-mutant` deletes):

```
built:    02a7515d3447ee7929a9f6c6ea889dfa1ac6dc3da4118bf195dd76d9750be877 (187006 bytes)
MUTANT DETECTED: one deleted line changes the hash, as it must
```

## How it is pinned

- Toolchain: `contracts/rust-toolchain.toml`, Rust 1.86.0, `wasm32-unknown-unknown`.
- Flags: `contracts/.cargo/config.toml` (`--cfg near`, `-C link-arg=-s`), release profile in `contracts/Cargo.toml`.
- Dependencies: the committed `contracts/Cargo.lock`, with `--locked` (near-sdk 5.27.0, the same version the
  `proofs/guard-real` crate runs the source against).
- The export is fresh, so no old `target/` folder or uncommitted edit can leak in.

## One thing that surprised us, kept here

The initial attempt built only the guard crate (`-p guard`) and got a different hash, `d76e6e4c…`. Building the
whole `contracts/` workspace, as `run.sh` does, gives `0382023b…`. The reason: with both crates in one build,
cargo picks one shared set of near-sdk features for both, which changes the guard's compiled code. So "the
source" here means the guard crate built as part of its workspace. Anyone rebuilding must build the workspace.

## What this ties together, and what it does not

- **Ties:** the Rust source the proofs read (`contracts/guard/src/lib.rs`, used unchanged by `proofs/guard-real`)
  is byte-for-byte the source of the deployed wasm. A changed line changes the hash.
- **Does not tie:** the proofs still run that source compiled for this Mac on near-sdk's mocked chain, not the
  wasm inside NEAR's VM. A bug in the Rust-to-wasm compiler or in the NEAR VM would not show up in the proofs.
  The "any number of calls" proof is still about the model, checked against the source up to the bounds in
  `proofs-inductive-2026-11-11.md`.
- Built on one machine (Apple M-series, macOS). Not yet rebuilt on Linux; a different OS could in principle give
  a different hash.
