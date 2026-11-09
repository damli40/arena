#!/usr/bin/env bash
# Build both contracts with the pinned toolchain, then run the local-sandbox proof.
# Local only: near-workspaces starts a throwaway near-sandbox node on this machine.
set -euo pipefail
cd "$(dirname "$0")"
source "$HOME/.cargo/env"
(cd contracts && cargo build --release --target wasm32-unknown-unknown)
# Test-only guard build with the `fault-injection` feature (on_transfer panics for `crash-` ids).
# Separate target dir, so it can never overwrite the normal guard.wasm.
(cd contracts && cargo build --release --target wasm32-unknown-unknown -p guard \
  --features fault-injection --target-dir target-fault)
cd tests
# --test-threads=1 keeps the evidence log readable; each test starts its own sandbox anyway.
cargo test --release -- --nocapture --test-threads=1 "$@"
