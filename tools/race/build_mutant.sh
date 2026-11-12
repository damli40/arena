#!/usr/bin/env bash
# Build one race-ordering mutant of vault-a:   tools/race/build_mutant.sh race-m1
# Same steps and build command as tools/mutation/run.sh: copy targets/vault-a, apply ONE planted flaw
# with tools/mutation/mutate.py, cargo build --release --target wasm32-unknown-unknown (toolchain
# 1.86.0, rustflags --cfg near), then write MUTATION.md (the diff) and FROZEN.txt (sha256) in
# mutants/<id>/. Planted-flaw TEST FIXTURE: never deploy.
set -euo pipefail
cd "$(dirname "$0")/../.."
if ! command -v cargo >/dev/null 2>&1 && [ -x "${CARGO_HOME:-$HOME/.cargo}/bin/cargo" ]; then
  PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"; export PATH
fi
id="${1:?usage: build_mutant.sh <race mutant id>}"
python3 -I tools/mutation/mutate.py --list-race | tr ' ' '\n' | grep -qx "$id" || { echo "not a race mutant: $id" >&2; exit 64; }
d="mutants/$id"
mkdir -p "$d/.cargo"
[ -d "$d/src" ] && chmod -R u+w "$d/src" && rm -r "$d/src"
cp targets/vault-a/Cargo.toml targets/vault-a/Cargo.lock targets/vault-a/rust-toolchain.toml "$d/"
cp -R targets/vault-a/src "$d/src"
cp targets/vault-a/.cargo/config.toml "$d/.cargo/config.toml"
chmod -R u+w "$d"
python3 -I tools/mutation/mutate.py "$id" "$d/src/lib.rs"
{
  echo "# $id"
  echo
  echo "One planted flaw in a copy of targets/vault-a, for race ordering (evidence/race-ordering-2026-11-11.md)."
  echo "Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a."
  echo
  echo '```diff'
  diff -u targets/vault-a/src/lib.rs "$d/src/lib.rs" | sed "1s|.*|--- targets/vault-a/src/lib.rs|;2s|.*|+++ mutants/$id/src/lib.rs|" || true
  echo '```'
} > "$d/MUTATION.md"
T="$PWD/mutants/target/wasm"
(cd "$d" && CARGO_TARGET_DIR="$T" cargo build --release --target wasm32-unknown-unknown)
cp "$T/wasm32-unknown-unknown/release/vault_a.wasm" "$d/vault_a.wasm"
{
  echo "$id frozen $(date -u +%Y-%m-%dT%H:%M:%SZ), before its race runs. Planted-flaw TEST FIXTURE: never deploy."
  echo "sha256 vault_a.wasm $(shasum -a 256 "$d/vault_a.wasm" | cut -d' ' -f1)"
  echo "sha256 src/lib.rs   $(shasum -a 256 "$d/src/lib.rs" | cut -d' ' -f1)"
  echo "built from targets/vault-a (wasm $(awk '$2=="vault_a.wasm"{print $3}' targets/vault-a/FROZEN.txt)) + MUTATION.md"
} > "$d/FROZEN.txt"
cat "$d/FROZEN.txt"
