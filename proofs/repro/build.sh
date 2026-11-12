#!/usr/bin/env bash
# Reproducible build check: does the guard source the proofs read build to the exact wasm
# that ran on NEAR testnet (sha256 0382023b...)?
#
# What it does, in order:
#   1. exports contracts/ from a git commit (default HEAD) into a fresh, empty folder,
#      so nothing from this working tree (old target/ dirs, edits) can leak in;
#   2. builds the guard there with the pinned toolchain (contracts/rust-toolchain.toml,
#      Rust 1.86.0) and the committed Cargo.lock (--locked), release profile, wasm32;
#   3. prints the sha256 and compares it with EXPECTED.
#   4. with --onchain, also asks a public testnet RPC (read only, no key, no write) for the
#      code of the two kept guard accounts and compares that sha256 too.
#
# Exit 0 only if every comparison matches.
set -euo pipefail
cd "$(dirname "$0")/../.."
source "$HOME/.cargo/env"
EXPECTED=0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e
REV="${REV:-HEAD}"
ONCHAIN=0; MUTANT=0
for a in "$@"; do
  case "$a" in --onchain) ONCHAIN=1;; --mutant) MUTANT=1;; *) echo "unknown arg $a"; exit 2;; esac
done
# --mutant: the must-fail check. Delete the one line proofs/guard-real-mutant deletes
# (`inv.status = Status::Pending;` in `pay`). The hash MUST then differ; exit 0 only if it does.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/arena-repro.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
if git rev-parse --git-dir >/dev/null 2>&1; then
  echo "rev: $(git rev-parse "$REV")"
  git archive "$REV" contracts | tar -x -C "$WORK"
else
  # A `git archive` export has no .git: copy contracts/ without any build output instead.
  echo "rev: (no git here; copying contracts/ from this folder, without target dirs)"
  mkdir "$WORK/contracts"
  (cd contracts && tar -c --exclude './target' --exclude './target-fault' . ) | tar -x -C "$WORK/contracts"
fi
cd "$WORK/contracts"
if [ $MUTANT = 1 ]; then
  N=$(grep -c '^                inv.status = Status::Pending;$' guard/src/lib.rs)
  [ "$N" = 1 ] || { echo "mutant: expected exactly 1 target line, found $N"; exit 2; }
  sed -i.bak '/^                inv.status = Status::Pending;$/d' guard/src/lib.rs && rm guard/src/lib.rs.bak
  echo "mutant: deleted the Pending write in pay"
fi
echo "toolchain: $(rustc --version)"
echo "cargo: $(cargo --version)"
# Whole workspace, exactly as run.sh does it: building only `-p guard` gives a different wasm
# (d76e6e4c...), because cargo then resolves near-sdk features without the test-token crate.
cargo build --release --target wasm32-unknown-unknown --locked --quiet
GOT=$(shasum -a 256 target/wasm32-unknown-unknown/release/guard.wasm | cut -d' ' -f1)
SIZE=$(wc -c < target/wasm32-unknown-unknown/release/guard.wasm | tr -d ' ')
echo "built:    $GOT ($SIZE bytes)"
echo "expected: $EXPECTED"
FAIL=0
if [ $MUTANT = 1 ]; then
  if [ "$GOT" = "$EXPECTED" ]; then echo "MUTANT NOT DETECTED: a changed source gave the same hash"; exit 1; fi
  echo "MUTANT DETECTED: one deleted line changes the hash, as it must"; exit 0
fi
if [ "$GOT" = "$EXPECTED" ]; then echo "REPRO MATCH: source at this commit builds the testnet wasm"; else echo "REPRO MISMATCH"; FAIL=1; fi
if [ $ONCHAIN = 1 ]; then
  for acct in r11bvf3-guard.arena-race-funder-1111.testnet r11cfx4-guard.arena-race-funder-1111.testnet; do
    H=$(curl -s https://rpc.testnet.fastnear.com -H 'content-type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_code\",\"finality\":\"final\",\"account_id\":\"$acct\"}}" \
      | python3 -I -c 'import sys,json,base64,hashlib; r=json.load(sys.stdin)["result"]; print(hashlib.sha256(base64.b64decode(r["code_base64"])).hexdigest())' || echo "read-failed")
    if [ "$H" = "$GOT" ]; then echo "ONCHAIN MATCH: $acct $H"; else echo "ONCHAIN MISMATCH: $acct $H"; FAIL=1; fi
  done
fi
exit $FAIL
