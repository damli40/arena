#!/usr/bin/env bash
# Mutation table for vault-a: plant ONE flaw per copy, run the bench's existing
# scripted attacks against each copy, record which attacks catch it.
#
#   tools/mutation/run.sh                 baseline + every mutant (M0..M10)
#   tools/mutation/run.sh M4 M7           baseline + only these mutants
#   SKIP_BASELINE=1 tools/mutation/run.sh M4    mutants only (table needs a baseline from the same date)
#
# What it does, from scratch each time:
#  1. pins the COMMITTED harness (git archive HEAD harness) into mutants/target/harness-pinned/,
#     with a private copy of test_token.wasm, builds it, and copies the binary to
#     mutants/target/bin/arena-harness. A parallel edit or rebuild of harness/ cannot touch it.
#  2. writes the scripted attacks with `arena-harness gen-scripted` and checks they match sequences-scripted/.
#  3. baseline: frozen targets/vault-a (must be 0 on all 10) and leaky-control-v2 (must be caught).
#  4. per mutant: copies vault-a's Cargo.toml, Cargo.lock, rust-toolchain.toml, .cargo/config.toml, src/ to mutants/<id>/,
#     applies tools/mutation/mutate.py <id>, writes the diff to MUTATION.md, builds with the same
#     command as vault-a (cargo build --release --target wasm32-unknown-unknown, toolchain 1.86.0),
#     writes the wasm sha256 to FROZEN.txt BEFORE running, runs the 10 attacks via --wasm,
#     and checks the sha256 again after.
# Outputs: evidence/mutation-<date>/<id>.log, <id>/ (result JSONs), summary.tsv.
# Never touches targets/, contracts/ or harness/. Local sandbox only.
set -euo pipefail
cd "$(dirname "$0")/../.."
source "$HOME/.cargo/env" 2>/dev/null || true
ROOT=$PWD
DATE=$(date +%Y-%m-%d)
OUT="$ROOT/evidence/mutation-$DATE"
PIN="$ROOT/mutants/target/harness-pinned"
BIN="$ROOT/mutants/target/bin/arena-harness"
WASM_TARGET="$ROOT/mutants/target/wasm"
mkdir -p "$OUT" "$(dirname "$BIN")"

ids=("$@")
[ ${#ids[@]} -eq 0 ] && read -r -a ids <<< "$(python3 -I tools/mutation/mutate.py --list)"

frozen_check() { # vault-a and leaky-control-v2 must match their FROZEN.txt
  for t in vault-a leaky-control-v2; do
    (cd "targets/$t" && while read -r tag file hash _; do
      [ "$tag" = sha256 ] || continue
      [ "$(shasum -a 256 "$file" | cut -d' ' -f1)" = "$hash" ] || { echo "FROZEN CHECK FAILED: $t/$file" >&2; exit 1; }
    done < FROZEN.txt)
  done
  echo "frozen ok ($1): vault-a, leaky-control-v2"
}

# 1. Pinned harness from the committed tree.
echo "== pinning harness from git HEAD $(git rev-parse HEAD)"
mkdir -p "$PIN/evidence" "$PIN/contracts/target/wasm32-unknown-unknown/release"
git archive HEAD harness | tar -x -C "$PIN"
cp contracts/target/wasm32-unknown-unknown/release/test_token.wasm "$PIN/contracts/target/wasm32-unknown-unknown/release/"
[ -e "$PIN/targets" ] || ln -s ../../../targets "$PIN/targets"
(cd "$PIN/harness" && cargo build --release) > "$OUT/harness-build.log" 2>&1 || { tail -20 "$OUT/harness-build.log"; exit 1; }
cp "$PIN/harness/target/release/arena-harness" "$BIN"
{
  echo "harness pinned from git HEAD $(git rev-parse HEAD) via git archive"
  echo "sha256 arena-harness  $(shasum -a 256 "$BIN" | cut -d' ' -f1)"
  echo "sha256 test_token.wasm $(shasum -a 256 "$PIN/contracts/target/wasm32-unknown-unknown/release/test_token.wasm" | cut -d' ' -f1)"
} | tee "$OUT/HARNESS.txt"

# 2. The scripted attacks, as the harness writes them.
SEQ="$OUT/sequences"
mkdir -p "$SEQ"
"$BIN" gen-scripted "$SEQ"
if diff -r "$SEQ" sequences-scripted > /dev/null; then echo "gen-scripted output == sequences-scripted/"; else echo "NOTE: gen-scripted output differs from sequences-scripted/" | tee -a "$OUT/HARNESS.txt"; fi

run_suite() { # $1 = id, then target flags
  local id="$1"; shift
  local log="$OUT/$id.log"
  echo "== running 10 scripted attacks on $id -> $log"
  set +e
  "$BIN" run "$SEQ" --budget 10 --label "mutation" "$@" > "$log" 2>&1
  local rc=$?
  set -e
  echo "  harness exit code $rc" | tee -a "$log"
  # copy this run's per-attempt result JSONs out of the pinned tree
  local rd; rd=$(grep -m1 "result json: " "$log" | sed 's/.*result json: //')
  if [ -n "$rd" ]; then mkdir -p "$OUT/$id"; cp "$(dirname "$rd")"/*.result.json "$OUT/$id/"; fi
  # one TSV line per attack: id, attack, unauthorised
  awk -v id="$id" '/^=+ SUMMARY/{on=1;next} on && /unauthorised=/ && !/attempts=/{
      a=$1; u=$2; sub("unauthorised=","",u); print id "\t" a "\t" u }' "$log" >> "$OUT/summary.tsv"
  grep -E "attempts=[0-9]+ attempts_found_something=" "$log" | sed "s/^/  $id: /" || echo "  $id: NO SUMMARY (run failed, see log)"
}

frozen_check "before"
# Fresh summary on a full run; a SKIP_BASELINE run appends to the existing one.
if [ "${SKIP_BASELINE:-0}" != 1 ] || [ ! -f "$OUT/summary.tsv" ]; then
  printf 'target\tattack\tunauthorised\n' > "$OUT/summary.tsv"
fi

# 3. Baseline.
if [ "${SKIP_BASELINE:-0}" != 1 ]; then
  run_suite baseline-vault-a --target vault
  run_suite baseline-leaky-control-v2 --target control
fi

# 4. Mutants.
for id in "${ids[@]}"; do
  d="mutants/$id"
  echo "== building $id"
  rm -rf "${d:?}/src" "$d/vault_a.wasm"
  mkdir -p "$d"
  cp targets/vault-a/Cargo.toml targets/vault-a/Cargo.lock targets/vault-a/rust-toolchain.toml "$d/"
  cp -R targets/vault-a/src "$d/src"
  mkdir -p "$d/.cargo"; cp targets/vault-a/.cargo/config.toml "$d/.cargo/config.toml"   # rustflags --cfg near, as vault-a
  chmod -R u+w "$d"   # the frozen sources are read-only; the copies must be editable
  python3 -I tools/mutation/mutate.py "$id" "$d/src/lib.rs"
  {
    echo "# $id"
    echo
    if [ "$id" = M0 ]; then echo "No change: an unmodified copy, to check the build reproduces the frozen vault-a wasm."
    else echo "One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan.md."; fi
    echo "Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a."
    echo
    echo '```diff'
    diff -u targets/vault-a/src/lib.rs "$d/src/lib.rs" | sed "1s|.*|--- targets/vault-a/src/lib.rs|;2s|.*|+++ mutants/$id/src/lib.rs|" || true
    echo '```'
  } > "$d/MUTATION.md"
  (cd "$d" && CARGO_TARGET_DIR="$WASM_TARGET" cargo build --release --target wasm32-unknown-unknown) > "$OUT/$id-build.log" 2>&1 \
    || { echo "  BUILD FAILED for $id (see $OUT/$id-build.log)"; printf '%s\tBUILD-FAILED\t-\n' "$id" >> "$OUT/summary.tsv"; continue; }
  cp "$WASM_TARGET/wasm32-unknown-unknown/release/vault_a.wasm" "$d/vault_a.wasm"
  sha=$(shasum -a 256 "$d/vault_a.wasm" | cut -d' ' -f1)
  prev=$(awk '$1=="sha256" && $2=="vault_a.wasm"{print $3}' "$d/FROZEN.txt" 2>/dev/null || true)
  {
    echo "$id frozen $(date -u +%Y-%m-%dT%H:%M:%SZ), before its bench run. Planted-flaw TEST FIXTURE: never deploy."
    echo "sha256 vault_a.wasm $sha"
    echo "sha256 src/lib.rs   $(shasum -a 256 "$d/src/lib.rs" | cut -d' ' -f1)"
    echo "built from targets/vault-a (wasm $(awk '$2=="vault_a.wasm"{print $3}' targets/vault-a/FROZEN.txt)) + MUTATION.md"
  } > "$d/FROZEN.txt"
  if [ -n "$prev" ] && [ "$prev" != "$sha" ]; then echo "  NOTE: $id wasm sha changed vs previous build ($prev -> $sha)"; fi
  echo "  $id wasm sha256 $sha"
  run_suite "$id" --wasm "$d/vault_a.wasm" --wasm-label "$id"
  [ "$(shasum -a 256 "$d/vault_a.wasm" | cut -d' ' -f1)" = "$sha" ] || { echo "  $id WASM CHANGED DURING RUN" >&2; exit 1; }
done

frozen_check "after"
echo "== done. summary: $OUT/summary.tsv (rows with unauthorised>0 below)"
awk -F'\t' 'NR>1 && $3!="0"' "$OUT/summary.tsv"
