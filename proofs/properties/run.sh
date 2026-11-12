#!/usr/bin/env bash
# The property library checks itself: no network, no NEAR sandbox, under a minute once built.
#   1. the specs' unit test (each property rejects only its own flawed ledger);
#   2. the harness template: with no flaw all five hold; each planted flaw breaks exactly its property.
# Exit 0 only if every outcome is as listed below.
set -uo pipefail
cd "$(dirname "$0")"
source "$HOME/.cargo/env" 2>/dev/null || true
PASS=0; FAIL=0
ok() { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
cargo +stable test --release --quiet > /dev/null 2>&1 && ok "specs unit test" || bad "specs unit test"
cargo +stable build --release --quiet --example template 2>&1 | grep -E '^error' -A5
while read -r flaw want; do
  line=$(./target/release/examples/template "$flaw" | tail -1)
  echo "      $line"
  case "$line" in *"broken=$want") ok "template flaw=$flaw -> broken=$want" ;; *) bad "template flaw=$flaw (wanted broken=$want)" ;; esac
done <<'EOF'
none []
double-pay ["no-double-pay"]
any-payee ["payee-list-only"]
no-cap ["never-beyond-cap"]
no-hold ["approval-threshold"]
no-budget ["window-budget"]
EOF
echo "properties: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
