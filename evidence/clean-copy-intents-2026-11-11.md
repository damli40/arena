# Clean-copy run before merging NEAR Intents testing (2026-11-11)

Before merging the `crosschain-intents` branch, we exported commit `4ee314d` with `git archive` into an
empty folder (no `target/`, no reports, no earlier logs) and ran the checks below, one after the
other, on one Mac (Apple silicon, macOS). Rust and the NEAR sandbox binary were already installed.

| # | Command | Exit | Time | Key line printed |
|---|---|---|---|---|
| 1 | `./verify.sh fast` | 0 | 433 s | `verify: 5 passed, 0 failed (mode=fast)` |
| 2 | `(cd harness && cargo test --release)` | 0 | 16 s | `62 passed; 0 failed; 1 ignored` |
| 3 | `python3 -I tools/check/tests/test_check.py` | 0 | 3 s | `Ran 105 tests`, `OK` |
| 4 | `python3 -I -m unittest discover -s tools/hunter/tests` | 0 | 1 s | `Ran 77 tests`, `OK` |
| 5 | `node --test tools/lookup/test.mjs` | 0 | 5 s | `pass 37`, `fail 0` |
| 6 | `./arena check targets/vault-a/vault_a.wasm` | 0 | 279 s | `arena: held 51/51 (...)` |
| 7 | `./arena check targets/leaky-control-v2/leaky_control.wasm` | 1 | 275 s | `arena: broke 5 of 51 (...)`, the same 5 attacks as `check-fixes-2-2026-11-11/leaky-control-v2/summary.md` |
| 8 | `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json` | 0 | 309 s | `arena: held 53/53 (...; pays via NEAR Intents: local release build, no withdrawals to other chains)` |
| 9 | `./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json` | 1 | 310 s | `arena: broke 2 of 53 (...; 300 tokens paid outside the five receivers; ...)`, the same 2 BROKE lines as `check-intents-2026-11-11.md` |
| 10 | `./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json` | 0 | 231 s | `arena: held 48/48 (...; scored from NEAR balances)` |

Every exit code and key line matched the saved evidence. The branch was then merged into `main`
(fast-forward, no merge commit).

## What this does not cover

- Not a different machine, not Linux. Rust and the sandbox were already installed here.
- Not run: the full `./verify.sh`, `proofs/run.sh`, `tla/run.sh`, the full mutation table, and the
  on-chain tests in `receipts/host` (the Intents work does not touch `receipts/`).
- No other person or coding agent has run this yet.
