# Attack admission branch, checked on a fresh copy (2026-11-12)

Commit `18270e7` (branch `attack-admission`) exported with `git archive` into an empty folder, put
under a new git repository so `git status` shows any file a run changes, then these commands in this
order. One Mac, Apple silicon; Rust and the sandbox already installed. Logs were kept outside the repo.

| # | Command | Exit | Time | Key line |
|---|---|---|---|---|
| 1 | `python3 -I -m unittest discover -s tools/hunter/tests` (before any build) | 0 | 10 s | `Ran 79 tests`, `OK` |
| 2 | `python3 -I -m unittest discover -s tools/admission/tests` (before any build) | 0 | 3 s | `Ran 54 tests`, `OK` |
| 3 | `./verify.sh fast` | 0 | 1612 s | `verify: 5 passed, 0 failed (mode=fast)` (includes building everything from nothing) |
| 4 | `(cd harness && cargo test --release)` | 0 | 77 s | `62 passed; 0 failed; 1 ignored` |
| 5 | `python3 -I tools/check/tests/test_check.py` | 0 | 6 s | `Ran 105 tests`, `OK` |
| 6 | hunter tests again, after building | 0 | 5 s | `Ran 79 tests`, `OK` |
| 7 | `node --test tools/lookup/test.mjs` | 0 | 5 s | `pass 37`, `fail 0` |
| 8 | `python3 -I tools/admission/manifest.py --check` | 0 | 1 s | `manifest: up to date` |
| 9 | `python3 -I tools/admission/admit.py --recheck sequences-scripted/03-sequential-second-pay.json` | 0 | under 1 s | `... stored runs give validated (...matched known-bad: mutant:M4); stamp agrees` |
| 10 | `python3 -I tools/admission/admit.py --recheck sequences-scripted/02-race-double-pay.json` | 0 | under 1 s | `... stored runs give partially-validated (... steps[].receipts absent ...); stamp agrees` |
| 11 | `python3 -I tools/hidden/hidden.py check-public` | 0 | under 1 s | `hidden-set public files: 6 of 6 consistent with set 835729d9f34fa123... (9 attacks)` |
| 12 | `python3 -I tools/admission/admit.py sequences-scripted/03-sequential-second-pay.json --runs 3` | 0 | 33 s | `ADMISSION scripted-03-sequential-second-pay: validated (...)`, raw runs in gitignored `runs/` |
| 13 | `./arena check targets/vault-a/vault_a.wasm` | 0 | 279 s | `arena: held 51/51 (...)` |
| 14 | `./arena check targets/leaky-control-v2/leaky_control.wasm` | 1 | 277 s | `arena: broke 5 of 51 (...)`: ai-01, ai-02, c261110-1-race-valid-double..., p210408638-1-reentrancy..., scripted-02, the same 5 as `evidence/check-2026-11-11/leaky-control-v2/report.json` |
| 15 | `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json` | 0 | 330 s | `arena: held 53/53 (...)` |
| 16 | `./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json` | 1 | 347 s | `arena: broke 2 of 53 (...)` |
| 17 | `./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json` | 0 | 232 s | `arena: held 48/48 (...)` |
| 18 | `git status --porcelain` after all of the above | | | empty: no committed file changed |

Guard results are unchanged by this branch. What it adds is the attack-level label: 7 of 53
validated, 1 partially, 45 unvalidated (`evidence/MANIFEST.md`).

## What this does not cover

- One machine, not Linux. The full `./verify.sh`, `proofs/run.sh`, `tla/run.sh` and the mutation
  table were not re-run. `tools/mutation/run.sh` was changed (its parity check now compares name and
  steps) and has not been run since.
- No testnet write. `tools/receipts/publish.py --hidden-set ... --library-admission --dry-run` was
  run on the working copy only.
- No independent reviewer reproduced this from a clean checkout yet.
