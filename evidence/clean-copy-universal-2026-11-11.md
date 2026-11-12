# Fresh-copy run of the direct-pay branch (`universal-guards`), Nov 11 to 12, 2026

Purpose: show that adding the direct-pay path (no invoices) changed none of Arena's existing results,
and that the new direct-pay claims re-run from a fresh copy. These are the checks the merge rules
ask for.

Commit `bfb6f16` exported with `git archive` into an empty folder outside the repo, put under a new
git repository so `git status` shows any file a run changes, then these commands in this order. One
Mac, Apple silicon; Rust and the sandbox were already installed, but nothing was built in the copy.
The two later commits on the branch (`82af03c`, `f4fbd08`) change wording only (a docstring, README
and EVALUATE text), no code.

| # | Command | Exit | Time | Key line |
|---|---|---|---|---|
| 1 | `python3 -I -m unittest discover -s tools/hunter/tests`, before anything was built | 0 | 4 s | `Ran 79 tests`, `OK` |
| 2 | `./verify.sh fast` | 0 | 1243 s (includes the first build) | `verify: 5 passed, 0 failed (mode=fast)` |
| 3 | `(cd harness && cargo test --release)` | 0 | 257 s | `70 passed; 0 failed; 1 ignored` (62 before this branch; the 8 new ones test the direct-pay config and accounting) |
| 4 | `python3 -I tools/check/tests/test_check.py` | 0 | 9 s | `Ran 105 tests`, `OK` |
| 5 | `python3 -I tools/check/tests/test_direct.py` | 0 | under 1 s | `Ran 19 tests`, `OK` |
| 6 | hunter tests again, after building | 0 | 12 s | `Ran 79 tests`, `OK` |
| 7 | `node --test tools/lookup/test.mjs` | 0 | 7 s | `pass 37`, `fail 0` |
| 8 | `./arena check targets/vault-a/vault_a.wasm` | 0 | 310 s | `arena: held 51/51 (...)` |
| 9 | `./arena check targets/leaky-control-v2/leaky_control.wasm` | 1 | 312 s | `arena: broke 5 of 51 (...)`, the same 5 attacks as `check-fixes-2-2026-11-11/leaky-control-v2/summary.md` |
| 10 | `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json` | 0 | 385 s | `arena: held 53/53 (...)` |
| 11 | `./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json` | 1 | 407 s | `arena: broke 2 of 53 (...; 300 tokens paid outside the five receivers; ...)`, the same 2 BROKE lines as `check-intents-2026-11-11.md` |
| 12 | `./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json` | 0 | 232 s | `arena: held 48/48 (...)` |
| 13 | Guard G check before fetching its code (EVALUATE row 16) | 2 | under 1 s | `verdict: could not finish before G0: the wasm ... is not there (...)` |
| 14 | `python3 -I tools/check/direct_selftest.py --out runs/direct-selftest --jobs 6` | 0 | 604 s | `self-tests: 18/18 passed` |
| 15 | `python3 targets/entrant-G/fetch.py` (network; account given by environment variable) | 0 | 4 s | `ok: wrote targets/entrant-G/guard_g.wasm, sha256 b0d6ee10... matches the frozen fingerprint (277735 bytes)` |
| 16 | Guard G check, hand mapping (EVALUATE row 18) | 0 | 48 s | `verdict: held 11, stopped by the access key 1` |
| 17 | fetch pointed at a closed local port (EVALUATE row 17) | 1 | under 1 s | `REFUSED: RPC call failed: ...; nothing written` |
| 18 | Guard G check, Muse's saved mapping (EVALUATE row 19) | 2 | 25 s | `verdict: could not finish at G2/G3: ...` |
| 19 | Guard G check, NEAR AI's saved mapping (EVALUATE row 19) | 2 | 46 s | `verdict: could not finish 1, held 10, stopped by the access key 1` |
| 20 | `git status --porcelain` after all of the above | | | empty: no committed file changed, and the fetched Guard G code stayed untracked |

## What this does not cover

- One machine, not Linux. The full `./verify.sh`, `proofs/run.sh`, `tla/run.sh` and the mutation
  table were not re-run.
- Rows 15, 16, 18 and 19 needed network and the Guard G account name, which is not in the repo.
- This is our own run. The independent reproduction from a clean checkout has not happened yet.
