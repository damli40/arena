# Clean-copy regression, branch admission-2 (2026-11-12)

Commit `79f8c41` (branch `admission-2`) was exported with `git archive` into an empty folder and put under
a new git repository, so `git status` would show any file a run changed. The commands below then ran in
order on one macOS machine. The NEAR sandbox binary already on disk was reused, cargo ran offline, and
nothing was downloaded. Steps 1-17 are the same list as `evidence/admission-clean-copy-2026-11-12.md`.
Steps 18-21 are new on this branch.

| # | command | exit | time | result |
|---|---|---|---|---|
| 1 | `python3 -I -m unittest discover -s tools/hunter/tests` (before any build) | 0 | 26 s | `Ran 83 tests`, `OK` |
| 2 | `python3 -I -m unittest discover -s tools/admission/tests` (before any build) | 0 | 2 s | `Ran 56 tests`, `OK` |
| 3 | `./verify.sh fast` | 0 | 2504 s | `verify: 5 passed, 0 failed (mode=fast)` (includes building everything from nothing) |
| 4 | `(cd harness && cargo test --release)` | 0 | 230 s | `62 passed; 0 failed; 1 ignored` |
| 5 | `python3 -I tools/check/tests/test_check.py` | 0 | 19 s | `Ran 105 tests`, `OK` |
| 6 | hunter tests again, after building | 0 | 29 s | `Ran 83 tests`, `OK` |
| 7 | `node --test tools/lookup/test.mjs` | 0 | 8 s | `pass 37`, `fail 0` |
| 8 | `python3 -I tools/admission/manifest.py --check` | 0 | 2 s | `manifest: up to date` |
| 9 | `admit.py --recheck sequences-scripted/03-sequential-second-pay.json` | 0 | under 1 s | `stored runs give validated (... matched known-bad: mutant:M4); stamp agrees` |
| 10 | `admit.py --recheck sequences-scripted/02-race-double-pay.json` | 0 | 1 s | `stored runs give partially-validated (... steps[].receipts absent ...)` |
| 11 | `python3 -I tools/hidden/hidden.py check-public` | 0 | under 1 s | `hidden-set public files: 12 of 12 consistent with the set each names (6 on current set e35a4c1f... (14 attacks); 6 on earlier set 835729d9... (9 attacks))` |
| 12 | `admit.py sequences-scripted/03-sequential-second-pay.json --runs 3` | 0 | 35 s | `ADMISSION scripted-03-sequential-second-pay: validated (... mutant:M4)`, raw runs in gitignored `runs/` |
| 13 | `./arena check targets/vault-a/vault_a.wasm` | 0 | 289 s | `arena: held 51/51` |
| 14 | `./arena check targets/leaky-control-v2/leaky_control.wasm` | 1 | 289 s | `arena: broke 5 of 51`: ai-01, ai-02, c261110-1-race-valid-double..., p210408638-1-reentrancy..., scripted-02, the same 5 as before |
| 15 | `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json` | 0 | 487 s | `arena: held 53/53` |
| 16 | `./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json` | 1 | 448 s | `arena: broke 2 of 53` |
| 17 | `./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json` | 0 | 237 s | `arena: held 48/48` |
| 18 | `admit.py --recheck sequences-paper/p261108811-3-stealth-thought-no-disclosure.json` | 0 | under 1 s | `stored runs give validated (... matched known-bad: mutant:M2, mutant:M3); stamp agrees` |
| 19 | `admit.py --recheck` on every file with `meta.admission` | 0 | 5 s | 31 files: 21 `validated ... stamp agrees`, 10 `partially-validated` (race ordering not shown) |
| 20 | `python3 -I -m unittest discover -s tools/hunter/tests -p test_hidden_dupes.py` | 0 | 1 s | `Ran 4 tests`, `OK` |
| 21 | `python3 -I tools/hunter/validate.py` and `... --intents-suite` | 0 | under 1 s | `48 valid, 0 invalid`; `2 valid, 0 invalid` |
| 22 | `git status --porcelain` after all of the above | | | empty: no committed file changed |

Counts at this commit: 21 validated, 10 partially validated, 22 unvalidated with a recorded reason
(`evidence/MANIFEST.md`, `tools/admission/unvalidated.json`).

## What this does not show

- **`--recheck` is not proof that a stamp belongs to its file.** A merge review of `attack-admission`
  (this branch's base, 1a39fdb) found that `admit.py --recheck` re-judges the stored runs without checking
  that they belong to the file: it skips the attack id, steps hash and spec hash. A stamp copied from another
  attack, or steps edited after admission, would still print "stamp agrees". Steps 9, 10, 18 and 19 show
  only that each class follows from the runs it points at. The binding of each stamp to its own file is
  shown by step 21: `validate.py` runs `check_admission`, which compares the evidence's `attack_id`,
  `steps_sha256` and `spec_sha256` with the file. The fix to `--recheck` is being made on
  `attack-admission`, not on this branch.
- One machine, not Linux. The full `./verify.sh`, `proofs/run.sh`, `tla/run.sh` and the full mutation
  table were not re-run. M11 was run once, in the worktree (`evidence/mutation-M11-2026-11-12/`).
- The hidden-set runs were not repeated here. The private set is outside the repository, so a clean copy
  cannot run it. Step 11 checks only the public files against the committed hashes.
- No testnet write.
