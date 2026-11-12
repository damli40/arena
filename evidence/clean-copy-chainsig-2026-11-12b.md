# Clean-copy run after the Chain Signatures review fixes (2026-11-12)

The merge review of `cacf4f2` asked for three fixes (see "Corrections" in
`check-chainsig-2026-11-11.md`). They are in commit `dc68116`. We exported that commit with
`git archive` into an empty folder, made it a fresh git repo, and ran the chainsig checks one after
the other on one Mac (Apple silicon, macOS). Other builders were using the machine at the same time.

| # | Command | Exit | Time | Key line printed |
|---|---|---|---|---|
| 1 | `(cd harness && cargo test --release chainsig)` | 0 | 836 s (cold build) | `11 passed; 0 failed` (7 before the fixes, plus 4 new: outsider-caused request counted, a request no step accounts for is invalid, the trace reads causes and failed stand-in calls, `seq.rs` still calls `note_executors`) |
| 2 | `python3 -I tools/check/tests/test_check.py` | 0 | 11 s | `OK (skipped=1)`: the skipped test needs the release harness binary, which this order had not built yet |
| 3 | `python3 -I tools/hunter/validate.py --self-test` | 0 | 0 s | `self-test: ok (validator vs schema/attack.schema.json)` |
| 4 | `python3 -I tools/hunter/validate.py --chainsig-suite` | 0 | 0 s | `validated 7 attack files: 7 valid, 0 invalid` |
| 5 | `(cd contracts/signer-standin && cargo build --release --target wasm32-unknown-unknown --offline)` then `shasum -a 256` | 0 | 104 s | rebuilt and committed `signer_standin.wasm` both `bd5b79282c34f6ff24bf4ae78a78eb6aa13d1a2f2a2fd6ae4bf1e143478aa9ef` |
| 6 | `./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard.json` | 0 | 681 s | `arena: held 57/57 (...)`, `attacks: 57 held, 0 broke, 0 not applicable, 0 did not finish` |
| 7 | `./arena check targets/chainsig-planted/chainsig_planted.wasm --config examples/configs/chainsig-guard.json` | 1 | 326 s | `arena: broke 3 of 57 (...; 3 signing requests outside the owner's list (a count, not an amount); ...)`, BROKE chainsig-01, -02, -04 |
| 8 | `./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard-wrong-path.json` | 2 | 17 s | `arena: not run`, `COULD NOT FINISH:` |
| 9 | `git status --porcelain` after all of the above | | | empty |

Same headlines as before the fixes. That is expected: both our guards refuse a request from the
outsider, and neither makes a request the stand-in refuses.

**What the "0 did not finish" shows.** After the fix, a guard request that no step's transaction
accounts for makes the attack "could not finish". Both guards made signing requests in many attacks
(the preflight and every allowed signing), and none ended "did not finish". So Arena traced every one
of those requests back to the step that caused it.

**What this does not show.** Neither new path fired in a sandbox run. No guard here signs for the
outsider, and no guard here makes a request the stand-in refuses. Unit tests cover both paths
(test 1). The honest check took 681 s against 343 s before the fixes, with the machine shared; we did
not re-time it on an idle machine. The stand-in's accept/refuse rules are our reading of the real
`v1.signer` (the coordinator's review, citing `near/mpc` `crates/near-mpc-crypto-types/src/sign.rs`);
we did not re-read that file ourselves.
