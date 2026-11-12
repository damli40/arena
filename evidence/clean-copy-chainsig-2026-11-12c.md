# Clean-copy run after the second Chain Signatures review (2026-11-12)

The second review of `cacf4f2..b6cedd0` asked for three fixes (see "Second review" in
`check-chainsig-2026-11-11.md`). They are in commit `828092b`. We exported that commit with
`git archive` into an empty folder, made it a fresh git repo, and ran these one after the other on
one Mac (Apple silicon, macOS), with other builders using the machine at the same time.

| # | Command | Exit | Time | Key line printed |
|---|---|---|---|---|
| 1 | `(cd harness && cargo test --release chainsig)` | 0 | 521 s (cold build) | `12 passed; 0 failed` (new: `a_recorded_unauthorised_request_is_broke_even_with_a_failed_signer_call`) |
| 2 | `python3 -I tools/check/tests/test_check.py` | 0 | 5 s | `Ran 113 tests`, `OK (skipped=1)` (new: `test_recorded_unauthorised_request_is_broke_even_if_a_sign_call_failed`; the skipped one needs the release harness binary, not built yet at that point) |
| 3 | `python3 -I tools/hunter/validate.py --self-test` | 0 | 0 s | `self-test: ok (validator vs schema/attack.schema.json)` |
| 4 | `python3 -I tools/hunter/validate.py --chainsig-suite` | 0 | 0 s | 7 valid, 0 invalid |
| 5 | stand-in offline rebuild, then `shasum -a 256` | 0 | 34 s | both `bd5b79282c34f6ff24bf4ae78a78eb6aa13d1a2f2a2fd6ae4bf1e143478aa9ef` |
| 6 | `./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard.json` | 0 | 445 s | `arena: held 57/57 (...)`, `attacks: 57 held, 0 broke, 0 not applicable, 0 did not finish`, `unauthorised signing requests: 0 (...)` |
| 7 | `./arena check targets/chainsig-planted/chainsig_planted.wasm --config examples/configs/chainsig-guard.json` | 1 | 336 s | `arena: broke 3 of 57 (...; 3 unauthorised signing requests (a count, not an amount); ...)`, and `BROKE chainsig-01-agent-passes-other-payload: 0 tokens beyond the rules; 1 unauthorised signing request (a count, not an amount)`, the same for -02 and -04 |
| 8 | `./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard-wrong-path.json` | 2 | 18 s | `arena: not run`, `COULD NOT FINISH:` |
| 9 | `git status --porcelain` | | | empty |

Same verdicts as before. Only the wording changed ("unauthorised" in place of "outside the owner's
list"). That is expected: neither of our guards signs an unauthorised hash and also makes a failing
sign call.

**What this does not show.** The new rule (a recorded unauthorised request is broke even when
something else failed) did not fire in a sandbox run; only the two unit tests cover it. When it does
fire, the attack's token numbers are not used, but its `paid_outside` and against-intent fields in
`report.json` are still read from the result and are not marked as unreliable.
