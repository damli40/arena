# Clean-copy run of the Chain Signatures branch (2026-11-12)

Before merging the `chain-signatures` branch, we exported commit `6f27e2a` with `git archive` into an
empty folder (no `target/`, no reports, no earlier logs, no private files), made it a fresh git
repo, and ran the checks below one after the other on one Mac (Apple silicon, macOS). Rust and the
NEAR sandbox binary were already installed. No network was needed, apart from what `verify.sh` and
the sandbox already use locally. Other builders were compiling and running sandboxes on the same
machine at the same time, so the times are slower than an idle machine (see the note under the table).

The commit after it (`5d898e8`) changed only docs and evidence files, no code.

| # | Command | Exit | Time | Key line printed |
|---|---|---|---|---|
| 1 | `python3 -I -m unittest discover -s tools/hunter/tests` (cold) | 0 | 3 s | `Ran 79 tests`, `OK` |
| 2 | `./verify.sh fast` | 0 | 1,947 s | `verify: 5 passed, 0 failed (mode=fast)` |
| 3 | `(cd harness && cargo test --release)` | 0 | 323 s | `69 passed; 0 failed; 1 ignored` |
| 4 | `python3 -I tools/check/tests/test_check.py` | 0 | 14 s | `Ran 112 tests`, `OK` |
| 5 | `python3 -I -m unittest discover -s tools/hunter/tests` (warm) | 0 | 17 s | `Ran 79 tests`, `OK` |
| 6 | `node --test tools/lookup/test.mjs` | 0 | 7 s | `pass 37`, `fail 0` |
| 7 | `python3 -I tools/hunter/validate.py --chainsig-suite` | 0 | 1 s | `validated 7 attack files: 7 valid, 0 invalid` |
| 8 | `python3 -I tools/hunter/validate.py --self-test` | 0 | 0 s | `self-test: ok (validator vs schema/attack.schema.json)` |
| 9 | `./arena check targets/vault-a/vault_a.wasm` | 0 | 321 s | `arena: held 51/51 (0 not applicable; ...; 2450 tokens paid against the owner's intent)` |
| 10 | `./arena check targets/leaky-control-v2/leaky_control.wasm` | 1 | 326 s | `arena: broke 5 of 51 (...)`; the same 5 attacks as `check-2026-11-11/leaky-control-v2.console.txt` |
| 11 | `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json` | 0 | 513 s | `arena: held 53/53 (...; pays via NEAR Intents: local release build, no withdrawals to other chains)` |
| 12 | `./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json` | 1 | 484 s | `arena: broke 2 of 53 (...; 300 tokens paid outside the five receivers; ...)` |
| 13 | `./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json` | 0 | 242 s | `arena: held 48/48 (...; scored from NEAR balances)` |
| 14 | `./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard.json` | 0 | 343 s | `arena: held 57/57 (...; signs via Chain Signatures: Arena's stand-in signer, no real MPC signing, nothing sent to another chain)` |
| 15 | `./arena check targets/chainsig-planted/chainsig_planted.wasm --config examples/configs/chainsig-guard.json` | 1 | 356 s | `arena: broke 3 of 57 (...; 3 signing requests outside the owner's list (a count, not an amount); ...)`, BROKE lines for chainsig-01, -02 and -04 |
| 16 | `./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard-wrong-path.json` | 2 | 18 s | `arena: not run`, `COULD NOT FINISH:` (the preflight saw the guard sign with a path the config did not declare) |
| 17 | `(cd contracts/signer-standin && cargo build --release --target wasm32-unknown-unknown --offline)` then `shasum -a 256` | 0 | 62 s | rebuilt and committed `signer_standin.wasm` both `fa83ea44877151bb070d6dcf75b6b8ab8eee8f6d486e14a05ea61b1a910956c1` |
| 18 | `git status --porcelain` after all of the above | | | empty: no tracked file changed, no untracked file left outside ignored folders |

Every result matches the saved runs: vault-a, leaky, intents and native-fixed give the same
headlines as `clean-copy-intents-2026-11-11.md`, and the chainsig results match
`check-chainsig-2026-11-11.md`. Rebuilding the stand-in signer offline from source gives the same
bytes as the committed file.

**About the times.** `verify.sh fast` took 1,947 s here, against 433 s on the Nov 11 clean copy, and
cargo test 323 s against 16 s. Both start with a cold build in a new folder, and on this run several
other builds and sandboxes were running on the machine at the same time (seen in `ps`). The
`arena check` times (242 to 513 s) are close to the earlier ones, except Intents (about 500 s against
about 310 s). We did not re-time on an idle machine.

**What this does not show.** Same machine, same installed toolchain, macOS only. Not run on Linux
or on GitHub. Nothing here touches testnet or mainnet.
