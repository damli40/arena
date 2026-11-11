# Clean-copy run of EVALUATE.md (2026-11-11)

What a screener does first: take the repo with no build folders and run the documented commands.
We exported commit `adaa69d` with `git archive` into an empty folder (no `target/`, no reports, no
earlier logs) and ran the commands below on one Mac (Apple silicon, macOS). Rust and the NEAR
sandbox binary were already installed on this machine, so the cold build time does not include
installing Rust.

| # | Command | Exit | Time | Key line printed |
|---|---|---|---|---|
| 1 | `./verify.sh fast` | 0 | 435 s | `verify: 5 passed, 0 failed (mode=fast)` |
| 2 | `./run-arena.sh replay sequences-paper/p210408638-1-reentrancy-async-double-pay.json --target control` | 0 | 16 s | `UNAUTHORISED PAYOUT = 200   (beyond-authorised 200 + above-cap 0)` |
| 3 | the same, `--target vault` | 0 | 15 s | `UNAUTHORISED PAYOUT = 0   (beyond-authorised 0 + above-cap 0)` |
| 4 | `./arena check targets/planted-outflow/planted_outflow.wasm` | 1 | 277 s | `arena: broke 11 of 51 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 1800 tokens paid outside the five receivers; 2450 tokens paid against the owner's intent)` |
| 5 | `./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json` | 0 | 228 s | `arena: held 48/48 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2.45 NEAR paid against the owner's intent; scored from NEAR balances)` |
| 6 | `python3 -I tools/hunter/recheck_attestation.py evidence/hunts/2026-11-11-papers-e3db55.json` | 0 | under 1 s | `recheck: all checks pass (Intel and NVIDIA signatures are not checked offline)` |
| 7 | `python3 -I tools/check/tests/test_check.py` | 0 | 3 s | `Ran 98 tests`, `OK` |
| 8 | `python3 -I -m unittest discover -s tools/hunter/tests` | 0 | 1 s | `Ran 77 tests`, `OK` |
| 9 | `node --test tools/lookup/test.mjs` (live testnet tests included) | 0 | 5 s | `pass 37`, `fail 0` |
| 10 | `node tools/lookup/cli.mjs r11cfx4-guard.arena-race-funder-1111.testnet` | 0 | 2 s | `status:    held` and `on chain:  held` |
| 11 | `(cd receipts && cargo build --release --target wasm32-unknown-unknown) && (cd receipts/host && cargo test --release --test onchain)` | 0 | 143 s | `3 passed; 0 failed; 1 ignored` |
| 12 | `ARENA_AGENT=compromised python3 -I tools/injection/run.py && python3 -I tools/injection/rescore.py` | 0 | 78 s | `Check: recomputed wrong-payment totals match the intent_leak recorded at run time (0 mismatches).` |

Every exit code and every key line matched what `EVALUATE.md` says.

## What this does not cover

- Not a different machine, not Linux, not GitHub's runners. Rust and the sandbox were already
  installed here.
- Not run here: the full `./verify.sh` (943 to 965 s in earlier runs), `proofs/run.sh`,
  `tla/run.sh`, and the full mutation table. The full mutation table was re-run the same night in
  the working copy (2,410 s) and matched `evidence/mutation-2026-11-11/summary.tsv` row for row.
- Commits after `adaa69d` change the publish tool (results only for Arena's own guards), the docs
  and the lookup page's saved examples. They do not change the commands above.
- No other person or coding agent has run this yet.
