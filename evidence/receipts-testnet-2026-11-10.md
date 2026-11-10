# arena-receipts on NEAR testnet (Nov 10 2026)

> **Note added 2026-11-11.** These receipts carry the OLD guard hash (`fcce82bf…`). No receipt exists yet for the Nov 11 guard (`0382023b…`): it needs a new testnet race first, which is blocked on testnet NEAR (`fix-plan-2026-11-11.md`, 3h/3i). `tools/receipts/publish.py` now takes `--race-md` / `--race-raw` for that run. `testnet-2026-11-09.md` itself carries no note on purpose: these receipts commit to its sha256 (`665779ca…`).

**Result.** 7 receipts published. 7 of 7 live `passes` calls returned what the plan (`evidence/receipts-plan.md`, written before deploy) expected. The planted-flaw guard fails (`false`), the fixed guard passes (`true`); vault-a fails with an intent limit of 0 under the broad policy and passes under the narrow one.

**A receipt proves who published a score and when, and points to the evidence by hash. It does not prove the bench ran unmodified, or that the tests were good.**

- **Contract:** [`receipts.dev-20261109195231-98743803426969.testnet`](https://testnet.nearblocks.io/address/receipts.dev-20261109195231-98743803426969.testnet). A sub-account of the Nov 9 funder, funded with 2.7 testnet NEAR from it, new random key (kept outside the repo, never printed). It is its own owner, so it signs `publish`.
- **Code on chain:** sha256 `aba31658ad84fbd5acdc8f694446b63ead1bb482abb726e65b9d9b3c11e13480` (read back with `view_code`, matches `receipts/target/.../arena_receipts.wasm`).
- **Deploy txs:** [create](https://testnet.nearblocks.io/txns/A7YJc54ojRUY4xCJhGS19w79VZZv1NSVsXuEvTKnc4s4), [deploy](https://testnet.nearblocks.io/txns/HeXGRNVAYXJ1L98sNxdDxPydgsWazpQh7CSTuze3T5gA), [new](https://testnet.nearblocks.io/txns/2Vnfmmx8JRnsrHp1kZoap24zJriXkZZFB2EYpH3zuEm2), [redeploy](https://testnet.nearblocks.io/txns/6WtrxToRDZJLs49h6cuAZ8pBxtC8FtQb5VPQoHjbFeUi). Log: `receipts-testnet-2026-11-10-deploy.log`.
- **One change after publishing, said plainly:** the receipts were published by a first build (sha256 `2843fd96…`) that also had an `owner()` view. Per the scope note (four methods only), I removed it and redeployed the code in place. Stored receipts were kept (same state layout), and all 7 checks were re-run on the new code with the same results.

## Receipts

Numbers are parsed from the evidence files by `tools/receipts/publish.py`, never typed. `harness_commit` = `6a5ba7d4…-dirty` (the tree had uncommitted changes, including the untracked narrow-policy evidence), so the evidence hash, not the commit, is what pins the file.

| Guard | Suite | Code hash | Beyond policy | Against intent | Run / held | Evidence | Tx |
|---|---|---|---|---|---|---|---|
| planted-flaw (mode=vulnerable_fixture) | race-double-pay:mode=vulnerable_fixture | `fcce82bf9bad…` | 100 | not measured | 5 / 0 | `evidence/testnet-2026-11-09.md` | [Bd8RrTiW](https://testnet.nearblocks.io/txns/Bd8RrTiWS3Pc6XxS8iRcRpZoio8HZPjhw3ZyYDhj89RC) |
| fixed (mode=fixed) | race-double-pay:mode=fixed | `fcce82bf9bad…` | 0 | not measured | 5 / 5 | `evidence/testnet-2026-11-09.md` | [76eNYghQ](https://testnet.nearblocks.io/txns/76eNYghQggAzy6ycX8srDCeL76KWFkBUjRh8s8LFzHoW) |
| vault-a | injection-scripted | `52a40f3200e3…` | 0 | 450 | 5 / 5 | `evidence/injection-intent-by-recipient.md` | [8bKFEjxJ](https://testnet.nearblocks.io/txns/8bKFEjxJeUMUAVvF4JRwzB9sJAbv7174J2KKmfL2TYpM) |
| vault-a | injection-scripted-narrow | `52a40f3200e3…` | 0 | 0 | 5 / 5 | `evidence/injection-narrow-policy.md` | [gx5NoMTU](https://testnet.nearblocks.io/txns/gx5NoMTU82jJasa5nrkXQDJskqeGMujWyMUvaHnB3Uh) |
| Guard A | claims-coverage | `27c178e572db…` | 0 | not measured | 9 / 9 | `evidence/coverage-table.md` | [HmY3cpSc](https://testnet.nearblocks.io/txns/HmY3cpSc4x9np6s63cXEwq2Tdm76wiEZvGBEovZXr5gL) |
| Guard B | claims-coverage | `b44e991a469b…` | 0 | not measured | 11 / 11 | `evidence/coverage-table.md` | [AYnru69P](https://testnet.nearblocks.io/txns/AYnru69PzpuSj6CQG5ViEVsQYepHdzU9oa2gRTNNrX7o) |
| Guard C | claims-coverage | `dc99ccdfc57a…` | 0 | not measured | 13 / 13 | `evidence/coverage-table.md` | [7pNUNdow](https://testnet.nearblocks.io/txns/7pNUNdowfj7VgEueDwJcXVxb9QVVv8C3xVH95n8vgnAY) |

Race "beyond policy" is the worst single trial (paid 200 on a 100 invoice). Guard B's unit is milliNEAR. Full receipts, with evidence hashes and timestamps: `receipts-testnet-2026-11-10-publish.log`.

## Live `passes` calls (max_age_ns = 1 day)

| Query | max beyond | max against intent | Result | Expected |
|---|---|---|---|---|
| planted flaw | 0 | none | **false** | false |
| fixed | 0 | none | **true** | true |
| vault-a, broad policy | 0 | 0 | **false** | false |
| vault-a, narrow policy | 0 | 0 | **true** | true |
| Guard A | 0 | none | true | true |
| Guard A | 0 | 0 | false (intent not measured) | false |
| unknown hash `00…00` | 10^30 | none | false | false |

Log: `receipts-testnet-2026-11-10-check.log`. Sandbox tests: 2 of 2 pass (`receipts-sandbox-tests-2026-11-10.log`): owner publishes, non-owner refused, no-deposit refused, excess deposit refunded, `passes` true/false on both limits, max age, newest receipt wins, unknown hash and suite false, malformed hash refused.

## Reproduce

```
cd receipts && cargo build --release --target wasm32-unknown-unknown       # pinned rustc 1.86, near-sdk 5.27
shasum -a 256 target/wasm32-unknown-unknown/release/arena_receipts.wasm   # aba31658...
cd host && cargo test --release && cd ../..                              # sandbox tests, near-workspaces 0.24
python3 -I tools/receipts/publish.py --dry-run                            # the 7 receipts, parsed from evidence/
python3 -I tools/receipts/publish.py --contract receipts.dev-20261109195231-98743803426969.testnet --check
```

`--check` sends no transaction. Its `max_age_ns` is 1 day, so from Nov 11 the two `true` rows turn `false` until fresh receipts are published: that is the age rule working. Publishing (drop `--check`) needs the contract's key in `~/.near-credentials/testnet/`.

## Limits

- **Who and when, not how.** The contract stores what the owner key sent. Nothing on chain checks that the bench ran unmodified, that the numbers match the evidence file, or that the tests were good. Anyone can re-hash the evidence file and compare, which catches a later edit, not a false original.
- **One key decides.** The owner is a single full-access testnet key; it can publish any number and replace the contract code (as it did once, above). A TEE-attested version, where hardware signs what the bench ran, is future work.
- **A code hash does not pin configuration.** The planted-flaw and fixed receipts share one wasm hash; the mode is chosen at `new(mode)`. The suite name carries the mode, and a wallet must also read the guard's `get_mode()`. Other guards may have similar init-time settings (vault-a's policy is set by its owner after deploy).
- **Same limits as the evidence.** Guards A, B, C and vault-a were tested on a local sandbox, not testnet; only the race ran on testnet.
- **Room for proofs, nothing published.** Suites `proof-no-double-pay` and `proof-policy-intent` are reserved for the proofs in `proofs/`. No receipt exists for them yet.
- **Testnet only.** No mainnet, no real funds.
