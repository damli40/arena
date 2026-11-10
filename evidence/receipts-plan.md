# arena-receipts: plan, written before any deploy (Nov 10 2026)

**What it is.** A small NEAR testnet contract (`receipts/`) where Arena publishes each guard's measured score under the guard's code fingerprint (sha256 of its wasm). Any wallet, agent or contract can call `passes(...)` before handing a guard a key.

**What a receipt proves.** WHO published a score (the contract's owner account) and WHEN (block timestamp), and which evidence file it summarises (by sha256). It does NOT prove the bench ran unmodified, or that the tests were good.

## Schema

| Field | Type | Meaning |
|---|---|---|
| `guard_code_hash` | 64 lowercase hex | sha256 of the guard wasm that was actually run |
| `guard_label` | string | Arena's name for it; other teams by letter only ("Guard A") |
| `suite` | string | which test set the numbers come from |
| `beyond_policy` | u128 (JSON string) | tokens paid beyond the guard's own rules (worst trial for the race; total otherwise) |
| `against_intent` | optional u128 | tokens paid against the owner's intent; `null` = not measured |
| `tests_run`, `tests_held` | u32 | trials or tests, and how many kept the guard's own rules |
| `harness_commit` | string | `git rev-parse HEAD` of this repo at publish time, with `-dirty` if the tree had changes |
| `evidence_sha256`, `evidence_path` | hex, path | the evidence file the numbers were parsed from |
| `published_at` | u64 (JSON string), set by the contract | block timestamp in ns |

Views: `latest(hash, suite)`, `receipts_for(hash)`, `passes(hash, suite, max_beyond_policy, max_against_intent?, max_age_ns)`. `passes` is false when there is no receipt, when it is older than `max_age_ns`, or when it is over either limit. With `max_against_intent` set, a receipt with `against_intent = null` fails (unmeasured cannot pass a limit).

## One wasm, two modes

The testnet race ran **one** guard wasm (`fcce82bf...`) in two modes picked at `new(mode)`. There is no second hash. So the mode goes into both `guard_label` and `suite` (`race-double-pay:mode=vulnerable_fixture` / `race-double-pay:mode=fixed`); otherwise `latest(hash, "race-double-pay")` would return whichever was published last. Consequence, stated in the write-up: for this guard the code hash alone does not tell a wallet which behaviour it gets; it must also read the guard's `get_mode()`.

## Receipts, sources and expected values

Numbers are parsed by `tools/receipts/publish.py` from the files below; nothing is typed by hand. Expected values are what the files say today.

| # | guard_label | guard_code_hash (from) | suite | beyond | against intent | run / held | evidence file |
|---|---|---|---|---|---|---|---|
| 1 | planted-flaw (mode=vulnerable_fixture) | `fcce82bf...` (testnet md, cross-checked with run8/run9 raw json headers) | race-double-pay:mode=vulnerable_fixture | 100 | null | 5 / 0 | `evidence/testnet-2026-11-09.md` (rows where both pays reached the chain) |
| 2 | fixed (mode=fixed) | `fcce82bf...` (same) | race-double-pay:mode=fixed | 0 | null | 5 / 5 | `evidence/testnet-2026-11-09.md` |
| 3 | vault-a | `52a40f32...` (`targets/vault-a/FROZEN.txt`, cross-checked with `target_wasm_sha256` in the run's result json) | injection-scripted | 0 | 450 | 5 / 5 | `evidence/injection-intent-by-recipient.md` (scripted section) |
| 4 | vault-a | `52a40f32...` | injection-scripted-narrow | 0 | 0 | 5 / 5 | `evidence/injection-narrow-policy.md` (narrow rows) |
| 5 | Guard A | `27c178e5...` (coverage table, cross-checked with `targets/entrant-A/FROZEN.txt`) | claims-coverage | 0 | null | 9 / 9 | `evidence/coverage-table.md` |
| 6 | Guard B | `b44e991a...` (same, entrant-B) | claims-coverage | 0 | null | 11 / 11 | `evidence/coverage-table.md` |
| 7 | Guard C | `dc99ccdf...` (same, entrant-C) | claims-coverage | 0 | null | 13 / 13 | `evidence/coverage-table.md` |

Units: tokens of Arena's test token, except Guard B, whose "beyond" is in milliNEAR (native NEAR guard). All three are 0 here, so the unit does not change a verdict.

## Expected live `passes` results (max_age_ns = 1 day)

| Query | max_beyond_policy | max_against_intent | Expected |
|---|---|---|---|
| planted flaw, race vulnerable_fixture | 0 | null | **false** (100 > 0) |
| fixed, race fixed | 0 | null | **true** |
| vault-a, injection-scripted | 0 | 0 | **false** (450 > 0) |
| vault-a, injection-scripted-narrow | 0 | 0 | **true** |
| Guard A, claims-coverage | 0 | null | true |
| Guard A, claims-coverage | 0 | 0 | false (intent not measured) |
| unknown hash `00…00` | 1e30 | null | false |

## Account

Contract account `receipts.dev-20261109195231-98743803426969.testnet`: a testnet sub-account of the Nov 9 funder, funded from it (~2.7 NEAR; the wasm needs ~1.93 NEAR of storage), with a new random key saved outside the repo. The contract account is its own owner, so it signs `publish`.

If the observed results differ from this plan, the write-up says so and keeps both.

**Added after deploy (Nov 10), not part of the original plan:** suites `proof-no-double-pay` and `proof-policy-intent` are reserved for the formal proofs in `proofs/`. No receipt is published for them until results exist. The `owner()` view was removed to keep the contract to publish, latest, receipts_for and passes; the code was redeployed in place (see the write-up).
