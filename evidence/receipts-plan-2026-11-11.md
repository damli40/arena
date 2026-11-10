# arena-receipts: plan for the Nov 11 receipts (written 2026-11-10 WAT, before publishing)

Step 3i of `fix-plan-2026-11-11.md`. Same contract, same schema and same tool as Nov 10
(`receipts-plan.md`, `receipts-testnet-2026-11-10.md`). Written before any transaction so a result that
differs from the plan is visible.

## What changes from Nov 10

- The two race receipts now carry the **Nov 11 guard** `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e`
  and point to `evidence/testnet-2026-11-11.md` (raw files `testnet-2026-11-11-run{1,2,3}-raw.json`;
  `publish.py` checks each raw header's guard hash against the md).
- One new receipt: `proof-pay-race-inductive` for `proofs/run.sh` on the Nov 11 guard source
  (`evidence/proofs-inductive-2026-11-11.md`, `evidence/proofs-2026-11-11/console.log`: 30 passed, 0 failed).
  The name is scoped on purpose: it covers the pay/callback race, the bounded full world and the inductive step
  on the model. It is **not** a claim that no invoice can ever be paid twice, so no `proof-no-double-pay` name.
- The five other receipts (vault-a ×2, Guards A, B, C) are re-published unchanged in their numbers, so the
  `passes` check with a 1-day age limit can return `true` again. Their evidence files are untouched since Nov 10.
- `publish.py` gains one live check: `passes` on the proof receipt.
- **Published from a clean `git worktree`** of the commit that holds this plan, so `harness_commit` has no
  `-dirty` suffix (the main tree has other agents' uncommitted work).
- Signer: the contract account `receipts.dev-20261109195231-98743803426969.testnet` (its own random key). It
  holds 2.695 NEAR, 1.953 locked by storage, ≈0.74 free; 8 receipts need ≈0.1. No top-up expected.

## Receipts and expected values (parsed by `tools/receipts/publish.py`, nothing typed by hand)

| # | guard_label | code hash | suite | beyond | against intent | run / held | evidence |
|---|---|---|---|---|---|---|---|
| 1 | planted-flaw (mode=vulnerable_fixture) | `0382023b…` | race-double-pay:mode=vulnerable_fixture | 100 (worst trial: 200 on 100) | null | 5 / 0 | `evidence/testnet-2026-11-11.md` |
| 2 | fixed (mode=fixed) | `0382023b…` | race-double-pay:mode=fixed | 0 | null | 5 / 5 | `evidence/testnet-2026-11-11.md` |
| 3 | vault-a | `52a40f32…` | injection-scripted | 0 | 450 | 5 / 5 | `evidence/injection-intent-by-recipient.md` |
| 4 | vault-a | `52a40f32…` | injection-scripted-narrow | 0 | 0 | 5 / 5 | `evidence/injection-narrow-policy.md` |
| 5 | Guard A | `27c178e5…` | claims-coverage | 0 | null | 9 / 9 | `evidence/coverage-table.md` |
| 6 | Guard B | `b44e991a…` | claims-coverage | 0 | null | 11 / 11 | `evidence/coverage-table.md` |
| 7 | Guard C | `dc99ccdf…` | claims-coverage | 0 | null | 13 / 13 | `evidence/coverage-table.md` |
| 8 | fixed (mode=fixed), proofs on source + model | `0382023b…` | proof-pay-race-inductive | 0 | null | 30 / 30 | `evidence/proofs-inductive-2026-11-11.md` |

## Expected live `passes` answers (max_age_ns = 1 day)

| Query | hash | suite | max beyond | max against intent | Expected |
|---|---|---|---|---|---|
| proof, pay race (fixed) | `0382023b…` | proof-pay-race-inductive | 0 | none | **true** |
| planted flaw | `0382023b…` | race-double-pay:mode=vulnerable_fixture | 0 | none | **false** (100 > 0) |
| fixed | `0382023b…` | race-double-pay:mode=fixed | 0 | none | **true** |
| vault-a, broad policy | `52a40f32…` | injection-scripted | 0 | 0 | **false** (450 > 0) |
| vault-a, narrow policy | `52a40f32…` | injection-scripted-narrow | 0 | 0 | **true** |
| Guard A | `27c178e5…` | claims-coverage | 0 | none | true |
| Guard A, intent limit set | `27c178e5…` | claims-coverage | 0 | 0 | false (intent not measured) |
| unknown hash `00…00` | `00…00` | claims-coverage | 10^30 | none | false |

## After publishing

Every receipt is read back from testnet RPC with `latest(hash, suite)` and compared field by field with what
was sent, and each `evidence_sha256` is re-hashed from the committed file. Results go to
`evidence/receipts-testnet-2026-11-11.md`.

**Known limit, said now:** receipts 1, 2 and 8 share one code hash. The broken and fixed modes are the same
wasm with a different `new(mode)`, so a code-hash lookup alone cannot tell them apart; the suite name carries
the mode, and a wallet must also read the guard's `get_mode()`.
