# arena-receipts

A small NEAR contract where Arena publishes each guard's score under the guard's code fingerprint (sha256 of its wasm). Before handing a guard a key, a wallet, agent or contract can ask: does this guard pass?

```
passes(guard_code_hash, suite, max_beyond_policy, max_against_intent, max_age_ns) -> bool
```

False when there is no receipt, when the newest one is older than `max_age_ns`, or when it is over either limit. Other views: `latest(guard_code_hash, suite)`, `receipts_for(guard_code_hash)`. Only the owner can `publish`, and the publisher pays the storage.

**A receipt proves who published a score and when, and points to the evidence by hash. It does not prove the bench ran unmodified, or that the tests were good.**

**Added 2026-11-11, same contract, upgraded in place** (the receipts and the four methods above are unchanged): guard owners opt in on chain (`opt_in`, `opt_out`, `opt_in_of`, `opt_ins`, `opt_in_count`), and other contracts ask `arena_result(guard_code_hash, suite, arena_commit)` before paying. Results are stored by `publish_result`, bound to the code hash and a clean Arena commit, with an optional `attestation_sha256`. "Held" means the attacks Arena ran found nothing; it never means safe. How to use it: `../docs/ON-CHAIN.md`. Source: `contract/src/onchain.rs`. Example caller: `example-caller/`.

Live on testnet: `receipts.dev-20261109195231-98743803426969.testnet`. Receipts, tx links and results: `../evidence/receipts-testnet-2026-11-10.md`.

| Folder | What |
|---|---|
| `contract/` | the contract (near-sdk 5.27, rustc 1.86 pinned by `rust-toolchain.toml`) |
| `host/` | sandbox tests (`cargo test --release`) and `receipts-cli`, the testnet client `../tools/receipts/publish.py` drives |
| `example-caller/` | a tiny wallet contract that asks `arena_result` before paying (sandbox test only, never deployed) |

Suites in use: `race-double-pay:mode=<mode>`, `injection-scripted`, `injection-scripted-narrow`, `claims-coverage`. Reserved for later: `proof-no-double-pay`, `proof-policy-intent`.
