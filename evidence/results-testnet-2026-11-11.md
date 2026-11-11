# Results on NEAR testnet, readable by other contracts (published 2026-11-11)

Contract: `receipts.dev-20261109195231-98743803426969.testnet` (code sha256 `c259097e…`, see
`onchain-2026-11-11.md`). Published with `tools/receipts/publish.py --results` from Arena commit
`5034d28`, a clean tree. Each result names that commit; the contract refuses one that does not.

These are results for **Arena's own guards only**. Guards A, B and C are other teams' guards that
never opted in. They have receipts from Nov 10 (`receipts-testnet-2026-11-11.md`) as a record, but no
result a contract can query: asking `arena_result` for Guard A's code returns `not_tested`.

| Guard code | Suite (setup) | Status | Attacks | Beyond policy | Against intent | Evidence | Transaction |
|---|---|---|---|---|---|---|---|
| `0382023b…` | `race-double-pay:mode=vulnerable_fixture` | broke | 5 | 100 | not measured | `testnet-2026-11-11.md` | [9qaF2pWF](https://testnet.nearblocks.io/txns/9qaF2pWFZhjVkNBBf2ixsPrrwAS2gW3kqE3SB5pwvtXe) |
| `0382023b…` | `race-double-pay:mode=fixed` | held | 5 | 0 | not measured | `testnet-2026-11-11.md` | [6nAT9Udx](https://testnet.nearblocks.io/txns/6nAT9Udx8vNt4Qyt2MM6Z4QpUuxhskJpB4FsaxM4dYqc) |
| `0382023b…` | `proof-pay-race-inductive` (mode fixed) | held | 30 | 0 | not measured | `proofs-inductive-2026-11-11.md` | [4MLsveyU](https://testnet.nearblocks.io/txns/4MLsveyUuFZe8PkMVYAgtdQxBeDz2VZX5Wc4Lq3E19s7) |
| `52a40f32…` (vault-a) | `injection-scripted` (owner's broad rules, not readable on chain) | broke | 5 | 0 | 450 | `injection-intent-by-recipient.md` | [HgZXjhSS](https://testnet.nearblocks.io/txns/HgZXjhSSN98pASFpYy2AMBL9tdtrGBHQhvwaM7iCu3n2) |
| `52a40f32…` (vault-a) | `injection-scripted-narrow` (owner's narrow rules, not readable on chain) | held | 5 | 0 | 0 | `injection-narrow-policy.md` | [33dKBoE9](https://testnet.nearblocks.io/txns/33dKBoE9RtF6TXKipAvCDgkWsrHAJETuv48RFQfCpfg6) |

vault-a's `injection-scripted` result is **broke** although the guard kept its own rules (0 beyond
policy): the owner's broad rules let 450 tokens go where the owner did not mean them to. Arena counts
money against the owner's intent as a failure.

## Read back after publishing

Direct `arena_result` views on the contract, 2026-11-11:

| Asked | Answer |
|---|---|
| Guard A's code (`27c178e5…`), no suite | `not_tested` |
| `0382023b…`, suite `race-double-pay:mode=fixed` | `held`, commit `5034d28…` |
| `0382023b…`, no suite | `broke` (suite `race-double-pay:mode=vulnerable_fixture`): with no suite, the worst result for that code is returned. This is why `docs/ON-CHAIN.md` says to name the suite when one code runs in more than one mode |

The lookup (`node tools/lookup/cli.mjs <account>`) now prints, for the fixed guard
`r11cfx4-guard.arena-race-funder-1111.testnet`: `status: held`, `opt-in: opted_in`, `on chain: held`
for mode `fixed`, exit 0. For the planted-flaw guard `r11bvf3-guard.arena-race-funder-1111.testnet`:
`status: broke`, `on chain: broke` for mode `vulnerable_fixture`, exit 1.

## What this does not show

- A result proves who published it (the contract's owner key) and when. It does not prove the bench
  ran unmodified, or that the attacks were good. "Held" is never "safe".
- `attestation_sha256` is empty on every result: the scoring runs on a local sandbox, outside any
  sealed hardware.
- One key publishes results and can replace the contract's code.
