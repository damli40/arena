# arena-receipts on NEAR testnet, Nov 11 guard (published 2026-11-10 16:10 UTC)

**Result.** 8 receipts published, 8 of 8 transactions succeeded. 8 of 8 live `passes` calls returned what the
plan (`receipts-plan-2026-11-11.md`, committed before publishing) expected. Re-read straight from testnet RPC,
8 of 8 receipts match what was sent field by field, and every `evidence_sha256` matches the committed file.

In plain words: anyone can now ask the testnet contract "did the guard with code `0382023b…` hold the pay race?"
and get **yes** for the fixed mode, **no** for the planted-flaw mode, and **yes** for the proof run, each pointing
to the evidence file by its hash.

**A receipt proves who published a score and when, and points to the evidence by hash. It does not prove the
bench ran unmodified, or that the tests were good.**

- **Contract:** [`receipts.dev-20261109195231-98743803426969.testnet`](https://testnet.nearblocks.io/address/receipts.dev-20261109195231-98743803426969.testnet), same as Nov 10, code unchanged (`aba31658…`). Signed by its own random key. It paid its own gas and storage: 2.6951 → 2.6928 NEAR. No top-up.
- **harness_commit:** `86ccccdfff54def98bcc89a0615cd471da040c83`, **not dirty**: published from a clean `git worktree` of that
  commit (the main tree had other agents' uncommitted work). The worktree was removed afterwards.
- **Command** (run inside the worktree):
  `python3 -I tools/receipts/publish.py --contract receipts.dev-20261109195231-98743803426969.testnet --with-proof --race-md testnet-2026-11-11.md --race-raw testnet-2026-11-11-run1-raw.json testnet-2026-11-11-run2-raw.json testnet-2026-11-11-run3-raw.json`
- Logs: `receipts-testnet-2026-11-11-publish.log` (sent receipts, tx hashes, live checks),
  `receipts-testnet-2026-11-11-reread.log` (independent re-read).

## Receipts

| Guard | Suite | Code hash | Beyond policy | Against intent | Run / held | Evidence | Tx | Re-read |
|---|---|---|---|---|---|---|---|---|
| planted-flaw (mode=vulnerable_fixture) | race-double-pay:mode=vulnerable_fixture | `0382023bed12…` | 100 | not measured | 5 / 0 | `evidence/testnet-2026-11-11.md` (`312cd0cd…`) | [BFhjD3wr](https://testnet.nearblocks.io/txns/BFhjD3wrZafHa3ZJTsoAv5mtkg4eSnWKb7phxv6W2ypS) | matches |
| fixed (mode=fixed) | race-double-pay:mode=fixed | `0382023bed12…` | 0 | not measured | 5 / 5 | `evidence/testnet-2026-11-11.md` | [92oZhohu](https://testnet.nearblocks.io/txns/92oZhohuHcH73HBDUQfp55ApXMnFMMEUoUVRKmoht949) | matches |
| vault-a | injection-scripted | `52a40f3200e3…` | 0 | 450 | 5 / 5 | `evidence/injection-intent-by-recipient.md` | [ALorMpxw](https://testnet.nearblocks.io/txns/ALorMpxwMBYxKuBbMsvNGxHMAzMY2atbLc37vA1qV7BG) | matches |
| vault-a | injection-scripted-narrow | `52a40f3200e3…` | 0 | 0 | 5 / 5 | `evidence/injection-narrow-policy.md` | [9JGV6KUQ](https://testnet.nearblocks.io/txns/9JGV6KUQW3zJzXs9ZyXs1Y2xHgHV9peKs6YQ2gPxG4qH) | matches |
| Guard A | claims-coverage | `27c178e572db…` | 0 | not measured | 9 / 9 | `evidence/coverage-table.md` | [AvmByZzR](https://testnet.nearblocks.io/txns/AvmByZzRNQWFzSJLVxBHzVRdCWF5Z2Mjan81Y8wcqXQv) | matches |
| Guard B | claims-coverage | `b44e991a469b…` | 0 | not measured | 11 / 11 | `evidence/coverage-table.md` | [4KQxfUJ3](https://testnet.nearblocks.io/txns/4KQxfUJ3AbUJVs2HS5xm3huaN9whxeh2LZcp9J3Eey56) | matches |
| Guard C | claims-coverage | `dc99ccdfc57a…` | 0 | not measured | 13 / 13 | `evidence/coverage-table.md` | [8c2WYcso](https://testnet.nearblocks.io/txns/8c2WYcsod9BzuXJT5D6jpLPJtmxRs93PmKnhNcqL2K4f) | matches |
| fixed (mode=fixed), proofs on source + model | proof-pay-race-inductive | `0382023bed12…` | 0 | not measured | 30 / 30 | `evidence/proofs-inductive-2026-11-11.md` (`3df396b1…`) | [Gc13udsQ](https://testnet.nearblocks.io/txns/Gc13udsQVQJ4Yn1vX5wRLgdiWeejvHZ3ivW3STyAAqvd) | matches |

Race "beyond policy" is the worst single trial (paid 200 on a 100 invoice). Guard B's unit is milliNEAR. The
vault-a and Guard A/B/C receipts repeat the Nov 10 numbers from unchanged files; they were re-published so the
1-day age check can return `true` again.

## Live `passes` calls (max_age_ns = 1 day)

| Query | max beyond | max against intent | Result | Expected |
|---|---|---|---|---|
| proof, pay race (fixed), `0382023b…` | 0 | none | **true** | true |
| planted flaw, `0382023b…` | 0 | none | **false** | false |
| fixed, `0382023b…` | 0 | none | **true** | true |
| vault-a, broad policy | 0 | 0 | **false** | false |
| vault-a, narrow policy | 0 | 0 | **true** | true |
| Guard A | 0 | none | true | true |
| Guard A | 0 | 0 | false (intent not measured) | false |
| unknown hash `00…00` | 10^30 | none | false | false |

**Re-read, outside the publish tool.** A separate script called `latest(guard_code_hash, suite)` for each receipt
directly on `rpc.testnet.fastnear.com` (not through `receipts-cli`), compared every sent field, and re-hashed each
`evidence_path` from the committed tree: 8 of 8 match.

## Limits

- **One wasm, two modes: a code-hash lookup alone cannot tell them apart.** The planted-flaw receipt, the fixed
  receipt and the proof receipt all carry `0382023b…`. The mode is chosen at `new(mode)`, not compiled in. The
  suite name carries the mode, so `passes(hash, "race-double-pay:mode=fixed", …)` and
  `passes(hash, "race-double-pay:mode=vulnerable_fixture", …)` give different answers, but a wallet that asks
  only "is this code hash good?" would be fooled by a guard deployed in the broken mode. It must also read the
  guard's `get_mode()` (the kept testnet guards return `fixed` and `vulnerable_fixture`).
- **The proof receipt is scoped.** `proof-pay-race-inductive` covers the pay/callback race and the bounded full
  world on the real source, plus the inductive step on the model. It is not "no invoice can ever be paid twice".
- **The race receipts do not test the `reconcile` fix.** The testnet race never reaches `reconcile`; that fix is
  tested locally and in the proofs.
- **Who and when, not how.** The contract stores what the owner key sent. One full-access testnet key decides; it
  could publish any number. Re-hashing the evidence file catches a later edit, not a false original.
- **Old receipts stay.** The Nov 10 receipts for the old build `fcce82bf…` are still stored; they will fail the
  1-day age check from Nov 11 on. `latest` for `0382023b…` returns only the new ones.
- **Same limits as the evidence.** Guards A, B, C and vault-a were tested on a local sandbox, not testnet. Testnet
  only, no mainnet.
