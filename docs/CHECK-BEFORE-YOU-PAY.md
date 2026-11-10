# Check before you pay

Before a wallet or an agent hands money to a guard contract, it can ask one question: **has Arena tested this
guard, and what happened?** This lookup answers it in one plain sentence, from what is on NEAR testnet right now.

It reads three things, all read-only (no keys, no transactions):

1. which code the guard account runs (its code fingerprint, the sha256 of its wasm);
2. every result Arena published for that code, from the receipts contract
   `receipts.dev-20261109195231-98743803426969.testnet` (it keeps the newest result per test suite);
3. the guard's mode, from its `get_mode()`. This matters because Arena's broken guard and fixed guard are the
   **same code** started in two different modes. The code fingerprint alone cannot tell them apart.

It then counts only the results published for the mode this guard reports.

## What it answers

| Status | Sentence (example) |
|---|---|
| `held` | Held the double-pay race test (5 of 5 runs held, 0 paid over the limit) and the pay-race proof run (30 of 30 checks held, 0 paid over the limit) in mode "fixed", published 2026-11-10. |
| `broke` | Broke the double-pay race test (0 of 5 runs held; worst run paid 100 over the limit) in mode "vulnerable_fixture", published 2026-11-10. |
| `unclear_setting` | Results exist for this code, but they depend on a setting this lookup can't read. Don't rely on them. |
| `no_record` | No Arena record for this code. |
| `no_contract` | The account has no contract deployed. |
| `no_account` | There is no such account on NEAR testnet. |
| `error` | The lookup could not finish (RPC down, timeout, odd reply). Treat the guard as unchecked. |

Only `held` means "a published result applies to this guard and it held". Every other status, including an
RPC error, is **not** a pass. Every answer ends with: *A record of what Arena tested, not a guarantee.* Each
result in the answer carries its publish transaction link, its date, its evidence file and that file's sha256.

## Use it from a wallet

```js
import { lookup } from "./tools/lookup/arena-lookup.mjs";
const a = await lookup("r11cfx4-guard.arena-race-funder-1111.testnet");
showToUser(a.sentence + " " + a.caveat);
if (a.status !== "held") askUserToConfirm(); // anything else is not a pass, including errors
// a.receipts[i].publish_tx_url, .published_date, .evidence_sha256 for the details
```

`arena-lookup.mjs` imports `suites.mjs` from the same folder. Both have no dependencies and use only `fetch`, so
they run in Node 18+ and in a browser.

From a terminal:

```
node tools/lookup/cli.mjs r11cfx4-guard.arena-race-funder-1111.testnet          # plain words
node tools/lookup/cli.mjs <account> --json                                       # the structured answer
node tools/lookup/cli.mjs <account> --suite race-double-pay:mode=fixed           # one suite only
```

Exit code: `0` = held, `1` = any other answer, `2` = bad input or the lookup could not finish.

Demo page: `tools/lookup/demo.html`. Served over http it runs live lookups. Opened as a file, or with no network,
it shows a saved example for the two kept guards, labelled as saved, and gives no answer for any other account.

Tests: `node --test tools/lookup/test.mjs` (set `ARENA_LOOKUP_OFFLINE=1` to skip the live testnet tests).

## Limits

- **Testnet only today.** The receipts contract and the guards are on NEAR testnet. Nothing on mainnet.
- **Only the suites Arena has published.** What each suite means, and which setting it depends on, is listed in
  one place: `tools/lookup/suites.mjs`. A suite not listed there is shown but never counted as a pass.
- **It depends on the guard exposing its mode.** A guard with no `get_mode()`, or whose mode matches no
  published result, gets `unclear_setting`, never `held`. Results that depend on a setting the lookup has no
  way to read (the fooled-agent tests depend on the vault's spending policy; the claims-coverage tests depend on
  how the guard was started) are never counted as a pass either.
- **Only the mode is matched.** Who owns the guard, and which agent and token it serves, are not compared with
  what Arena tested.
- **The answer is for one moment.** All reads use one block. If the account still has a full-access key (both
  kept guards do), its owner can deploy new code later; the answer says so. Check again right before you pay.
- **A receipt says who published a score and when.** It points to the evidence by hash. It does not prove the
  bench ran unmodified or that the tests were good. One testnet key publishes receipts.
- **Publish transaction links come from a list** in `suites.mjs`, copied from the publish logs, because the
  contract does not store them. A receipt missing from that list links to the receipts contract's history and
  says so.
- **The double-pay race receipts do not test the `reconcile` fix**, and the proof run is scoped to the
  pay/callback race. See `evidence/receipts-testnet-2026-11-11.md`.
