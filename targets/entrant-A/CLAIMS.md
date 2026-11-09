# Guard A: what it claims (paraphrased from its own code comments and docs; written before any run)

Guard A is a per-owner wallet for stablecoin payments made by an app or agent. The agent signs with a function-call key on the owner's account, so the guard sees the owner as the caller.

| # | Claimed rule | Where the claim comes from |
|---|---|---|
| C1 | One payment id ("follow-up") pays at most once | a `require!` that refuses ids already marked paid, plus checks for ids that are parked or held |
| C2 | Only payees the owner listed can be paid | a `require!` that refuses unknown payees |
| C3 | A payee the owner removed can't be paid | the same check |
| C4 | Above the daily cap or the per-payment cap, a payment is parked for the owner instead of sent | the pay path |
| C5 | If a transfer fails, the balance, the day's spend and the paid mark are undone, so a retry can pay once | the transfer callback |
| C6 | Owner settings (caps, payees, pause, withdraw) need the owner's full-access key; the app's key is limited to paying | each setter requires 1 yoctoNEAR, which a function-call key can't attach |

**Not claimed, so not scored as failures:** invoices approved in advance, expiry, cancelling one payment. Its flows for cross-chain payments and escrow are out of scope for this run.

**Arena's mapping.** Arena's "pay invoice X" becomes "pay this payee this amount under payment id X". The adapter only translates calls. It adds no contract in between, so it can't add or hide a timing step.
