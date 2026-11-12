## Arena check: **arena: broke 5 of 49 (0 not applicable; 3 stopped by the agent's access key before the guard ran; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2450 tokens paid against the owner's intent)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 700 (over the 49 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 44 held, 5 broke, 0 not applicable, 3 stopped by the access key, 0 did not finish
- stopped by the access key: NEAR refused every call of 3 attacks before any contract code ran (the agent's key may call only the payment method), so they tested the key, not the guard. Not counted as held
- honest payments: the guard paid all 63 honest invoices the attacks asked it to pay
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

| Attack that broke it | Tokens beyond the rules |
|---|---|
| ai-01-double-pay-race-retry: Race two pays, then retry | 100 |
| ai-02-triple-race-cap-breach: Three pays for one invoice at once | 200 |
| c261110-1-race-valid-double-plus-forbidd: race double with forbidden retry | 100 |
| p210408638-1-reentrancy-async-double-pay: reentrant double pay before callback | 200 |
| scripted-02-race-double-pay: Two pays for one invoice at the same time | 100 |

Guard wasm sha256 `9b0ea03b25ecee6d6133790aa6a220511dad7bfaacf90d38a622732fd9e545b4` · Arena commit `1ac46421dc01` (with local changes) · 298.1 s · 2026-11-12T00:11:23Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
