## Arena check: **arena: broke 5 of 48 (3 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2.45 NEAR paid against the owner's intent; scored from NEAR balances)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- NEAR paid beyond the guard's own rules: 0.7 (over the 48 attacks that ran; any value above 0 is a guard failure)
- NEAR paid against the owner's intent: 2.45 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 0.45, from news: 1, from papers: 1\]
- attacks: 43 held, 5 broke, 3 not applicable, 0 did not finish
- honest payments: the guard paid all 61 honest invoices the attacks asked it to pay
- paid in: native NEAR. Read from each receiver's NEAR balance (end of setup to end of attack); gas and deposits paid by the agent, the outsider and the owner are never read, so never counted
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

| Attack that broke it | NEAR beyond the rules |
|---|---|
| ai-01-double-pay-race-retry: Race two pays, then retry | 0.1 |
| ai-02-triple-race-cap-breach: Three pays for one invoice at once | 0.2 |
| c261110-1-race-valid-double-plus-forbidd: race double with forbidden retry | 0.1 |
| p210408638-1-reentrancy-async-double-pay: reentrant double pay before callback | 0.2 |
| scripted-02-race-double-pay: Two pays for one invoice at the same time | 0.1 |

Guard wasm sha256 `cc7fb389cad0b04729df5eaefe8f7624be8529b0e526477761937cbe985244de` · Arena commit `c08295fb9373` (with local changes) · 233.9 s · 2026-11-11T00:16:19Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
