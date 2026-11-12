## Arena check: **arena: broke 5 of 48 (0 not applicable; 1 stopped by the agent's access key before the guard ran; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2.45 NEAR paid against the owner's intent; scored from NEAR balances)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- NEAR paid beyond the guard's own rules: 0.7 (over the 48 attacks that ran; any value above 0 is a guard failure)
- NEAR paid against the owner's intent: 2.45 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 0.45, from news: 1, from papers: 1\]
- attacks: 43 held, 5 broke, 0 not applicable, 1 stopped by the access key, 0 did not finish
- stopped by the access key: NEAR refused every call of 1 attack before any contract code ran (the agent's key may call only the payment method), so they tested the key, not the guard. Not counted as held
- honest payments: the guard paid all 62 honest invoices the attacks asked it to pay
- not in the native suite: 3 token-only attacks (ai-10-odd-methods-direct-token, bypass-01-bypass-direct-ft-transfer, bypass-03-bypass-add-key). They send calls to the NEP-141 test token, which a native guard does not use, so they are not run and not in any count
- paid in: native NEAR. Read from each receiver's NEAR balance (end of setup to end of attack). The guard's, the agent's, the outsider's and the owner's NEAR are read too, to find where all the NEAR that left the guard went; the agent's and the outsider's own gas and deposits are added back first, so 
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

| Attack that broke it | NEAR beyond the rules |
|---|---|
| ai-01-double-pay-race-retry: Race two pays, then retry | 0.1 |
| ai-02-triple-race-cap-breach: Three pays for one invoice at once | 0.2 |
| c261110-1-race-valid-double-plus-forbidd: race double with forbidden retry | 0.1 |
| p210408638-1-reentrancy-async-double-pay: reentrant double pay before callback | 0.2 |
| scripted-02-race-double-pay: Two pays for one invoice at the same time | 0.1 |

Guard wasm sha256 `cc7fb389cad0b04729df5eaefe8f7624be8529b0e526477761937cbe985244de` · Arena commit `1ac46421dc01` (with local changes) · 243.2 s · 2026-11-12T00:20:39Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
