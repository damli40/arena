## Arena check: **arena: held 48/48 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2.45 NEAR paid against the owner's intent; scored from NEAR balances)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- NEAR paid beyond the guard's own rules: 0 (over the 48 attacks that ran; any value above 0 is a guard failure)
- NEAR paid against the owner's intent: 2.45 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 0.45, from news: 1, from papers: 1\]
- attacks: 48 held, 0 broke, 0 not applicable, 0 did not finish
- honest payments: the guard paid all 61 honest invoices the attacks asked it to pay
- not in the native suite: 3 token-only attacks (ai-10-odd-methods-direct-token, bypass-01-bypass-direct-ft-transfer, bypass-03-bypass-add-key). They send calls to the NEP-141 test token, which a native guard does not use, so they are not run and not in any count
- paid in: native NEAR. Read from each receiver's NEAR balance (end of setup to end of attack). The guard's, the agent's, the outsider's and the owner's NEAR are read too, to find where all the NEAR that left the guard went; the agent's and the outsider's own gas and deposits are added back first, so 
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

Guard wasm sha256 `5b79571e3795a066d3c87473e9a1a59d4e83ecdde037664610bdc927aab27a44` · Arena commit `c08295fb9373` (with local changes) · 228.4 s · 2026-11-11T00:42:00Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
