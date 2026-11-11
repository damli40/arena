## Arena check: **arena: held 48/48 (3 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2.45 NEAR paid against the owner's intent; scored from NEAR balances)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- NEAR paid beyond the guard's own rules: 0 (over the 48 attacks that ran; any value above 0 is a guard failure)
- NEAR paid against the owner's intent: 2.45 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 0.45, from news: 1, from papers: 1\]
- attacks: 48 held, 0 broke, 3 not applicable, 0 did not finish
- honest payments: the guard paid all 61 honest invoices the attacks asked it to pay
- paid in: native NEAR. Read from each receiver's NEAR balance (end of setup to end of attack); gas and deposits paid by the agent, the outsider and the owner are never read, so never counted
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

Guard wasm sha256 `5b79571e3795a066d3c87473e9a1a59d4e83ecdde037664610bdc927aab27a44` · Arena commit `c08295fb9373` (with local changes) · 234.2 s · 2026-11-11T00:16:19Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
