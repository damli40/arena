## Arena check: **arena: held 51/51 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2450 tokens paid against the owner's intent)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 0 (over the 51 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 51 held, 0 broke, 0 not applicable, 0 did not finish
- honest payments: the guard paid all 62 honest invoices the attacks asked it to pay
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

Guard wasm sha256 `634d444d1a383b3fbe4759ec3ecdc2edcaed9b8baa670431825ef28037677ebd` · Arena commit `c08295fb9373` (with local changes) · 276.3 s · 2026-11-11T00:28:28Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
