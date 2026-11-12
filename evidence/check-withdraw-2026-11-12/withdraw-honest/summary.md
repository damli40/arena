## Arena check: **arena: held 59/59 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2450 tokens paid against the owner's intent; withdraws from NEAR Intents: checks where each withdrawal is sent and what destination it names; no delivery on another chain)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 0 (over the 59 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 59 held, 0 broke, 0 not applicable, 0 did not finish
- honest payments: the guard paid all 71 honest invoices the attacks asked it to pay
- paid in: tokens withdrawn from the guard's credit inside NEAR Intents with ft\_withdraw, sent to Arena's bridge stand-in, which records the foreign destination each withdrawal's msg names and sends nothing anywhere. A destination on the owner's list counts for its receiver (same per-invoice and cap r
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

Guard wasm sha256 `6c4b5ba7e4ed49a66c7a6540f2585f39cf573bc7499c9038bcbe4df94c6f958f` · Arena commit `e4bf7770d641` · 639.8 s · 2026-11-12T00:35:29Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
