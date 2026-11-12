## Arena check: **arena: held 51/51 (0 not applicable; 3 stopped by the agent's access key before the guard ran; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2450 tokens paid against the owner's intent; pays via NEAR Intents: local release build, no withdrawals to other chains)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 0 (over the 51 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 51 held, 0 broke, 0 not applicable, 3 stopped by the access key, 0 did not finish
- stopped by the access key: NEAR refused every call of 3 attacks before any contract code ran (the agent's key may call only the payment method), so they tested the key, not the guard. Not counted as held
- honest payments: the guard paid all 65 honest invoices the attacks asked it to pay
- paid in: tokens deposited into NEAR Intents. Each receiver's tokens on the token contract plus its credit inside Intents (Intents' own ledger, mt\_balance\_of). Intents is the pinned release build defuse v0.4.2 on the local sandbox, fee 0, no solvers. Every token that entered Intents must be credited 
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

Guard wasm sha256 `1dbd023f08ddf8ac0299842f26e7e4140e4a53bdb77ed46637d38b7ef1cf7a35` · Arena commit `1ac46421dc01` (with local changes) · 496.7 s · 2026-11-12T00:24:42Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
