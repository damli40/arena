## Arena check: **arena: held 49/49 (0 not applicable; 3 stopped by the agent's access key before the guard ran; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2450 tokens paid against the owner's intent)**
![arena: held 49/49 (0 not applicable; 3 stopped by the access key; rules claimed: all 4; 2450 against intent)](https://img.shields.io/badge/arena-held%2049%2F49%20%280%20not%20applicable%3B%203%20stopped%20by%20the%20access%20key%3B%20rules%20claimed%3A%20all%204%3B%202450%20against%20intent%29-yellow)

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 0 (over the 49 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 49 held, 0 broke, 0 not applicable, 3 stopped by the access key, 0 did not finish
- stopped by the access key: NEAR refused every call of 3 attacks before any contract code ran (the agent's key may call only the payment method), so they tested the key, not the guard. Not counted as held
- honest payments: the guard paid all 63 honest invoices the attacks asked it to pay
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

Guard wasm sha256 `52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1` · Arena commit `9679b61b3678 (taken from the GitHub Action ref; not checked by git)` · 1041.1 s · 2026-11-13T16:12:57Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
