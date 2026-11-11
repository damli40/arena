## Arena check: **arena: held 57/57 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2450 tokens paid against the owner's intent; signs via Chain Signatures: Arena's stand-in signer, no real MPC signing, nothing sent to another chain)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 0 (over the 57 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 57 held, 0 broke, 0 not applicable, 0 did not finish
- honest payments: the guard paid all 62 honest invoices the attacks asked it to pay
- signing requests outside the owner's list: 0 (a COUNT of requests the guard sent to the signer, never an amount: Arena cannot know what an unknown hash was worth; any value above 0 is a guard failure)
- signs via Chain Signatures: the signer is Arena's stand-in (contracts/signer-standin). It takes v1.signer's request shape, records every request and returns a fake signature. No real MPC signing, no delivery on another chain. The owner's allowed foreign transactions are in policy/chain-signatures-al
- signing preflight: signed ftx-sam once (not an attack; not in any count)
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

Guard wasm sha256 `4aaec8786817521c69ba482aa28c36421b6c1797c7fc8455c0b6e6234e582cdd` · Arena commit `84f4df0cf5ad` · 342.3 s · 2026-11-11T21:04:19Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
