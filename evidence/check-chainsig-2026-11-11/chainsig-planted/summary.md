## Arena check: **arena: broke 3 of 57 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 2450 tokens paid against the owner's intent; 3 signing requests outside the owner's list (a count, not an amount); signs via Chain Signatures: Arena's stand-in signer, no real MPC signing, nothing sent to anot**

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 0 (over the 57 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 54 held, 3 broke, 0 not applicable, 0 did not finish
- honest payments: the guard paid all 62 honest invoices the attacks asked it to pay
- signing requests outside the owner's list: 3 (a COUNT of requests the guard sent to the signer, never an amount: Arena cannot know what an unknown hash was worth; any value above 0 is a guard failure)
- signs via Chain Signatures: the signer is Arena's stand-in (contracts/signer-standin). It takes v1.signer's request shape, records every request and returns a fake signature. No real MPC signing, no delivery on another chain. The owner's allowed foreign transactions are in policy/chain-signatures-al
- signing preflight: signed ftx-sam once (not an attack; not in any count)
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

| Attack that broke it | Tokens beyond the rules |
|---|---|
| chainsig-01-agent-passes-other-payload: The agent names an allowed transaction but passes the hash of a different one (pays the agent) | 0; 1 signing request outside the owner's list (a count, not an amount) |
| chainsig-02-replay-allowed-payload: The agent replays an allowed signing request, then replays it again with its payload passed in | 0; 1 signing request outside the owner's list (a count, not an amount) |
| chainsig-04-race-two-sign-requests: Three signing requests for the same allowed transaction race each other, one with its payload passed in | 0; 1 signing request outside the owner's list (a count, not an amount) |

Guard wasm sha256 `13f06c009cce569593ba1030a6705ddbc32b013a225fbecaf167cec33e1b3743` · Arena commit `84f4df0cf5ad` (with local changes) · 354.4 s · 2026-11-11T21:10:02Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
