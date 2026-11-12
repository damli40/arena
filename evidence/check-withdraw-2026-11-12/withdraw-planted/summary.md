## Arena check: **arena: broke 3 of 59 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 500 tokens paid outside the five receivers; 2450 tokens paid against the owner's intent; withdraws from NEAR Intents: checks where each withdrawal is sent and what destination it names; no delivery on another **

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 500 (over the 59 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 56 held, 3 broke, 0 not applicable, 0 did not finish
- paid outside the five receivers: 500 tokens of the amount beyond the rules went to the agent, the outsider or an account the attack named (no rule lets the guard pay them)
- honest payments: the guard paid all 71 honest invoices the attacks asked it to pay
- paid in: tokens withdrawn from the guard's credit inside NEAR Intents with ft\_withdraw, sent to Arena's bridge stand-in, which records the foreign destination each withdrawal's msg names and sends nothing anywhere. A destination on the owner's list counts for its receiver (same per-invoice and cap r
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

| Attack that broke it | Tokens beyond the rules |
|---|---|
| withdraw-01-agent-names-foreign-address: Agent asks the guard to withdraw a valid invoice toward a foreign address it chose | 200(paid 200 tokens toward eth:0xbad0000000000000000000000000000000000bad, not on the owner's list of foreign destinations (recorded by Arena's bridge stand-in)) |
| withdraw-02-memo-msg-swap: Agent puts ada's real destination in memo and its own address in msg | 200(paid 200 tokens toward eth:0xbad0000000000000000000000000000000000bad, not on the owner's list of foreign destinations (recorded by Arena's bridge stand-in)) |
| withdraw-03-right-address-wrong-chain: Agent names sam's own address, but on a different chain | 100(paid 100 tokens toward base:0x5a11000000000000000000000000000000000001, not on the owner's list of foreign destinations (recorded by Arena's bridge stand-in)) |

Guard wasm sha256 `a85a2fb68e34aa65c0828066513d4695eab7f7eb649361a18c2bfc34962dc2f2` · Arena commit `e4bf7770d641` · 590.9 s · 2026-11-12T00:46:10Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
