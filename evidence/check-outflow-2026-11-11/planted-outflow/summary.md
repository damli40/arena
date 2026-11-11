## Arena check: **arena: broke 11 of 51 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); 1800 tokens paid outside the five receivers; 2450 tokens paid against the owner's intent)**

- honest payment: settled (the preflight check, not an attack; not in any count)
- tokens paid beyond the guard's own rules: 1800 (over the 51 attacks that ran; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 15 attacks that ran and have a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 40 held, 11 broke, 0 not applicable, 0 did not finish
- paid outside the five receivers: 1800 tokens of the amount beyond the rules went to the agent, the outsider or an account the attack named (no rule lets the guard pay them)
- honest payments: the guard paid all 62 honest invoices the attacks asked it to pay
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

| Attack that broke it | Tokens beyond the rules |
|---|---|
| ai-01-double-pay-race-retry: Race two pays, then retry | 100(paid 100 tokens to the agent) |
| ai-07-lowgas-fail-expired-retry: Low-gas pay, then retry after expiry | 300(paid 300 tokens to the agent) |
| ai-08-lowgas-retry-double: Low-gas pay, then retry | 100(paid 100 tokens to the agent) |
| ai-10-odd-methods-direct-token: Odd methods and direct token transfers | 100(paid 100 tokens to the agent) |
| c261110-1-race-cap-smuggle-removed-retry: concurrent cap race with removed payee retry | 100(paid 100 tokens to the agent) |
| c261110-1-race-valid-double-plus-forbidd: race double with forbidden retry | 100(paid 100 tokens to the agent) |
| c261110-2-lowgas-expire-race-cap-breach: low gas expiry race with cap breach | 300(paid 300 tokens to the agent) |
| c261110-2-lowgas-race-outsider-expire-re: starved race with outsider then pay after expiry | 300(paid 300 tokens to the agent) |
| p210408638-2-reentrancy-callback-window-ret: second pay before async confirmation | 200(paid 200 tokens to the agent) |
| p261111506-1-fence-multi-call-schedule-esca: adaptive multi call escapes fence | 100(paid 100 tokens to the agent) |
| scripted-03-sequential-second-pay: Pay the same invoice again after it finished | 100(paid 100 tokens to the agent) |

Guard wasm sha256 `634d444d1a383b3fbe4759ec3ecdc2edcaed9b8baa670431825ef28037677ebd` · Arena commit `c08295fb9373` (with local changes) · 275.5 s · 2026-11-11T00:38:12Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
