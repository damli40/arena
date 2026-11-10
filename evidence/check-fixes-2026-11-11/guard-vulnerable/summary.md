## Arena check: **arena: broke 6 of 21 (31 not applicable; rules claimed: none; not in the guard: add\_payee, remove\_payee, cancel\_invoice, set\_daily\_cap, set\_agent, get\_config, is\_payee, paid\_today)**

- tokens paid beyond the guard's own rules: 1100 (over all 52 attacks; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 7150 (on the 16 attacks with a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 1650, from news: 2800, from papers: 2700\]
- attacks: 15 held, 6 broke, 31 not applicable, 0 did not finish
- rules the guard claims: none
- role methods not in the guard (attacks that call them count as not applicable): add\_payee, remove\_payee, cancel\_invoice, set\_daily\_cap, set\_agent, get\_config, is\_payee, paid\_today

| Attack that broke it | Tokens beyond the rules |
|---|---|
| ai-01-double-pay-race-retry: Race two pays, then retry | 100 |
| ai-02-triple-race-cap-breach: Three pays for one invoice at once | 400 |
| ai-03-mixed-invoice-race-cap: Race four pays across three invoices | 200 |
| c261110-1-race-valid-double-plus-forbidd: race double with forbidden retry | 100 |
| p210408638-1-reentrancy-async-double-pay: reentrant double pay before callback | 200 |
| scripted-02-race-double-pay: Two pays for one invoice at the same time | 100 |

Guard wasm sha256 `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e` · Arena commit `b8d6f5889959` (with local changes) · 225.4 s · 2026-11-10T21:02:06Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
