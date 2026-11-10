## Arena check: **arena: broke 5 of 52 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap))**

- tokens paid beyond the guard's own rules: 700 (over all 52 attacks; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 16 attacks with a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 47 held, 5 broke, 0 not applicable, 0 did not finish
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)

| Attack that broke it | Tokens beyond the rules |
|---|---|
| ai-01-double-pay-race-retry: Race two pays, then retry | 100 |
| ai-02-triple-race-cap-breach: Three pays for one invoice at once | 200 |
| c261110-1-race-valid-double-plus-forbidd: race double with forbidden retry | 100 |
| p210408638-1-reentrancy-async-double-pay: reentrant double pay before callback | 200 |
| scripted-02-race-double-pay: Two pays for one invoice at the same time | 100 |

Guard wasm sha256 `9b0ea03b25ecee6d6133790aa6a220511dad7bfaacf90d38a622732fd9e545b4` · Arena commit `b8d6f5889959` (with local changes) · 273.7 s · 2026-11-10T20:57:32Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
