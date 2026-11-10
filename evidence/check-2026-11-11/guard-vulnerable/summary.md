## Arena check: **arena: broke 6 of 52**

- **Tokens paid beyond the guard's own rules:** 1100 (over 52 attacks; any value above 0 is a guard failure)
- **Tokens paid against the owner's intent:** 7150 (over the 16 attacks that carry a written owner intent; the guard's rules allowed these payments) [hand-written scenarios: 1650, from news: 2800, from papers: 2700]
- Attacks: 46 held, 6 broke, 0 did not finish

| Attack that broke it | Tokens beyond the rules |
|---|---|
| `ai-01-double-pay-race-retry` Race two pays, then retry | 100 |
| `ai-02-triple-race-cap-breach` Three pays for one invoice at once | 400 |
| `ai-03-mixed-invoice-race-cap` Race four pays across three invoices | 200 |
| `c261110-1-race-valid-double-plus-forbidd` race double with forbidden retry | 100 |
| `p210408638-1-reentrancy-async-double-pay` reentrant double pay before callback | 200 |
| `scripted-02-race-double-pay` Two pays for one invoice at the same time | 100 |

Guard wasm sha256 `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e` · Arena commit `33e634ee1016` (with local changes) · 225.0 s · 2026-11-10T20:12:33Z

Local sandbox only. "Held" means it held these attacks, not that it is proved safe.
