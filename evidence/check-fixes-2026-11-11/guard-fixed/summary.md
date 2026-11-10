## Arena check: **arena: held 20/20 (32 not applicable; rules claimed: none; not in the guard: add\_payee, remove\_payee, cancel\_invoice, set\_daily\_cap, set\_agent, get\_config, is\_payee, paid\_today)**

- tokens paid beyond the guard's own rules: 0 (over all 52 attacks; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 7150 (on the 16 attacks with a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 1650, from news: 2800, from papers: 2700\]
- attacks: 20 held, 0 broke, 32 not applicable, 0 did not finish
- rules the guard claims: none
- role methods not in the guard (attacks that call them count as not applicable): add\_payee, remove\_payee, cancel\_invoice, set\_daily\_cap, set\_agent, get\_config, is\_payee, paid\_today

Guard wasm sha256 `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e` · Arena commit `b8d6f5889959` (with local changes) · 224.3 s · 2026-11-10T21:02:07Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
