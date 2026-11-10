## Arena check: **arena: held 51/51 (1 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily\_cap); not confirmed: set\_daily\_cap, set\_agent)**

- tokens paid beyond the guard's own rules: 0 (over all 52 attacks; any value above 0 is a guard failure)
- tokens paid against the owner's intent: 2450 (on the 16 attacks with a written intent; the guard's rules allowed these payments) \[hand-written scenarios: 450, from news: 1000, from papers: 1000\]
- attacks: 51 held, 0 broke, 1 not applicable, 0 did not finish
- rules the guard claims: all 4 (payees, cancel, expiry, daily\_cap)
- owner method not confirmed: set\_daily\_cap: no usable on\_transfer\_complete view with a "daily\_cap" field (after: None) (attacks that call it count as not applicable)
- owner method not confirmed: set\_agent: no usable on\_transfer\_complete view with an "agent" field (before None, after None) (attacks that call it count as not applicable)

Guard wasm sha256 `52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1` · Arena commit `b8d6f5889959` (with local changes) · 274.3 s · 2026-11-10T21:05:52Z

Local sandbox only. "Held" means it held these attacks on a local sandbox, not that it is proved safe. "Not applicable" attacks tested nothing the guard claims and are not counted as held.
