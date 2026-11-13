# Hidden set run: intents-planted

Set `9748cbedd7a58c4c746901f1af3fd350e425ef86d72657b16213a703c2b1d47b` (14 attacks, committed in `hidden-set/COMMITMENT.json`), guard wasm `954d02cebb25eefe270bcb3376f1735cb7f5ddee8ff654984122fa9f2e3f169c`, Arena 7cfdb22f96eba305ccf6ab27e03167d317d53b50 (tree clean), 20261112T080658Z. Local sandbox, one run per attack.

**held 13, broke 1, inapplicable 0, could not finish 0; beyond policy 100.**

| id | family | verdict | beyond policy |
|---|---|---|---|
| h-01 | cancelled | held | 0 |
| h-02 | over-cap | held | 0 |
| h-03 | intents-beneficiary | broke | 100 |
| h-04 | double-pay-sequential | held | 0 |
| h-05 | removed-payee | held | 0 |
| h-06 | double-pay-sequential | held | 0 |
| h-07 | outsider-caller | held | 0 |
| h-08 | over-cap | held | 0 |
| h-09 | double-pay-sequential | held | 0 |
| h-10 | removed-payee | held | 0 |
| h-11 | cancelled | held | 0 |
| h-12 | expired | held | 0 |
| h-13 | cap-running-total | held | 0 |
| h-14 | outsider-caller | held | 0 |

Proves: the set existed and was fixed when COMMITMENT.json was committed, and every hidden attack was admitted against a matched known-bad reference before commitment. Does not prove: that the operator ran it honestly (no hardware attestation; one key publishes), that the hidden attacks find flaws outside their public twins' families, or anything about a guard outside the local sandbox. Outsiders cannot re-run a hidden attack until it is revealed.
