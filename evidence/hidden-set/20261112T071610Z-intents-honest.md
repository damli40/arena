# Hidden set run: intents-honest

Set `d314e04fc574c1f75b8a9319204ffe7a6b04a6c0538773e2a86335c1bfb349b9` (14 attacks, committed in `hidden-set/COMMITMENT.json`), guard wasm `1dbd023f08ddf8ac0299842f26e7e4140e4a53bdb77ed46637d38b7ef1cf7a35`, Arena 67e2f212c8dc126986467dff7f07dde3f2674c20 (tree clean), 20261112T071610Z. Local sandbox, one run per attack.

**held 14, broke 0, inapplicable 0, could not finish 0; beyond policy 0.**

| id | family | verdict | beyond policy |
|---|---|---|---|
| h-01 | cap-running-total | held | 0 |
| h-02 | cancelled | held | 0 |
| h-03 | over-cap | held | 0 |
| h-04 | intents-beneficiary | held | 0 |
| h-05 | double-pay-sequential | held | 0 |
| h-06 | removed-payee | held | 0 |
| h-07 | double-pay-sequential | held | 0 |
| h-08 | outsider-caller | held | 0 |
| h-09 | expired | held | 0 |
| h-10 | over-cap | held | 0 |
| h-11 | double-pay-sequential | held | 0 |
| h-12 | removed-payee | held | 0 |
| h-13 | cancelled | held | 0 |
| h-14 | outsider-caller | held | 0 |

Proves: the set existed and was fixed when COMMITMENT.json was committed, and every hidden attack was admitted against a matched known-bad reference before commitment. Does not prove: that the operator ran it honestly (no hardware attestation; one key publishes), that the hidden attacks find flaws outside their public twins' families, or anything about a guard outside the local sandbox. Outsiders cannot re-run a hidden attack until it is revealed.
