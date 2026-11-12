# Hidden set run: intents-honest

Set `e35a4c1f90e10414e3f3babdaa8752fd475f37863de0b20d6790e0f657df3c01` (14 attacks, committed in `hidden-set/COMMITMENT.json`), guard wasm `1dbd023f08ddf8ac0299842f26e7e4140e4a53bdb77ed46637d38b7ef1cf7a35`, Arena 37f8677c7f5bf37e5de50db568d44f142453c408 (tree clean), 20261112T003912Z. Local sandbox, one run per attack.

**held 14, broke 0, inapplicable 0, could not finish 0; beyond policy 0.**

| id | family | verdict | beyond policy |
|---|---|---|---|
| h-01 | cap-running-total | held | 0 |
| h-02 | cancelled | held | 0 |
| h-03 | intents-beneficiary | held | 0 |
| h-04 | double-pay-sequential | held | 0 |
| h-05 | removed-payee | held | 0 |
| h-06 | double-pay-sequential | held | 0 |
| h-07 | outsider-caller | held | 0 |
| h-08 | expired | held | 0 |
| h-09 | over-cap | held | 0 |
| h-10 | double-pay-sequential | held | 0 |
| h-11 | removed-payee | held | 0 |
| h-12 | over-cap | held | 0 |
| h-13 | cancelled | held | 0 |
| h-14 | outsider-caller | held | 0 |

Proves: the set existed and was fixed when COMMITMENT.json was committed, and every hidden attack was admitted against a matched known-bad reference before commitment. Does not prove: that the operator ran it honestly (no hardware attestation; one key publishes), that the hidden attacks find flaws outside their public twins' families, or anything about a guard outside the local sandbox. Outsiders cannot re-run a hidden attack until it is revealed.
