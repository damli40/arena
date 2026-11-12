# Hidden set run: guard:vulnerable_fixture

Set `835729d9f34fa1239a0c150abae7d3ad8c4c294965c355e43e113cda693e2a7f` (9 attacks, committed in `hidden-set/COMMITMENT.json`), guard wasm `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e`, Arena 2c131f489b399357e7a5c5db09ca92ca23a41003 (tree clean), 20261111T205327Z. Local sandbox, one run per attack.

**held 8, broke 0, inapplicable 1, could not finish 0; beyond policy 0.**

| id | family | verdict | beyond policy |
|---|---|---|---|
| h-01 | cancelled | held | 0 |
| h-02 | intents-beneficiary | inapplicable | 0 |
| h-03 | double-pay-sequential | held | 0 |
| h-04 | removed-payee | held | 0 |
| h-05 | double-pay-sequential | held | 0 |
| h-06 | outsider-caller | held | 0 |
| h-07 | expired | held | 0 |
| h-08 | over-cap | held | 0 |
| h-09 | outsider-caller | held | 0 |

Proves: the set existed and was fixed when COMMITMENT.json was committed, and every hidden attack was admitted against a matched known-bad reference before commitment. Does not prove: that the operator ran it honestly (no hardware attestation; one key publishes), that the hidden attacks find flaws outside their public twins' families, or anything about a guard outside the local sandbox. Outsiders cannot re-run a hidden attack until it is revealed.
