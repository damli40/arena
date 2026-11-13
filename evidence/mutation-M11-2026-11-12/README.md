# Mutant M11 (gas pre-check removed): result against the pre-registered plan

Plan, written and committed before the build (commit a09815c): `evidence/mutation-plan-2026-11-12.md`.
Run: `SKIP_BASELINE=1 MUT_DATE=M11-2026-11-12 MUT_PLAN=evidence/mutation-plan-2026-11-12.md tools/mutation/run.sh M11`,
harness pinned from git HEAD a88c991 (`HARNESS.txt`). M11 wasm sha256 `5f37ab174733820349508ed454685d438d091b3985aa55bee22c580bbe09697f`
(`mutants/M11/FROZEN.txt`); the diff is in `mutants/M11/MUTATION.md`. Frozen vault-a and leaky-control-v2 checked before and after.

| expected | got |
|---|---|
| survives, 0 on all 10 scripted attacks | **survived, 0 on all 10** (`summary.tsv`) |
| `08-gas-starve-then-pay`: the 20 TGas pay fails as a whole and rolls back; the next pay is the first real one | as expected: step 1 `contract-failure` "Exceeded the prepaid gas", step 2 `ok`, inv-pay `Paid` once, 0 beyond policy (`M11/08-gas-starve-then-pay.result.json`) |

Also run once each through the gate's runner (`evidence/admission-2-survey-2026-11-12/round-2/`): `ai-07-lowgas-fail-expired-retry`
and `ai-08-lowgas-retry-double` on M11, 0 beyond policy each: the 50 TGas pay is enough even without the check, so it pays normally.

What it decides: M11 is NOT added to `tools/admission/references.json` (no attack breaks it, so it validates nothing), and
`scripted-08` and `ai-07` stay unvalidated with the reason "no one flaw finds it", now measured. (The plan named three attacks
keeping that reason; `ai-08` was meanwhile validated against M4 for a different flaw, the already-paid check.)

What this does not show: a callback that runs out of gas. NEAR reserves the callback's static gas when `pay` creates the
promise, so these attacks cannot reach that state on vault-a; the fault-injection guard tests (`tests/tests/race.rs` t5-t8)
cover it outside the library.
