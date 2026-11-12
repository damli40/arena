# Mutation plan, M11 (pre-registered 2026-11-12, before the build and the run)

**Why M11.** Three library attacks try to break a guard with a starved-gas pay: `scripted-08-gas-starve-then-pay`
(20 TGas), `ai-07-lowgas-fail-expired-retry` and `ai-08-lowgas-retry-double` (50 TGas). On vault-a none of them
reaches a half-paid state, because `pay` refuses before touching state unless the call carries
GAS_FT_TRANSFER + GAS_CALLBACK + GAS_PAY_OVERHEAD = 20 + 15 + 10 = 45 TGas (`targets/vault-a/src/lib.rs`, `pay`,
"not enough gas attached to pay safely"). M11 removes exactly that check, so the attacks can reach the code
behind it. Question: does any of them then pay beyond the policy?

| id | planted flaw | expected | why |
|---|---|---|---|
| M11 | gas pre-check in `pay` removed | **survives, 0 on all 10 scripted attacks** | with 20 TGas, `pay` cannot attach 20 + 15 TGas of static gas to its two promises, so NEAR fails the whole call and rolls its state back (Pending mark and cap reservation included); the next full-gas pay is the first real one. A callback that runs out of gas (the half-paid state these attacks aim for) is not reachable this way: the callback's 15 TGas is reserved when the promise is created |

If M11 survives, it is NOT added to `tools/admission/references.json` (a reference no attack can break validates
nothing), and the three attacks keep the reason "no one flaw finds it", now measured rather than argued.
If anything pays beyond the policy on M11, the attack that did it gets a spec naming M11 and goes through the gate.

Run: `SKIP_BASELINE=1 MUT_DATE=M11-2026-11-12 MUT_PLAN=evidence/mutation-plan-2026-11-12.md tools/mutation/run.sh M11`
(the 10 scripted attacks), then `ai-07` and `ai-08` once each on M11 through the gate's runner.

**Not edited after the run.** Any difference from this table is reported in `evidence/mutation-M11-2026-11-12/` (named outside `mutation-20*` on purpose: the manifest reads the latest full table, `evidence/mutation-2026-11-11/`, and a one-mutant table must not replace it).
