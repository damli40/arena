# Arena: bench details

Moved from the README on 2026-11-10 so the README stays short. Commands and saved logs are unchanged. Start with the README for the results.

## 1. Duplicate payment and the fix (~3 minutes)
```
./run.sh
```
You should see `10 passed; 0 failed`. Then check these result lines. Each one also appears in the saved log named in the last column.

| Test | Line to look for | What it shows | Saved log |
|---|---|---|---|
| t1 | `RESULT vulnerable_fixture race payouts per trial: [200, 200, 200, 200, 200]` | Two requests for one 100-token invoice, sent together, pay 200 in 5 of 5 trials | `run-2026-11-08.log` and `run-2026-11-08-callback.log` |
| t2 | `RESULT fixed race payouts per trial: [100, 100, 100, 100, 100]` | The fixed guard pays once; the second request is refused with "payment already in flight" | both |
| t5 | `after retry Sam=200 status=Approved -> DOUBLE PAY` | The final step fails after Sam got paid, and one ordinary retry pays him again | `run-2026-11-08-callback.log` |
| t5 | `retry refused, Sam=100 status=Pending -> no double pay, but stuck` | The fixed guard never pays twice, but the invoice is stuck | `run-2026-11-08-callback.log` |
| t7 | `reconcile -> Paid; retry refused; Sam=100` | `reconcile` reads the balance, marks it paid, and Sam stays at 100 | `run-2026-11-08-callback.log` |
| t8 | `reconcile leaves it Pending; resolve_stuck(sent=false) -> Failed; pay refused; re-issued under a new id, paid once (Sam=100)` | When the money never left, `reconcile` no longer reopens the invoice (changed Nov 11). The owner closes it as `Failed` and re-issues it under a new id, which pays once | `verify-2026-11-11-run.log` (the Nov 8 log shows the old behaviour) |

Logs live in `evidence/`. `run-2026-11-08.log` holds t1–t4; `run-2026-11-08-callback.log` holds all ten tests.

## 2. The test bench on Arena's own guards
```
./run-arena.sh scripted
```
This runs 10 fixed test sequences against `targets/vault-a`, a guard an AI wrote from a one-page spec without seeing these tests. Look for the `SUMMARY tester=scripted` block. Each row prints `unauthorised=` and `honest_settled=`. Saved run: `evidence/arena-2026-11-09-scripted.log` (10 attempts, unauthorised payout 0 on every one; the agent signs with a function-call key, see "Can the agent go around the guard?"). The run before that key was added is kept as `evidence/arena-2026-11-09-scripted-before-fc-key.log`, with the same result.

**Does the scorer see a leak at all?** Run the scorer's own tests with `cd harness && cargo test`. The tests feed it made-up balances, such as 200 paid on a 100 invoice, and check that it reports 100 unauthorised. Next comes a positive control: the same 10 scripted sequences run against `targets/leaky-control-v2`, a labelled fixture with the duplicate-payment flaw.
```
./run-arena.sh control
```
Saved run: `evidence/arena-2026-11-09-positive-control.log`. Lines to look for in its SUMMARY: `race-double-pay              unauthorised=100    honest_settled=0/3` and `attempts=10 attempts_found_something=1`. The other 9 rows show `unauthorised=0`. Its replay (`./run-arena.sh replay sequences-scripted/02-race-double-pay.json --target control`) gave the same balances: sam received 200 against a 100 invoice, everyone else 0 (`evidence/replays.log`).

**Any other guard.** `./run-arena.sh any <guard.wasm> [label]` runs the scripted sequences against any wasm that implements `targets/vault-a/INTERFACE.md`, with no code change. The run header prints the wasm's sha256, and the run fails if the file changes during it. Checked once with vault-a's own wasm: same 10 rows as the scripted run.

## 3. Replay a finding
```
./run-arena.sh replay <sequence.json> [--target vault|control | --wasm <guard.wasm>]
```
The command starts a fresh sandbox, runs that one sequence and prints the final balances. A finding counts only if the replay reproduces the same balances.

## How NEAR fits

- **Split execution:** the bug and the fix both come from NEAR running a contract call across several blocks. Test t3 sends the second request after the first finishes, and both guards refuse it. So the double payment needs that timing gap.
- **Separate accounts:** owner, agent and an outside account are separate NEAR accounts. Testers act only as the agent or the outsider, never the owner.
- **Function-call access key:** the agent signs every test step with a key NEAR only lets call the guard's `pay` method, with no deposit and at most 10 NEAR of gas allowance. The agent's full-access key adds that key at setup and signs nothing else. See "Can the agent go around the guard?" below.
- **NEP-141 tokens:** token targets are scored from token balances only, because gas and storage refunds would pollute native NEAR balances. Native-NEAR targets (`native-control`, `native-fixed`) are scored from receivers' NEAR balances in milliNEAR; receivers sign nothing, so gas never touches them.
- **near-workspaces sandbox:** every attempt starts from the same fresh state, so two runs of one sequence give the same balances.

## How fair is the comparison

- `policy/vault-a.policy.md` fixes the rules before testing. Neither tester can change it.
- `targets/*/FROZEN.txt` records each guard's sha256 fingerprints. `run-arena.sh` checks vault-a's, leaky-control's and leaky-control-v2's before and after every run and stops on a mismatch.
- Both testers get the same interface file, starting state and attempt budget (10).
- vault-a is our control: an AI wrote it from our spec, so a pass shows the bench runs. It doesn't show that vault-a, or anyone else's guard, is safe.

## AI tester

| Tester | How it worked | Attempts | Unauthorised payout | Log |
|---|---|---|---|---|
| Scripted | 10 fixed sequences | 10 | 0 every time | `evidence/arena-2026-11-09-scripted.log` |
| AI, one-shot | wrote 10 sequences up front, without seeing any result | 10 | 0 every time | `evidence/arena-2026-11-09-ai.log` |

Both logs are re-runs with the agent on a function-call key; the earlier runs are kept as `evidence/arena-2026-11-09-*-before-fc-key.log`. In the AI run, one step (the agent calling `ft_transfer` on the guard with 1 yoctoNEAR attached, in `odd-methods-direct-token`) is now refused by NEAR before it runs, instead of by the guard.

The one-shot AI run doesn't answer whether an AI finds what a script misses, because it never saw a result. The next run feeds the AI each attempt's result before it writes the next, under the same budget, and records the model used.

## Can the agent go around the guard?

If the agent could sign other transactions, it could skip the guard and move tokens itself. The bench gives the agent a function-call access key (only the guard, only `pay`, no deposit) and tries three ways around:

```
./run-arena.sh bypass vault      # -> evidence/arena-2026-11-09-bypass-vault.log
./run-arena.sh bypass control    # -> evidence/arena-2026-11-09-bypass-control.log
```

| Sequence | What the agent tries | NEAR's refusal (copied from the log) |
|---|---|---|
| `bypass-direct-ft-transfer` | `ft_transfer` on the token, with and without 1 yoctoNEAR | `InvalidAccessKeyError(DepositWithFunctionCall)`; `InvalidAccessKeyError(ReceiverMismatch { ... })` |
| `bypass-owner-method` | `approve_invoice`, `set_daily_cap` (1 yoctoNEAR each), `cancel_invoice` | `DepositWithFunctionCall` twice; `MethodNameMismatch { method_name: "cancel_invoice" }` |
| `bypass-add-key` | add a full-access key, then a token-calling key, to its own account | `InvalidAccessKeyError(RequiresFullAccess)` twice; the account still has 1 full-access + 1 function-call key |

All 7 steps were refused by the protocol before any contract code ran (`protocol_rejected=2/2`, `3/3`, `2/2`), on both targets, with 0 tokens moved. The log marks these `outcome=REJECTED-BY-PROTOCOL`, separate from a contract panic (`outcome=contract-failure`). This shows the key does its job on the sandbox. It doesn't show that a real deployment set up its keys this way.

## Known limits

- The first positive-control fixture (`targets/leaky-control`, v1) had an interface bug: 4 owner methods lacked `#[payable]`, so setup failed before any attack ran (`evidence/arena-2026-11-09-positive-control-v1-setup-failure.log`). `targets/leaky-control-v2` adds those 4 attributes and nothing else (`targets/leaky-control-v2/CHANGES.diff`). Both are frozen.

- Sandbox only. Real-network timing differs, but the gap of at least two blocks between a call and its callback is how NEAR works.
- A forced panic stands in for the final step failing. We didn't produce a real out-of-gas failure.
- `reconcile` handles one stuck invoice at a time and refuses when two are stuck. A plain token transfer into the guard while an invoice is stuck leaves it stuck for good. A transfer of exactly the invoice amount could lead to a second payment. Neither case has a test yet.
- The race was tested with both requests in the same block only.

Full test details, the `reconcile` design and build notes: `docs/guard-tests.md`. Harness design: `harness/README.md`.

