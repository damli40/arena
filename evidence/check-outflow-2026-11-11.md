# `arena check`: where did the guard's money go? (2026-11-11)

Plain-words record of one fix, one smaller change, and six real runs.

## What was wrong

Arena scored a guard only from the final balances of the five receivers (sam, ada, lin, kai, mo).
Money the guard sent to anyone else (the agent, the outsider, an account the attack named, an
account the guard created) was never read. So an attack that moved money only there was scored
**held**. That was true for token guards and native guards alike, and
`evidence/check-native-2026-11-11.md` listed it as a known gap.

This is the worst kind of wrong answer: the run finishes, the badge says held, and the guard paid
the attacker.

## What changed

**Every attack now accounts for all the money that left the guard** (`harness/src/conserve.rs`,
new). Right before the attack's first step the harness reads the guard's balance and the balances
of the owner, the agent, the outsider, and any account the attack names in its arguments (token
guards: also the token contract and the token's total supply). After the attack it reads them
again. Then:

- money that reached **the agent, the outsider, the token contract or an account the attack
  named** is added to the payout beyond the rules. No rule lets the guard pay them: Arena's setup
  makes only the five receivers payees. The attack is **broke**, and the report says who got it
  ("paid 100 tokens to the agent");
- money that went **back to the owner** is accounted for, not a theft;
- money Arena **cannot find** (or numbers that do not add up) makes the attack **did not finish**,
  so the whole check is **incomplete (exit 2)**. It is never held.

**Token guards: exact.** Tokens are whole numbers and only the guard and the owner hold any at the
start (checked every attempt), so the tolerance is 0. A token guard's agent or outsider gaining
plain NEAR (net of its own gas) also makes the attack not finish, because a token guard is not
scored in NEAR.

**Native guards: gas taken out.** The guard's outflow is its NEAR balance change plus deposits it
kept. The agent's and the outsider's gain is their balance change plus every bit of gas and deposit
they paid, read from their own transactions' receipts (`tokens_burnt`), so their gas never looks like
a payment.

**Preflight checks the check.** On the honest payment, what left the guard must equal what sam got
(exactly 100 tokens, or 0.1 NEAR within the tolerance below). If not, the check stops (exit 2):
"Arena cannot account for the guard's money, so it cannot score this guard".

**Smaller change: the native suite.** The 3 attacks that work only on the test token
(`ai-10-odd-methods-direct-token`, `bypass-01-bypass-direct-ft-transfer`, `bypass-03-bypass-add-key`)
used to count as "not applicable" on every native guard, so a native badge could never be green.
They are not a gap in the guard; they are just not part of a native guard's suite. Now a native
check does not run them, leaves them out of every count, and lists them by id with the reason on a
line of its own ("not in the native suite"). Green still needs 0 paid against the owner's intent,
so native-fixed stays **yellow**.

Also: the Muse mapping prompt now says how the guard pays (ft_transfer for a token guard, a plain
NEAR transfer for a native guard). Prompt text only; model and provider unchanged.

## Tolerance, and why (native guards)

**1 milliNEAR (0.001 NEAR, 10^21 yoctoNEAR).** The smallest invoice in Arena's setup is 0.05 NEAR,
50 times bigger. The library's attacks attach at most 1 yoctoNEAR of deposit.

One thing can hide a small outflow: gas rewards the guard earns (the protocol gives a contract 3/10 of
the gas burnt in its own receipts). They only push the guard's balance up, so they can hide outflow
but never invent it. Arena computes a bound per attempt from the receipts (`reward_bound`, 3/10 of
the tokens burnt in receipts the guard executed) and prints it. The largest bound in these runs was
0.00053 NEAR (native-fixed). An outflow bigger than 1 milliNEAR plus that bound cannot hide.

**What was measured:** in all 98 native attempts, the money Arena could not find was exactly 0
yoctoNEAR, and the agent's, the outsider's and the owner's gains were exactly 0. So on this sandbox
the gas accounting is exact to the yoctoNEAR, and no gas reward showed up in the guard's balance.

## A bug found on the way, and fixed

The first native try failed its own preflight: the owner seemed to receive 0.0106 NEAR during the
honest payment. That was setup's gas refunds reaching the owner a block or two after setup's
transactions had returned. The native snapshot now waits for real blocks until the guard's, the
owner's, the agent's and the outsider's balances stop moving (it never fast-forwards, so block time
and expiry are not touched). No visible slowdown: native-control took 227.8 s (233.9 s before).

A second, older bug showed up in the same try: every native log starts with a `SCORING: native`
header line, and `tools/check/explain.py` matched that line as the scorer's `get_invoice` failure.
So any native error got the wrong advice ("map get_invoice"). It now matches only the scorer's own
failure text. Test added.

## The planted guard: before and after

`targets/planted-outflow/` is a copy of vault-a with one planted flaw (`CHANGES.diff`): a second
`pay` for an invoice that is already paid sends the invoice amount to the caller, the agent. No
frozen fixture was edited.

| | Headline | Exit |
|---|---|---|
| **Before** (the code as it was) | `held 51/51 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2450 tokens paid against the owner's intent)` | 0 |
| **After** | `broke 11 of 51 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 1800 tokens paid outside the five receivers; 2450 tokens paid against the owner's intent)` | 1 |

All 1800 tokens went to the agent, in 11 attacks. One example, `scripted-03-sequential-second-pay`:
before, sam got 100 and the score was 0 beyond the rules (held); after, the log shows
`OUTFLOW guard_out=200 seen_at_receivers=100`, `other the agent: received 100`, and
`PAID OUTSIDE THE RECEIVERS: 100 tokens to the agent`.

## The four existing headlines

| Guard | Before (earlier evidence) | After (this run) | Same? |
|---|---|---|---|
| vault-a | `held 51/51 (0 not applicable; rules claimed: all 4 (...); 2450 tokens paid against the owner's intent)` | identical | yes |
| leaky-control-v2 | `broke 5 of 51 (0 not applicable; rules claimed: all 4 (...); 2450 tokens paid against the owner's intent)` | identical, same 5 attacks, same amounts | yes |
| native-control | `broke 5 of 48 (3 not applicable; ...; 2.45 NEAR paid against the owner's intent; scored from NEAR balances)` | `broke 5 of 48 (0 not applicable; ...)`, same 5 attacks, same 0.7 NEAR | one change |
| native-fixed | `held 48/48 (3 not applicable; ...; 2.45 NEAR paid against the owner's intent; scored from NEAR balances)` | `held 48/48 (0 not applicable; ...)`, still yellow | one change |

The only change is `3 not applicable` becoming `0 not applicable` on the two native guards. That is
the native-suite change above, on purpose: the 3 token-only attacks are now listed on their own
line instead. Nothing else moved. In every attempt of these four guards, the money Arena could not
find was 0 and nothing reached a non-receiver, so the conservation check added accounting lines to
the logs and nothing to the scores. "Before" comes from `check-fixes-2-2026-11-11` (token) and
`check-native-2026-11-11` (native), not from a re-run of the old code today. All four fixtures matched
their FROZEN.txt fingerprints after the runs.

All six runs: same Mac (Apple silicon), Arena HEAD c08295f with uncommitted edits, `--jobs 4`, two
checks at a time. Consoles in `check-outflow-2026-11-11/console-*.txt` (each starts with its
`$ command` line), report folders next to them.

## Tests run

- `cargo test --release` in `harness/`: 48 passed, 1 ignored (was 32; 16 new: 14 for the pure
  conservation math in conserve.rs, 2 for folding it into the score).
- `python3 -I tools/check/tests/test_check.py`: 98 OK (was 86; 12 new, 1 changed). The new ones
  include 5 that run `check.main` through the real runner with a stand-in harness that returns
  stored result files (`tools/check/tests/outflow/`), plus one that the files are there: money to the outsider is broke, money to the
  agent is broke, money Arena cannot find is incomplete and never held, an honest payment that
  conserves lets the check go on, and one that does not stops it. Three of the stored files are real
  results from the planted run; three are edited from them, and each file says so in its
  `_fixture` field. The changed test: a token-only attack on a native guard is now outside the suite,
  not "not applicable".
- `node tools/lookup/test.mjs`: 32 pass.
- Not run: the hunter tests (another agent is editing them), `verify.sh`, and the live
  `cargo test --release -- --ignored native_live` (it was updated to take the new snapshot first, but
  not run).

## Limits

- **Money is followed only to accounts Arena knows**: the receivers, the agent, the outsider, the
  owner, the token contract (token guards) and accounts named in the attack's arguments (at most 20).
  Money sent anywhere else is not traced to where it went. It shows as money Arena cannot find, so
  the check ends incomplete, not held, but the report cannot say who got it.
- **Native: gas rewards can hide a small outflow**, up to 1 milliNEAR plus the printed
  `reward_bound`.
- **Native: NEAR sent to the token contract is not checked** (its balance moves with its own gas
  rewards); it would show as money Arena cannot find.
- **Money back to the owner is not counted as theft.** A guard that refunds the owner on an
  attacker's request is not scored as broke for that.
- **A token guard paying the attacker in plain NEAR** makes the check incomplete, not broke: Arena
  sees it but has no token number for it.
- The planted guard and both fixture families are our own. No guard written by anyone else was run.

## What was not checked

- No run on Linux or GitHub's runners; the Action was not exercised.
- No native guard that pays the agent or the outsider (no planted native variant was built); the
  native path is covered by unit tests and by 98 native attempts that conserved exactly.
- No attack in the library pays an account it names or creates, so those paths are unit-tested only.
- `./run-arena.sh`, the board and `verify.sh` use the same scorer and now print the new accounting
  lines; they were not re-run.
- `tools/injection/__pycache__/run.cpython-314.pyc` is a tracked file that Python rewrites when the
  check imports tools/injection/run.py; it was already modified before this work.
