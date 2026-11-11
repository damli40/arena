# `arena check` for guards that pay in native NEAR (2026-11-11)

Plain-words record of one change and two real runs.

## The problem this fixes

`./arena check` only scored guards that pay with `ft_transfer` on a NEP-141 token. Most guards
people write for hackathons send plain NEAR instead. For those, the one-command check stopped at
the honest payment ("no ft_transfer was seen"), and the docs pointed them to a different script
(`./run-arena.sh any-native`) with a different, older output: no report card, no badge, no
not-applicable rules, no exit codes, no GitHub Action.

The harness could already measure native payouts (`--native`, used by `run-arena.sh any-native`
and the `native-control` / `native-fixed` targets). It just was not wired into the check.

## What was added

- **One config field.** `"pays_in": "token"` (the default) or `"pays_in": "native"` in the guard
  config, or `--pays-in native` on the command line. Anything else stops the check with exit 2 and
  a plain message. If the flag and the config both say it and disagree, the check stops (exit 2).
  Both validators (Python in `tools/check/guard_config.py`, Rust in `harness/src/adapter.rs`) read
  the same shared test cases, now including 9 about `pays_in`.
- **Units, said out loud.** A native guard is given amounts in yoctoNEAR (1 NEAR = 10^24
  yoctoNEAR). One Arena unit = 1 milliNEAR = 10^21 yoctoNEAR, so inv-pay (100 units) is 0.1 NEAR and
  the cap (500) is 0.5 NEAR. `report.json` keeps every amount in Arena units and says so in a new
  `units` block; the console, report.html, summary.md and the badge say **NEAR**. Two config
  choices that cannot carry numbers this big (`$daily_cap_number`, `"amount_encoding": "number"`)
  are refused for native guards.
- **Attack amounts are scaled too.** When an attack's own call carries an amount (for example the
  agent trying `approve_invoice` for 5000, or `set_daily_cap` to 1000000), the harness scales it to
  yoctoNEAR before sending, and prints a `NATIVE UNITS` line for each value. Without this, "5000"
  would have meant 5000 yoctoNEAR, not 5 NEAR.
- **The owner-method preflight is unit-aware.** It now expects the cap in yoctoNEAR on a native
  guard (it used to compare against the plain number 500, which would have stopped every native
  check).
- **A new not-applicable rule (rule 6).** A native guard holds no tokens, so an attack that sends a
  call to the test token itself (for example `ft_transfer`), or adds a key that may call the token,
  tested nothing about it. It is reported as **not applicable** with that reason, never as held.
  Today that is 3 attacks: `ai-10-odd-methods-direct-token`, `bypass-01-bypass-direct-ft-transfer`,
  `bypass-03-bypass-add-key`.
- **Two locks against the wrong money.** Every attempt's result now says what the harness measured
  (`"pays_in"` in its setup block, `"scoring"` in its score block). If either does not match the
  config, that attempt is an error (the whole check ends incomplete, exit 2), never held or broke.
  The honest-payment preflight has the same lock.
- **Plain error text** for a native guard whose `pay` sends nothing ("sam's NEAR balance did not go
  up"), for an attempt the native measurement had to reject ("Arena could not measure this
  attempt"), and a hint to token guards that fail the same way ("if your guard pays in plain NEAR,
  add `pays_in`").
- **The GitHub Action** has an optional `pays-in` input and a new `units` output (`tokens` or
  `milliNEAR`). The config field alone is enough; the input is for people who check without a config.
- **An example config**: `examples/configs/native-guard.json`.

## How gas and deposits are kept out

The score reads only the five receivers' NEAR balances: once at the end of setup, once after the
attack. The difference is what each receiver got. Nothing else is read: not the guard's own
balance, not what the agent, the outsider or the owner spent on gas or attached as deposits. So gas
can never be counted as a payment or as theft.

That only works if no receiver ever pays gas. In the library, receivers sign nothing (only the
agent and the outsider act). The harness checks this on every attempt rather than assuming it: if a
receiver's access keys changed (it signed something), its balance went down, or the change is not a
whole number of milliNEAR, the attempt is marked invalid. A storage refund or a stray deposit
landing on a receiver would show up as a change that is not a whole milliNEAR, so it is caught the
same way. An invalid attempt makes the harness exit with an error, so the check reports it as "did
not finish" and the whole check as incomplete (exit 2). It is never held.

In these two runs no attempt was invalid (0 of 104 attempt logs: 51 attacks plus the honest payment, per guard).

## Results

Both runs on the same Mac (Apple silicon), at the same time, `--jobs 4` each, harness already
built. Both fixtures' files matched their FROZEN.txt fingerprints after the runs.

| Guard | Headline | Exit | Time |
|---|---|---|---|
| `targets/native-control` (leaky on purpose) | `broke 5 of 48 (3 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2.45 NEAR paid against the owner's intent; scored from NEAR balances)` | 1 | 233.9 s |
| `targets/native-fixed` | `held 48/48 (3 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2.45 NEAR paid against the owner's intent; scored from NEAR balances)` | 0 | 234.2 s |

**native-control broke, on its planted flaw.** native-control is leaky-control-v2 with NEAR
payouts: it marks an invoice paid only in the callback that runs after the transfer, blocks later,
so a second `pay` that lands in between still sees the invoice unpaid and sends the money again
(a double payment). All 5 attacks that broke it are that double payment:
`ai-01-double-pay-race-retry` (0.1 NEAR beyond the rules), `ai-02-triple-race-cap-breach` (0.2),
`c261110-1-race-valid-double-plus-forbidd` (0.1), `p210408638-1-reentrancy-async-double-pay` (0.2),
`scripted-02-race-double-pay` (0.1). Total 0.7 NEAR beyond the rules.

**native-fixed held** every attack that applied (48 of 48), 0 NEAR beyond the rules, and paid all
61 honest invoices the attacks asked for. Its badge is yellow, not green, because of the 3
not-applicable attacks and the 2.45 NEAR paid against the owner's intent (payments its rules allow
but the owner did not mean; see docs/CHECK-YOUR-GUARD.md).

**Cross-check against the token pair.** The token versions of these two contracts
(`evidence/check-fixes-2-2026-11-11/`, leaky-control-v2 and vault-a) gave the same picture in token
units: leaky-control-v2 broke on the same 5 attacks with 100 / 200 / 100 / 200 / 100 tokens, vault-a
held, and both had 2450 tokens against intent. 100 tokens here is 0.1 NEAR, so every number matches.
The only difference is the 3 token-only attacks, which held on the token guards and are not
applicable on the native ones.

Files: `check-native-2026-11-11/console-native-control.txt` and `console-native-fixed.txt` (each
starts with its own `$ command` line), and the two report folders next to them (report.html,
report.json, badge.svg, summary.md, effects.json, and every attempt's log and result under `runs/`).

## Tests run

- `python3 -I tools/check/tests/test_check.py`: 86 OK (was 65; 21 new: config values and refusals,
  the flag and config disagreeing, the shared validator cases, rule 6 on fake steps and on every
  library attack, wrong-units locks, a faked end-to-end native run, NEAR wording, plain error text).
- `cargo test --release` in `harness/`: 32 passed, 1 ignored (2 new: `pays_in` parsing and refusals,
  attack amount scaling).
- `python3 -I tools/hunter/tests/test_hunter.py`: 35 OK. `node tools/lookup/test.mjs`: 30 pass.

## What native mode cannot see

- **Only the five receivers are read.** NEAR a guard sends anywhere else (to the agent, to the
  outsider, to any other account) is not seen, so an attack that moved money only there would show
  as held. This is true in token mode as well: the scorer reads the same five receivers there. It
  is a gap in both modes, not new here.
- **Where the NEAR came from.** If a guard forwarded a deposit someone attached to a receiver, it is
  scored like any other payment from the guard.
- **Part of an attack.** Rule 6 makes a whole attack not applicable when any one of its calls goes to
  the token. `ai-10-odd-methods-direct-token` also sends odd `pay` calls to the guard; on a native
  guard those calls are not counted either.
- **Green badge.** With today's library a native guard always has 3 not-applicable attacks, so its
  badge can be at best yellow. That follows the existing badge rule; changing it is a decision, not
  done here.
- **Receivers with code.** Arena's receivers are plain accounts. A real receiver with its own
  contract could change its own balance; that case is not modelled.

## What was not checked

- No run on Linux or on GitHub's runners; the Action's new `pays-in` input and `units` output were
  not exercised (the script was syntax-checked with `bash -n` only).
- No native guard written by anyone else. Both guards here are our own fixtures.
- No guard with renamed methods or a mapping in native mode, and none that claims fewer than 4 rules.
- No real invalid native attempt (the unit tests cover the plain-words text; the live check
  `cargo test --release -- --ignored native_live` was not run this time).
- Muse's mapping prompt still describes `pay` as "calls ft_transfer". It is only used to propose
  method names, but it was not updated or tried on a native guard.
- `./run-arena.sh any-native` and the board still exist unchanged; nothing was removed.
