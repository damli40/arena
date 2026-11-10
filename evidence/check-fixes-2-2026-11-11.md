# `arena check` fixes, round 2 (run tag 2026-11-11)

A second review of `./arena check` found places where a run could still print a clean-looking
result that was not true. This file says what was wrong, what changed, and shows fresh runs.
Everything here ran on a local NEAR sandbox on one Mac. Nothing ran on GitHub.

## What was wrong

1. **The honest payment was counted as a held attack.** Before the attacks, Arena makes one normal
   payment to check the guard works. That payment was added to the attack counts. So a run where
   no attack tested anything the guard claims still said `held 1/1` and exited 0. Our full runs
   said "52 attacks" when there are 51 attacks plus that one payment.
2. **The board said "held" where the check said "tested nothing".** On Arena's own two
   contracts/guard entries, 63 board cells said "held" only because nothing ran, and the honest
   payment was counted as a result on every guard.
3. **The home page said "33/33 tests held".** 3 of those rows are honest payments and 1 is a stress
   test of a rule the guard never claimed.
4. **A guard that could not read Arena's arguments, or that refused honest payments, could still
   get a clean "held".**
5. **The green badge did not match the docs**, the shields.io link left `/` unescaped, and the
   Action's `status` output could not tell a green "held" from a yellow one.
6. **"Against the owner's intent" counted attacks that did not apply** (and the honest payment), so
   `--fail-on against-intent` tripped for reasons that tested nothing.

## What changed

- The honest payment is now its own line ("honest payment: settled") and is in no count, no badge,
  no total. A run where no attack applied ends `incomplete`, exit 2.
- The board uses the same rule as the check (`tools/check/applicable.py`). Cells that tested
  nothing show "not applicable" and are not counted. The honest payment is shown on its own line.
- The home page counts the three kinds of row apart (29 tests of written rules, 1 stress test,
  3 honest payments), read from `evidence/coverage-table.md` at build time.
- A role call the guard could not read ("missing field", "failed to deserialize", "invalid type",
  "Failed to parse") makes the attack not applicable. Honest payments an attack asked for and the
  guard refused, with no reason Arena can see, are counted and shown in the headline, near the top
  of report.html, and keep the badge from green.
- Green now needs: held, 0 not applicable, all 4 rules claimed, nothing missing, unconfirmed or
  refused, **and 0 tokens paid against the owner's intent**. The shields.io link escapes `/`. The
  Action has a new output `full` (`true` only for green).
- Both token totals count only attacks that ran (held or broke). What not-applicable attacks paid
  against intent is shown on its own "not counted" line.

## The repro from the review, before and after

Command: `./arena check contracts/target/wasm32-unknown-unknown/release/guard.wasm --config examples/configs/contracts-guard-fixed.json --only ai-04-cap-fill-then-big`
(full consoles: `repro-before.txt`, `repro-after.txt` in `evidence/check-fixes-2-2026-11-11/`).

Before:

```
preflight ok (11.6 s). Running 2 attacks, 4 at a time ...
arena: held 1/1 (1 not applicable; rules claimed: none; not in the guard: ...; subset: 2 of 52 attacks)
exit=0
```

After:

```
preflight ok: the honest payment settled (11.4 s). Running 1 attack, 4 at a time ...
arena: incomplete (1 not applicable; rules claimed: none; not in the guard: ...; subset: 1 of 51 attacks)
  honest payment: settled (the preflight check, not an attack; not in any count)
  attacks: 0 held, 0 broke, 1 not applicable, 0 did not finish
COULD NOT FINISH:
  No attack tested a rule your guard claims, so there is nothing to report as held.
exit=2
```

## Fresh runs (all in `evidence/check-fixes-2-2026-11-11/`)

| Guard | Console | Headline | Badge | Exit |
|---|---|---|---|---|
| vault-a | `console-vault-a.txt` | held 51/51 (0 not applicable; all 4 rules; 2450 tokens paid against the owner's intent) | yellow | 0 |
| leaky-control-v2 (leaky on purpose) | `console-leaky-control-v2.txt` | broke 5 of 51 (same brackets) | red | 1 |
| vault-a, through the Action's script step | `action-local.txt` | held 51/51, `status=held`, `full=false` | yellow | 0 |

vault-a is yellow, not green, because 2450 tokens went to payees the owner had approved but did not
mean to pay in those runs (the prompt-injection attacks). Its rules held; the owner's rules were wide.
With `--fail-on against-intent` that run would exit 1, which is the point of that line.

Against-intent totals, old count vs new (only attacks that ran): vault-a 2450 vs 2450;
contracts/guard (fixed and vulnerable_fixture) 7150 vs 1000 (6150 came from attacks that did not
apply). Board vs check, attack by attack (`compare-with-board.txt`): 51 of 51 the same for
vault-a, leaky-control-v2, guard-fixed and guard-vulnerable.

## What was not checked

- Nothing ran on GitHub or on Linux. `action-local.txt` runs only the Action's script step, on macOS.
- guard-fixed, guard-vulnerable and the renamed guard were not re-run with the new code; their
  round-1 results were re-classified with the new rules (no change in any attack's class) and
  compared with the board.
- The honest-refusal count trusts two explanations: an owner rule change in the attack, or the cap.
  A guard that refuses for another reason Arena cannot see is counted as refusing.
- The owner-method preflight still trusts the guard's own views (listed in the docs' limits).
