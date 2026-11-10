> **Correction (round 2):** the counts in this file include the honest-payment check as if it were an attack (so "52" here is 51 attacks plus that one payment, and "held N/N" is one too high), and its "against the owner's intent" totals include attacks that were not applicable (7150 for contracts/guard; 1000 when only attacks that ran are counted). `evidence/check-fixes-2-2026-11-11.md` corrects that.

# `arena check` fixes: no more false "held" (run tag 2026-11-11)

An adversarial review found ways `./arena check` could print "held", exit 0 and show a green badge
when nothing had really been tested. This file records what was fixed, the rule now used, and
fresh runs of the same five guards as `evidence/check-2026-11-11.md`. `2026-11-11` is the run tag
for this build series, not the date the runs happened (2026-11-10 local).

Everything here ran on a local NEAR sandbox. "Held" always means: it held these attacks on a local
sandbox. It is not a proof.

## The five guards, before and after

| Guard | Before (`evidence/check-2026-11-11/`) | Now (this folder) | Exit |
|---|---|---|---|
| vault-a | `held 52/52` | `held 52/52 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap))` | 0 |
| leaky-control-v2 | `broke 5 of 52` | `broke 5 of 52 (0 not applicable; rules claimed: all 4 ...)`, 700 tokens beyond the rules | 1 |
| contracts/guard, `fixed` | `held 52/52` | `held 20/20 (32 not applicable; rules claimed: none; not in the guard: add_payee, remove_payee, cancel_invoice, set_daily_cap, set_agent, get_config, is_payee, paid_today)`, yellow badge | 0 |
| contracts/guard, `vulnerable_fixture` | `broke 6 of 52` | `broke 6 of 21 (31 not applicable; rules claimed: none; not in the guard: ...)`, 1100 tokens beyond the rules | 1 |
| renamed guard + mapping | `held 52/52` | `held 52/52 (0 not applicable; rules claimed: all 4 ...)` | 0 |

So the guards that claim all four rules score exactly as before. The contracts/guard runs were the
ones overstating: 32 (fixed) and 31 (vulnerable) of their 52 "held" attacks tested nothing the guard
claims. Tokens beyond the rules and against the owner's intent are unchanged for all five.

Report folders: `vault-a/`, `leaky-control-v2/`, `guard-fixed/`, `guard-vulnerable/`, `renamed-guard/`.
Console captures: `console-vault-a.txt`, `console-leaky-control-v2.txt` (exact command line first,
then the output as printed), `guard-fixed.console.txt`, `guard-vulnerable.console.txt`,
`renamed-guard.console.txt`. The vault-a, guard-fixed and renamed runs ran one after another, at the
same time as the other three (two checks sharing the machine): 224 to 274 s each.

## The rule for "not applicable" (finding 1)

An attack that made the guard pay beyond its rules is always **broke**. Otherwise it is **not
applicable** when at least one call it sent to the guard (views do not count):

1. uses a starting invoice that was never created on this guard (its rule is not claimed);
2. calls an owner method for a rule the guard does not claim (cancel, payee list, daily cap);
3. calls a role method the guard does not have, or NEAR answered "no such method" (MethodNotFound) for a role method;
4. calls an owner method whose effect Arena could not confirm in preflight;
5. or, when the guard claims no daily cap: pays different invoices that add up to more than Arena's cap of 500.

Any other attack is **held**, even if the guard refused every call (an outsider's pay being refused
is a real "held"). One deliberate exception to "any MethodNotFound": a "no such method" answer for a
name that plays no role (an attacker probing for a hidden method) does not count, because the
guard really has no such method and that is what the attack checks. Code:
`tools/check/applicable.py`; tests: `NotApplicable` in `tools/check/tests/test_check.py`.

The rule is strict on purpose: an attack that mixes a real test (pay an existing invoice twice)
with a call that tests nothing (pay an invoice that was never created) is not applicable, not held.
On contracts/guard `fixed`, the 32 split as: 20 use an invoice that was never created, 6 test the
cap only, 5 both, 1 calls an owner method the guard does not have. 10 of the 32 had every call
fail; the other 22 had at least one call that went through.

"Held N/N" now counts only attacks that really ran against a rule the guard claims. Next to every
held or broke count, in the console headline, `badge.svg`, `shields.json`, `summary.md`,
`report.html` and `report.json`, Arena shows: how many were not applicable, which of the 4 rules the
guard claims, role methods the guard lacks (badge: their number; everywhere else: their names), owner
methods not confirmed, and `subset: K of N attacks` for an `--only` run. The badge is green only when
none of that applies; otherwise yellow.

Console: each attack row's third column is one word. The new word is `not-applicable`.

## What the board says for our own guards

`compare-with-board.txt`, from `tools/check/compare_board.py`. A "not applicable" row against a
board "held" with 0 tokens on both sides is not counted as a difference (no token moved either way),
but it is listed on its own line, because the board's "held" claims more than the run showed.

| Guard | Same as the board | Different | Board says held only because nothing ran |
|---|---|---|---|
| vault-a | 52 | 0 | 0 |
| leaky-control-v2 | 52 | 0 | 0 |
| guard-fixed | 20 | 0 | 32 |
| guard-vulnerable | 21 | 0 | 31 |
| renamed guard (vs board vault-a) | 52 | 0 | 0 |

So **63 board cells for our own guards are "held" only because nothing ran** (32 for guard-fixed,
31 for guard-vulnerable). The board was not changed.

## Owner methods mapped to a method that does nothing (finding 2)

Each owner role on vault-a was mapped, one at a time, to `contract_source_metadata`, a view that
does nothing (inputs: `noop-inputs/`). Preflight now looks at each owner method's own visible effect
through the guard's views on a fresh sandbox (`harness/src/effects.rs`): is_payee after adding and
removing payees, get_invoice of the cancelled invoice against its uncancelled twin, get_config
before and after a cap change and an agent change. It never calls pay and never asks whether pay
honours a rule; that stays the attacks' job.

| Role mapped to a no-op | What the check now says | Exit |
|---|---|---|
| add_payee | `arena: not run`: setup fails, approve_invoice for inv-pay refused ("receiver is not a payee") | 2 |
| remove_payee | `arena: not run`: "the owner removed lin, but `is_payee` still says lin is a payee" | 2 |
| cancel_invoice | `arena: not run`: "`get_invoice` shows it exactly like the uncancelled inv-mid (\"Approved\")" | 2 |
| set_daily_cap | `arena: not run`: "the owner set the cap to 400, but `get_config` still shows 500" | 2 |
| set_agent | `arena: not run`: "the owner changed the agent, but `get_config` still shows the old agent" | 2 |
| set_agent, and no view can show it (get_config mapped to a private callback) | `arena: held 51/51 (1 not applicable; ...; not confirmed: set_daily_cap, set_agent)`, yellow badge | 0 |

Consoles: `noop-<role>.console.txt`, `noview-set_agent.console.txt`; reports in the matching folders.
The last row is the "no view exists" case: the run finishes, but the headline says which owner
methods are not confirmed, and the one attack that calls one of them (`bypass-02-bypass-owner-method`)
is not applicable.

## Reviewer's repro script

`repro-before.txt` (tools/check at commit 525c248) and `repro-after.txt` (working tree, plus a few
added lines for cases 1, 1b and 5, with their script text). Before: 6 bad configs accepted, an
uncaught IndexError on a 13-byte wasm, a fake "held 52/52" heading injected into summary.md, and
`held 1/1` for `--only nope` with the library problem hidden. After: all 6 refused, a plain WasmError,
the injected text stays inside a longer code fence, and the report shows "incomplete" with the
subset and the library problem. Cases 1 and 1b print `problems: []` both times on purpose (a missing
OPTIONAL role does not stop a run); what changed is that those roles are now listed in every output
and attacks touching them are not applicable, shown in the added lines.

## Other findings

- **Partial attack list (3).** A file the attack library cannot load stops the run (exit 2, listed).
  `--only` with any unknown id, or with none, is an error. A subset run says `subset: K of N attacks`.
- **Crashes (4).** The report files of the previous run are deleted before anything else runs; an
  unexpected error gives "Arena itself hit an unexpected error ..." and exit 2; Ctrl-C exits 2 (not tested); a
  missing `cargo` is a plain message. Exit 1 now only means "over the --fail-on line".
- **Validators (5).** Python and Rust read the same 30 raw-text cases (`tools/check/tests/validator-cases.json`)
  and agree on all of them (`ValidatorsAgree` in Python, `agrees_with_the_python_validator` in Rust).
- **summary.md (6).** Untrusted text is backslash-escaped, with backticks, pipes and newlines removed;
  error text sits in a fence longer than any run of backticks inside it.
- **Daily cap and expiry (7).** A config that claims the cap but passes no `$daily_cap` /
  `$daily_cap_number` is refused, in both validators. Expiry in `s` or `ms`: checked. For a guard that
  follows the interface ("payable while block time < expiry"), the rounding could not produce a false
  "broke": the guard was told an expiry up to 1 s EARLIER than the scorer used, so it could only refuse
  more. The two still disagreed about that last second, so setup now approves with the rounded value
  and scores against the same value (`expiry_in_seconds_is_exact_on_both_sides`).
- **Stale build (8).** Rebuild when any harness or test-token source file is newer than the built file.
- **Paths (9).** report.json, report.html, summary.md, console and the run logs show paths relative to
  the folder the check ran from (or a file name, or `<report>`, `<arena>`, `~`).

## Unit tests and verify

- `python3 -I tools/check/tests/test_check.py`: 49 passed (`unit-tests-python.txt`).
- `cd harness && cargo test --release`: 30 passed, 1 ignored (`unit-tests-rust.txt`).
- `./verify.sh fast`: 5 passed, 0 failed, 196 s (`verify-fast.txt`). The files it rewrites were
  restored with `git checkout`; `evidence/verify-summary.log` keeps its new line. Without
  `--guard-config` the harness writes the same result JSON as before: the new `setup` block and the
  new `effects` command exist only for `--guard-config` runs.

## Not done or not tested

- The no-op mapping table was run on vault-a only, not on the renamed guard.
- A guard whose owner method stores a timestamp would show "not confirmed" for cancel instead of
  "confirmed": the check compares the two invoices field by field when their status matches.
- The Action was not run on GitHub; the files another agent owns (action.yml, workflows, action
  scripts, the `arena` launcher) were not edited.
