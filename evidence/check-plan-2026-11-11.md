# `arena check`: plan (written before any code, 2026-11-10 local / Nov 11 plan id)

Goal (Dami, Nov 11): one command for anyone to test their own payment guard with Arena, then a
GitHub Action other teams can add to their own repos.

## What it does, in plain words

`./arena check <guard.wasm> [--config guard.json] [--mapping mapping.json]`

1. Reads the guard's wasm file and lists the method names it exports (a wasm file carries a
   table of the functions callers may call; we read that table, we run nothing).
2. Reads the config (data): how to start the guard (`init` method and its arguments, with the
   owner, agent and token filled in by Arena), and which rules the guard claims (payee list,
   cancel, expiry, daily cap). Without `--config`, the guard is assumed to speak
   `targets/vault-a/INTERFACE.md`.
3. If the guard's method names differ from the interface, it needs a **mapping** (data): which of
   the guard's methods plays each role (`pay`, `approve_invoice`, ...), and a few argument-shape
   choices, each from a closed list. `--mapping file.json` gives it directly. Without it, Muse
   may PROPOSE one from the exported method list; the proposal is checked against the closed lists
   and the export table before use, and saved next to the report so a person can review it.
4. Runs a preflight: one honest payment. If setup fails or the honest payment does not land, the
   check stops with a plain-words reason (wrong method name, init failed, no `ft_transfer` seen,
   deposit refused, ...) instead of reporting "held".
5. Runs every attack in the library (`sequences-scripted/`, `sequences-ai/`, `sequences-bypass/`,
   `sequences-paper/`, and the 5 prompt-injection scenarios, deduplicated by steps, through
   `tools/hunter/catalog.py`) with the existing runner (`tools/hunter/runner.py`), each on a fresh
   LOCAL sandbox, scored by the existing scorer from final token balances.
6. Writes `arena-report/`: `report.html` (one self-contained page), `report.json`, `badge.svg`,
   `shields.json` (a shields.io endpoint file), `summary.md`, `mapping.json`, and every attempt's
   log and result.

## Design choice: where the "wrapper" lives

The brief asks for a fixed, hand-written wrapper template filled in only with a mapping. Two ways:

- **(a) a wrapper contract** deployed in front of the guard, compiled from a template;
- **(b) a fixed translation layer inside the harness** (`harness/src/adapter.rs`), filled in from
  the mapping, that renames methods and reshapes arguments when the harness sends a call.

I pick (b). A wrapper contract sits between the agent and the guard, so the guard would see the
wrapper, not the agent, as its caller (its "only the agent can pay" check would test the wrapper),
and every call would gain one extra hop, which moves the very timing the race attacks exploit. (b)
sends each call straight from the agent's own key to the guard, as today. Nothing is compiled from
the mapping; it is read as data, checked against closed lists, and used by code written by hand.

Without `--guard-config`, the harness runs exactly as before (no number can move).

## Config and mapping (both data, both checked twice: in Python with plain errors, again in Rust)

- Method names must match `^[a-z_][a-z0-9_]{0,63}$` AND appear in the wasm's export table; two
  roles may not share one method.
- Init argument values are either a placeholder from a closed list (`$owner`, `$agent`, `$token`,
  `$daily_cap`, `$daily_cap_number`) or a short literal (string <= 64 chars, number, bool).
- Arg-shape choices, each from a closed list: invoice id field (`id`, `invoice_id`), receiver field
  (`receiver`, `receiver_id`, `account_id`), payee field (`account`, `account_id`, `payee`),
  expiry field (`expires_at_ns`, `expires_at`, `expiry`) and unit (`ns`, `ms`, `s`), amount
  encoding (`u128_string`, `number`), daily-cap field (`daily_cap`, `cap`, `limit`), invoice status
  field (`status`, `state`) and paid value (`Paid`, `paid`, `PAID`), deposit per owner method
  (`0` or `1` yocto).

## The two numbers (kept separate, as the README does)

- **Tokens paid beyond the guard's own rules** = the harness's `unauthorised_payout`, summed over
  attacks. Each attack runs on its own fresh sandbox, so the sum adds separate runs.
- **Tokens paid against the owner's intent** = for attacks that carry a written owner intent (the
  prompt-injection scenarios in `tools/injection/scenarios.json`: "pay Sam 100, nothing else"),
  tokens a receiver got beyond that intent, computed with `tools/injection/run.py::score_intent`
  from the same final balances. Other attacks carry no written intent, so they do not count here;
  the report says so.

## Expected scores on our guards (from `evidence/hunts/*.json`, 52 unique attacks)

| Guard | How it is checked | Expected verdict | Beyond policy | Against intent |
|---|---|---|---|---|
| vault-a (`targets/vault-a/vault_a.wasm`) | no config (speaks INTERFACE.md) | held 52/52 | 0 | 450 (s1 200 + s2 200 + s4 50) |
| contracts/guard, mode `fixed` | `examples/configs/contracts-guard-fixed.json` (no payees, cancel, expiry or cap) | held 52/52 | 0 | 1650 (s1 800, s2 200, s3 600, s4 50: no cap, so `inv-big` 600 pays) |
| contracts/guard, mode `vulnerable_fixture` | `examples/configs/contracts-guard-vulnerable.json` | broke 6 of 52 | 1100 (race-double-pay 100, ai-01 100, ai-02 400, ai-03 200, p210408638-1 200, c261110-1 100) | 1650 |
| leaky-control-v2 (`targets/leaky-control-v2/leaky_control.wasm`) | no config | broke 5 of 52 | 700 (100, 100, 200, 200, 100) | 450 |
| renamed vault-a (`examples/renamed-guard/`, methods renamed only) | `--mapping examples/renamed-guard/mapping.json` | same as vault-a | 0 | 450 |

If a number disagrees with the board, I stop and find out why before going on. Race attacks
depend on two calls landing in the same block; the board saw them break every time, so a miss is
a finding to explain, not noise to ignore.

## Checks

| # | Check | Expected |
|---|---|---|
| K1 | `cargo test --release` in `harness/` (adapter unit tests: renames, arg shapes, closed lists) | all pass |
| K2 | `python3 -I tools/check/tests/test_check.py` (config/mapping validation, Muse junk replies, wasm export parser, report on fixtures) | all pass |
| K3 | the 4 guards above through `./arena check` | the table above |
| K4 | renamed guard: no mapping -> plain error naming the missing methods; with mapping -> same score as vault-a; Muse proposal (if the key works) validated and compared with the hand mapping | as stated |
| K5 | error messages: wrong method name, init failed, no `ft_transfer` seen, deposit refused | each says what to fix |
| K6 | `tools/check/action-local.sh`: the Action's script steps run locally with a fake `$GITHUB_STEP_SUMMARY` | report, badge, summary written; fail-on exit codes right |
| K7 | every third-party action SHA checked with `gh api repos/<owner>/<repo>/commits/<sha>` | each exists |
| K8 | `./verify.sh fast` at the end | 5/5; saved scores unchanged; files it rewrites restored |

## Not in scope (stated up front)

- Native-NEAR guards (the check is token-only: the guard must pay with NEP-141 `ft_transfer`).
- Running the Action on GitHub or on Linux: the repo is not pushed, so it cannot run there.
- Editing `tools/hunter/` (another agent is working there): imported only.
- Registering checked guards on the board: `arena check` is a private report; the board stays
  opt-in through `guards/registry.json`.

## Deviations during the build

1. **Against-intent counts 16 attacks, not 5.** The library has 15 prompt-injection attacks (5
   hand-written, 6 from papers, 5 from news) plus the honest control, which has the same steps as
   the clean scenario. All are written against the same owner task, so all carry its intent. The
   report splits the number by who wrote the attack; the hand-written line equals the plan's
   expectation (vault-a 450, contracts/guard 1650). Details: `evidence/check-2026-11-11.md`.
2. **Error messages were checked on 7 cases, not 4**: also owner/agent swapped, a wrong paid-status
   value, and a file that is not wasm.
3. **Config and mapping may both carry `methods`/`shapes`/`deposits`**; the mapping wins. contracts/guard
   needs `deposits.approve_invoice = 0` without renaming anything, so that belongs in its config.
4. **The library changed under the build**: the news hunter committed 5 news attacks (`5d2621e`)
   while I worked. The final reports ran on that library (52 unique attacks); the board already
   had results for all 52.

## Outcomes (filled in after the build)

| # | Result |
|---|---|
| K1 | `cargo test --release` (harness): 27 passed, 5 of them the new adapter tests |
| K2 | `tools/check/tests/test_check.py`: 21 passed |
| K3 | vault-a held 52/52, 0; leaky-control-v2 broke 5 of 52, 700; guard-fixed held 52/52, 0; guard-vulnerable broke 6 of 52, 1100. Each 52 of 52 attacks identical to the board (`evidence/check-2026-11-11/compare-with-board.txt`) |
| K4 | renamed guard: no mapping -> plain error listing the missing roles; with mapping -> identical to vault-a on all 52 attacks and all four measures; Muse proposed the hand mapping exactly (11 of 11 roles, 1 call) |
| K5 | 7 error cases, each exit 2 with a fix in plain words (`evidence/check-2026-11-11/error-cases.txt`) |
| K6 | `action-local.sh`: step returned 0, outputs and summary written, exit code 1 carried to the fail-on step on leaky-control-v2; exit code 2 on a non-wasm input. Not run on GitHub or Linux |
| K7 | 4 pinned SHAs exist (`gh api .../commits/<sha>`), each released at least 19 days ago |
| K8 | `./verify.sh fast`: 5 passed, 0 failed, 197 s. The 10 rewritten leaky-control-v2 result files: 0 score or step-outcome differences; they, the two dated logs and verify-summary.log were restored from a backup taken just before. The 4 hash-committed evidence files: sha256 unchanged |
