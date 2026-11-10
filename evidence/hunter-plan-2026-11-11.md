# Paper hunter: plan (written before any code, 2026-11-10 local / Nov 11 plan id)

Goal (Dami, Nov 11): be the default benchmark for anyone who builds a guard. New ways to break a
guard plug in as data. An always-on AI attacker (Muse Spark) reads recent security papers and turns
them into attacks, on demand or daily, against our guards and opt-in guards only.

## Design in plain words

1. **An attack is a data file.** It is a list of steps from the harness's fixed vocabulary
   (`call`, `view`, `race`, `wait_blocks`, `wait_seconds`, `add_key`), plus a `meta` block saying
   who wrote it, why, what it tries to break and what a safe guard should do. The harness already
   ignores keys other than `name` and `steps`, so adding `meta` inside the same file changes no
   step and no result. (A sidecar `.json` next to the sequence would be read by `harness run` as a
   sequence and fail, so the metadata goes inline.)
2. **A guard is a registry entry.** `guards/registry.json` lists each opt-in guard: its wasm, its
   sha256, the harness flags that run it, which interface it speaks, and the owner's opt-in line.
   Only `vault-a`, `leaky-control`, `leaky-control-v2`, `native-control`, `native-fixed`,
   `guard-fixed`, `guard-vulnerable` go in. `targets/entrant-*` never do.
3. **The hunter** (`tools/hunter/`, Python stdlib only):
   fetch recent arXiv papers -> pick at most 5 not used before -> ask Muse for at most 3 attacks per
   paper, as data only -> validate every attack against the schema (reject and log anything else)
   -> dedupe against every attack we already have (same canonical steps = same attack) -> run each
   new attack on a fresh local sandbox against every registered guard with `arena-harness attempt`
   -> score with the existing scorer -> write `evidence/hunts/<date>-<id>.md` + `.json` -> save
   attacks that broke something to `sequences-paper/` -> rebuild `site/board-data.json`.
4. **Nothing the attacker writes is executed** except through the harness's fixed step actions.
   Muse output is parsed as JSON, validated field by field (whitelisted keys, bounded numbers,
   bounded string lengths, method names matching `^[a-z_][a-z0-9_]{0,63}$`, actors only
   `agent`/`outsider`, targets only `vault`/`token`). Paper text goes to Muse inside a block marked
   untrusted; the hunter never acts on it.

## Deviation found while reading the code (decided before coding)

- `contracts/guard` does **not** speak `targets/vault-a/INTERFACE.md`: `new(mode, owner, agent,
  token)`, `approve_invoice(id, receiver, amount)` with no expiry, no payees, no daily cap, no
  `get_config`. So `--wasm` cannot run it. I add two harness targets, `guard-fixed` and
  `guard-vulnerable`, with their own setup branch: same accounts, token, funding, function-call
  agent key; the owner approves only the four invoices this guard can express (`inv-pay`,
  `inv-small`, `inv-mid`, `inv-big`); `inv-cancel`, `inv-expire`, `inv-removed` are never created
  and authorise nothing. The guard claims no daily cap, so the scorer's cap is set to "none" for
  these two targets (the cap term cannot fire). Its policy is "each approved invoice pays at most
  once, only the agent can pay", and the board says so next to its rows.
- A `view` of a method the guard does not have currently aborts the whole attempt as a harness
  error (e.g. `get_config` on `contracts/guard`). I change `do_view` to record a failed view as a
  step outcome and carry on. Views change no state; no frozen run had a failing view (all reached
  their summary), so frozen numbers cannot move. Checked by `verify.sh full` after.
- `leaky-control` (v1) cannot be set up: 4 owner methods lack `#[payable]`, so setup fails before
  any attack (`evidence/arena-2026-11-09-positive-control-v1-setup-failure.log`). It is listed in
  the registry with `runnable: false` and that reason; the hunter skips it and the board shows
  "setup fails (known, frozen)".

## Files

| File | What |
|---|---|
| `schema/attack.schema.json` | JSON schema: a sequence file with its `meta` block |
| `schema/guard-registry.schema.json` | JSON schema: `guards/registry.json` |
| `tools/hunter/validate.py` | the validator the hunter enforces (stdlib; the schema documents it, `--self-test` checks they agree) |
| `tools/hunter/catalog.py` | load every attack, canonical form, dedupe |
| `tools/hunter/arxiv.py` | arXiv API fetch, parse, keyword filter, used-paper cache |
| `tools/hunter/muse.py` | Muse client (same endpoint/model as `tools/injection/run.py`), prompt, parse |
| `tools/hunter/runner.py` | attack x guard via `arena-harness attempt`, parallel, per-attempt timeout |
| `tools/hunter/hunt.py` | the CLI: `hunt`, `--library`, `--paper`, `--offline-attacks` |
| `tools/hunter/board.py` | builds `site/board-data.json` from `evidence/hunts/*.json` |
| `tools/hunter/tests/test_hunter.py` | adversarial unit tests (junk, injection text, duplicates, no papers, runaway waits) |
| `tools/hunter/ci-steps.sh`, `tools/hunter/ci-local.sh` | the CI steps, and a local dry run of exactly those steps |
| `guards/registry.json` | the 7 opt-in guards |
| `docs/ADD-AN-ATTACK.md`, `docs/REGISTER-A-GUARD.md` | how-to for outside people |
| `sequences-paper/` | paper attacks that broke at least one guard |
| `evidence/hunts/` | one `.md` + `.json` per hunt, `used-papers.json` |
| `site/board-data.json`, `site/board.html` | results board data + a standalone fragment (not wired into `site/build.mjs`) |
| `.github/workflows/hunt.yml` | daily cron + on-demand; artifact upload |
| `harness/src/setup.rs`, `harness/src/seq.rs` | guard targets; failed view recorded instead of aborting |
| `run-arena.sh` | new `hunt` mode (frozen checks before/after, then the hunter) |
| `sequences-{scripted,ai,bypass}/*.json` | `meta` block added; steps unchanged (checked by canonical hash vs git HEAD) |

## Checks and expected outcomes

| # | Check | Expected |
|---|---|---|
| C1 | `validate.py` on all 23 existing sequences after backfill | 23 valid; canonical steps hash equal to the HEAD version of each file |
| C2 | unit tests: junk JSON, prose, extra keys, owner actor, 10^9 wait, 50 steps, script tags, duplicate, empty paper list | every bad input rejected with a logged reason; no crash; empty paper list writes a "no papers" hunt file |
| C3 | `--library` hunt: every existing attack x every runnable guard | leaky-control-v2 and native-control break on `race-double-pay` (as frozen evidence); guard-vulnerable breaks on a double-pay race; vault-a, native-fixed, guard-fixed hold everywhere |
| C4 | one real hunt on recent papers | whatever it is, reported honestly (0 breaks on hardened guards is a valid result) |
| C5 | `--paper <id>` hunt on a paper about state inconsistency / races | path from paper -> attack -> break on at least one leaky control, if Muse proposes a race; if not, say so |
| C6 | `ci-local.sh` | runs the same steps as the workflow (offline Muse stub), produces the artifact folder |
| C7 | `verify.sh full` before and after | 43/43 both times; frozen evidence unchanged |

## Cost bounds

- At most 5 papers per hunt, at most 3 attacks per paper (so at most 15 new attacks).
- Hard cap of 20 Muse calls per hunt (1 per paper + at most 1 repair retry each); the hunt stops
  calling Muse when the cap is hit and says so.
- Per Muse call timeout 180 s; per harness attempt timeout 240 s; whole-hunt timeout 60 min.
- Step bounds per attack: <= 12 steps, races of 2-4 calls, `wait_blocks` <= 200,
  `wait_seconds` <= 30 each and <= 60 total, `gas_tgas` 1-300, `deposit_yocto` <= 10^18.
- Local sandbox only. No testnet, no mainnet.
- One attempt measured at ~15 s; 15 attacks x 6 runnable guards = 90 attempts, ~6 min at 4 jobs.

## Not in scope (stated up front)

- Running Muse as the *victim* agent for paper-derived injection scenarios (it costs up to 8 calls
  per trial). Injection scenarios from papers are validated and run as the pays a fully fooled
  agent would make ("compromised" mode, as in `tools/injection`).
- Method-name mapping for outside guards with a different interface: the registry records the
  mapping, but the harness only runs guards whose names match `INTERFACE.md`; others need a thin
  adapter contract. Stated in `docs/REGISTER-A-GUARD.md`.

## Deviations during the build

1. **Every new hunt runs a canary** (the scripted double-pay race on every guard). Not in the
   first plan. It is the pipe check Dami asked for: the leaky controls must break on it, or the hunt
   is marked untrusted, nothing is saved, and the board ignores it. Costs 6 attempts (~30 s).
2. **Metadata backfill covered 23 files, not 20**: the 3 bypass sequences got a `meta` block too.
   The 5 injection scenarios in `tools/injection/scenarios.json` were NOT edited; the catalog derives
   their metadata in code (`catalog.py`), so the injection evidence files stay byte-identical.
3. **The "before" verify ran partly after the metadata backfill** (the backfill landed while it was
   running). The harness ignores keys other than `name`/`steps`, and it still passed 43/43 with the
   old harness binary, which is itself a check that `meta` changes nothing.
4. **Verify rewrites tracked result files** (`evidence/results/*`). After each verify I compared the
   score and step outcomes of every rewritten file with HEAD (0 differences before) and restored
   them from git, so committed evidence does not move.
5. **Built-from-source fingerprint for `contracts/guard`.** Its wasm is built, not frozen, and a
   Linux CI build will not have the same bytes as a macOS one. The registry pins the sha256 of
   `contracts/guard/src/lib.rs` and `Cargo.toml` instead, and each hunt records the wasm sha256 it
   actually ran.
6. **AutoRedTeamer adoption (Dami, Nov 11, after the plan).** Four parts adapted from AutoRedTeamer
   (Zhou et al., NeurIPS 2025, arXiv 2503.15754): (a) papers are scored before attacking (novelty +
   distance from the library + reported success; one Muse call for up to 10 candidates; falls back
   to keyword relevance with a logged reason if the call fails); (b) a new attack joins
   `sequences-paper/` only after it ran cleanly on every guard, as `broke` or
   `valid-nothing-broke` (the first plan saved only attacks that broke something); (c) one Muse call
   per hunt may propose up to 2 attacks that join library attacks (`source: combined`, `parents`);
   (d) a memory (`tools/hunter/memory.py`, `evidence/hunts/memory.json`) rebuilt from trusted hunt
   files picks library re-runs: never-tried attack x guard pairs first, then families that broke a
   guard not leaky on purpose. Attack families are computed from the steps, not by the model.
   Budget per hunt: 1 scoring + up to 10 proposal calls (5 papers, 1 repair each) + 1 combine = 12,
   under the cap of 20. The difference from the paper on purpose: their model writes attack code,
   ours writes data only.
7. **Distance formula changed after the first real hunt** (`2026-11-10-papers-c1bea9`). The first
   version compared whole family strings, so a paper about prompt injection scored "distance 4"
   (far from the library) although 4 library attacks already use injection. That over-ranked
   injection papers in that hunt; its file keeps the scores it actually used. The new version
   counts, for each mechanism the paper uses, how many library attacks use it.


## Outcomes (filled in after the build, 2026-11-10 local)

| # | Result |
|---|---|
| C1 | 23 backfilled sequences valid; steps identical to HEAD (canonical hash) |
| C2 | 29 unit tests pass (`tools/hunter/tests/test_hunter.py`) |
| C3 | Library hunt `2026-11-10-library-5303da`: 27 attacks x 6 guards = 162 attempts, 595 s, 0 errors. 10 broke, all on the 3 leaky-on-purpose controls; vault-a, native-fixed, guard-fixed held on all 27 |
| C4 | Real hunt `2026-11-10-papers-c1bea9`: 5 papers read, 13 attacks run (78 attempts), 7 of 20 Muse calls. No paper attack broke anything; 1 combined attack (contains the known race) broke the 3 leaky controls. 13 added to `sequences-paper/` |
| C5 | SAILFISH (arXiv 2104.08638): run 1 `2026-11-10-paper-abc6e6` broke nothing (Muse wrote sequential calls, which cannot overlap). Timing note added to the prompt. Run 2 `2026-11-10-paper-cd8587`: a 2-pay race broke leaky-control-v2, native-control, guard-vulnerable (+200 each), held elsewhere. Paper -> attack -> break path shown, on a known bug class |
| C6 | `ci-local.sh` passed: same 4 steps as the workflow, offline, 42 attempts, owner-actor fixture rejected, planted instruction text flagged, artifact secret-scanned |
| C7 | See the verify logs `evidence/verify-hunter-{before,after}-*` |
