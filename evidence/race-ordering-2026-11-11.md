# Race ordering on the local sandbox (2026-11-11)

**What this file answers.** When Arena "races" two payments today, in which block does each payment's
guard check run, and in which block does the first payment's result come back? Before this file, no
committed result recorded block heights, so the README line "races were tested with both calls in the
same block only" rested on nothing anyone could re-read.

**Where to look.** Section 1 is the existing race in one table. Section 1b is the new timed stagger
(second payment one block later) and the matched pairs. Section 1c is the slow token, race-m2,
race-m3 and the cap race. Section 2 says what changed in the docs.
Section 3 says what this does not show.

Branch `race-ordering` (cut from `universal-guards` at `23a6ce2`), which adds a per-receipt block
trace to every result file (`steps[].receipts`, `harness/src/receipts.rs`). Local near-sandbox only.

## 1. Checkpoint 1: the existing race, traced (15 runs)

The sequence is the unchanged `sequences-scripted/02-race-double-pay.json`: the agent sends two
`pay` calls for the 100-token invoice `inv-pay` without waiting between them (`seq.rs` `do_race`).
3 runs on each of 5 guards, one fresh sandbox per run:

    cd harness && ./target/release/arena-harness attempt ../sequences-scripted/02-race-double-pay.json \
        <--target guard-vulnerable | --target guard-fixed | --target vault | --target control
         | --wasm ../mutants/M5/vault_a.wasm --wasm-label M5> --out <file>

Harness binary built from `23a6ce2` with no changes (sha256 `88476fe0ac6f8dcc...`). Guard wasm
sha256 (first 16 hex): guard-vulnerable and guard-fixed `0382023bed120866` (same bytes, mode set at
init), vault-a `52a40f3200e313c1`, leaky-control-v2 `9b0ea03b25ecee6d`, M5 `e92c54bb2744391c`.
Raw files: `race-ordering-2026-11-11/c1-traces/<guard>-<n>.result.json` and `.log`.
Table printed by `python3 -I tools/race/table.py evidence/race-ordering-2026-11-11/c1-traces/*.result.json`.

| file | guard | per leg: accepted → check → transfer → callback | judge | beyond policy |
|---|---|---|---|---|
| `guard-fixed-1.result.json` | guard-fixed | 79 → 80 → 81 → 82 / 79 → 80 (refused) → - → - | overlap-proven (last check 80, first callback 82) | 0 |
| `guard-fixed-2.result.json` | guard-fixed | 78 → 79 → 80 → 81 / 78 → 79 (refused) → - → - | overlap-proven (last check 79, first callback 81) | 0 |
| `guard-fixed-3.result.json` | guard-fixed | 80 → 81 → 82 → 83 / 80 → 81 (refused) → - → - | overlap-proven (last check 81, first callback 83) | 0 |
| `guard-vulnerable-1.result.json` | guard-vulnerable | 79 → 80 → 81 → 82 / 79 → 80 → 81 → 82 | overlap-proven (last check 80, first callback 82) | 100 |
| `guard-vulnerable-2.result.json` | guard-vulnerable | 78 → 79 → 80 → 81 / 78 → 79 → 80 → 81 | overlap-proven (last check 79, first callback 81) | 100 |
| `guard-vulnerable-3.result.json` | guard-vulnerable | 80 → 81 → 82 → 83 / 80 → 81 → 82 → 83 | overlap-proven (last check 81, first callback 83) | 100 |
| `leaky-control-v2-1.result.json` | leaky-control-v2 | 110 → 111 → 112 → 113 / 110 → 111 → 112 → 113 | overlap-proven (last check 111, first callback 113) | 100 |
| `leaky-control-v2-2.result.json` | leaky-control-v2 | 108 → 109 → 110 → 111 / 108 → 109 → 110 → 111 | overlap-proven (last check 109, first callback 111) | 100 |
| `leaky-control-v2-3.result.json` | leaky-control-v2 | 110 → 111 → 112 → 113 / 110 → 111 → 112 → 113 | overlap-proven (last check 111, first callback 113) | 100 |
| `M5-1.result.json` | M5 | 110 → 111 → 112 → 113 / 110 → 111 → 112 → 113 | overlap-proven (last check 111, first callback 113) | 100 |
| `M5-2.result.json` | M5 | 109 → 110 → 111 → 112 / 109 → 110 → 111 → 112 | overlap-proven (last check 110, first callback 112) | 100 |
| `M5-3.result.json` | M5 | 110 → 111 → 112 → 113 / 110 → 111 → 112 → 113 | overlap-proven (last check 111, first callback 113) | 100 |
| `vault-a-1.result.json` | vault-a | 110 → 111 → 112 → 113 / 110 → 111 (refused) → - → - | overlap-proven (last check 111, first callback 113) | 0 |
| `vault-a-2.result.json` | vault-a | 109 → 110 → 111 → 112 / 109 → 110 (refused) → - → - | overlap-proven (last check 110, first callback 112) | 0 |
| `vault-a-3.result.json` | vault-a | 110 → 111 → 112 → 113 / 110 → 111 (refused) → - → - | overlap-proven (last check 111, first callback 113) | 0 |

How to read a row: "79 → 80 → 81 → 82" means the transaction was accepted in block 79, the guard's
check ran in 80, the token moved the money in 81, and the guard's callback (where a flawed guard
finally writes "paid") ran in 82. "(refused)" means the guard said no at its check, so nothing followed.
The judge column comes from `tools/race/ordering.py` (the one judge: a race only if the last check ran
in a block strictly before the first callback).

**What the numbers say.**

- **15 of 15 runs: both checks ran in the same block, and the first callback came exactly 2 blocks
  later.** Both transactions were also accepted in the same block every time. The absolute block
  numbers differ between guards (78 to 111) only because setup takes a different number of blocks.
- **So the race window was open in every run, by block number:** last check strictly before the first
  callback, 15 of 15.
- **Every flawed guard broke and every fixed guard held, 3 of 3 each:** guard-vulnerable, leaky-control-v2
  and M5 paid 200 for a 100 invoice (100 beyond policy); guard-fixed and vault-a refused the second
  call at its check ("payment already in flight") and paid 100.
- **Later runs, and one that split.** Two more saved sets of the same command on fresh copies:
  `c1-fresh-53f45b3/` (5 runs) and `c1-fresh-d2e2093/` (15 runs), both checks in one block in all
  20. An independent reviewer's fresh `tools/race/c1.sh` run (not saved here; we did not reproduce
  it in 15 tries) had **4 of 5** in one block: on guard-fixed the checks ran in blocks 83 and 84 and
  the first callback in 85, so the judge still called it a proven race, and guard-fixed still held.
  Total: 35 of 35 saved runs, 39 of 40 counting the reviewer's, had both checks in one block; all 40
  were proven races with the same broke/held lists.
- **What this decides:** "both calls in the same block" is what usually happens on the sandbox, not
  what always happens: 1 of 40 runs split by a block. That run was still a race, because one block
  later is still before the callback (section 1b tests that spacing on purpose). It is also the only spacing tested: no run here put the second check
  one block later, which is the case a guard that locks "within the same block only" would fail.

## 1b. Checkpoint 2: the second payment one block later (timed stagger), matched pairs

**The new step.** A `race` step can now say `"offsets": [0, 1]`: send payment 1 right after a new
block is made, then send payment 2 when the chain is one block further, so payment 2's guard check
runs one block after payment 1's (`harness/src/race.rs`). The harness cannot put a transaction in a
block, so it writes down what happened and the judge (`tools/race/ordering.py`) throws away any try
whose checks did not land where asked (`not-produced`, never held or broke).

**Did the timing work? (hit rate)** 20 tries each on guard-vulnerable, three at a time, while other
builders' sandboxes ran on the same Mac:

| sequence | asked | landed where asked | verdicts |
|---|---|---|---|
| `sequences-race/s1-same-block.json` | offsets [0, 0] | 20 of 20 | overlap-proven 20 |
| `sequences-race/s2-next-block.json` | offsets [0, 1] | 20 of 20 | overlap-proven 20 |

Raw: `race-ordering-2026-11-11/c2-hitrate-s{1,2}/` (`hitrate.json` + one result and log per try).
So what it decides: on this machine the timed stagger is reliable enough that "3 counted tries in at
most 5" was never close; no try was thrown away. A busier machine may miss; misses are discarded, so
they cost time, not correctness.

**The new flawed guard, `race-m1`** (`mutants/race-m1/`, wasm sha256 `edcac3a94d71207e...`, built by
`tools/race/build_mutant.sh race-m1`; the diff is `mutants/race-m1/MUTATION.md`). It is vault-a with
ONE flaw: its "payment already in flight" lock refuses a second payment only in the **same block** as
the first; one block later it lets it through. A test suite that only fires payments together would
pass it. Planted-flaw test fixture, never deploy.

**Matched pairs** (`python3 -I tools/race/run.py`, 17 cells, 3 counted tries each, at most 5 tries).
"Must" is what the guard has to do. A try counts only if the judge gave the ordering the cell needs:
`overlap-proven` for a race, `sequential` for a sequential twin. "held" = 0 beyond policy and the
receiver got exactly 100; "broke" = exactly 100 beyond policy (receiver got 200).

| scenario | guard | must | counted tries were | counted | cell | blocks (last check → first callback, achieved offsets) | not counted |
|---|---|---|---|---|---|---|---|
| s1-same-block | guard-vulnerable | broke | broke | 3 of 3 | PASS | checks to callback 83→85 offs [0, 0]; checks to callback 85→87 offs [0, 0]; checks to callback 86→88 offs [0, 0] | - |
| s1-same-block | guard-fixed | held | held | 3 of 3 | PASS | checks to callback 83→85 offs [0, 0]; checks to callback 85→87 offs [0, 0]; checks to callback 84→86 offs [0, 0] | - |
| s1-same-block | M5 | broke | broke | 3 of 3 | PASS | checks to callback 112→114 offs [0, 0]; checks to callback 112→114 offs [0, 0]; checks to callback 115→117 offs [0, 0] | - |
| s1-same-block | vault-a | held | held | 3 of 3 | PASS | checks to callback 114→116 offs [0, 0]; checks to callback 112→114 offs [0, 0]; checks to callback 111→113 offs [0, 0] | - |
| s1-same-block | race-m1 | held | held | 3 of 3 | PASS | checks to callback 113→115 offs [0, 0]; checks to callback 111→113 offs [0, 0]; checks to callback 113→115 offs [0, 0] | - |
| s2-next-block | race-m1 | broke | broke | 3 of 3 | PASS | checks to callback 112→113 offs [0, 1]; checks to callback 113→114 offs [0, 1]; checks to callback 115→116 offs [0, 1] | - |
| s2-next-block | vault-a | held | held | 3 of 3 | PASS | checks to callback 114→115 offs [0, 1]; checks to callback 116→117 offs [0, 1]; checks to callback 114→115 offs [0, 1] | - |
| s2-next-block | guard-vulnerable | broke | broke | 3 of 3 | PASS | checks to callback 85→86 offs [0, 1]; checks to callback 86→87 offs [0, 1]; checks to callback 83→84 offs [0, 1] | - |
| s2-next-block | guard-fixed | held | held | 3 of 3 | PASS | checks to callback 85→86 offs [0, 1]; checks to callback 88→89 offs [0, 1]; checks to callback 84→85 offs [0, 1] | - |
| s2-next-block | M5 | broke | broke | 3 of 3 | PASS | checks to callback 114→115 offs [0, 1]; checks to callback 116→117 offs [0, 1]; checks to callback 115→116 offs [0, 1] | - |
| s1-twin-sequential | guard-vulnerable | held | held | 3 of 3 | PASS | checks to callback 86→83 offs [0, 5]; checks to callback 86→83 offs [0, 5]; checks to callback 86→83 offs [0, 5] | - |
| s1-twin-sequential | M5 | held | held | 3 of 3 | PASS | checks to callback 117→114 offs [0, 5]; checks to callback 118→115 offs [0, 5]; checks to callback 116→113 offs [0, 5] | - |
| s2-twin-sequential | race-m1 | held | held | 3 of 3 | PASS | checks to callback 118→115 offs [0, 5]; checks to callback 119→116 offs [0, 5]; checks to callback 115→112 offs [0, 5] | - |
| s2-twin-sequential | guard-vulnerable | held | held | 3 of 3 | PASS | checks to callback 87→84 offs [0, 5]; checks to callback 87→84 offs [0, 5]; checks to callback 87→84 offs [0, 5] | - |
| s2-twin-sequential | M5 | held | held | 3 of 3 | PASS | checks to callback 120→117 offs [0, 5]; checks to callback 117→114 offs [0, 5]; checks to callback 115→112 offs [0, 5] | - |
| s5-too-late | guard-vulnerable | held | held | 3 of 3 | PASS | checks to callback 88→85 offs [0, 5]; checks to callback 88→85 offs [0, 5]; checks to callback 84→81 offs [0, 5] | - |
| s5-too-late | guard-fixed | held | held | 3 of 3 | PASS | checks to callback 84→81 offs [0, 5]; checks to callback 86→83 offs [0, 5]; checks to callback 89→86 offs [0, 5] | - |

Raw: `race-ordering-2026-11-11/c2-matrix/` (one result JSON and log per try, `summary.json`,
`summary.md`). Every block number above is read from the result files, not from the harness's own
timing.

**What the numbers say.**

- **race-m1 is the case the old suite could not see:** it **held** on the same-block race (S1, 3 of 3)
  and **broke** by 100 when the second payment's check ran one block later (S2, 3 of 3), while vault-a
  (its fix) held on both. Sent one after the other (its sequential twin), race-m1 held 3 of 3. So the
  break comes from the ordering, not from a flaw a plain test would find.
- **The older pairs hold up one block later too:** guard-vulnerable and M5 broke on S2 as on S1;
  guard-fixed and vault-a held on both. This replaces the "inferred, not tested" line in
  `docs/guard-tests.md`.
- **The judge does not call a payment in a row a race:** every sequential twin and S5 (the second pay
  sent after the first has fully finished) was judged `sequential` (its check 3 blocks after the first
  callback), and every guard held.
- **No try was thrown away** in this run (not counted: 0). The rule that would discard one is tested
  in `tools/race/tests/test_ordering.py` (a mistimed S2, a tie, a fast-forward gap, a missing height).

**Pairs, in one line each** (matched = flawed broke, fixed held, sequential twin held on the flawed):

| pair | flawed guard | fixed guard | race | flawed | fixed | twin on flawed |
|---|---|---|---|---|---|---|
| P1 | guard-vulnerable | guard-fixed | S1 same block | broke 3/3 | held 3/3 | held 3/3 |
| P1 | guard-vulnerable | guard-fixed | S2 next block | broke 3/3 | held 3/3 | held 3/3 |
| P1b | M5 | vault-a | S1 | broke 3/3 | held 3/3 | held 3/3 |
| P1b | M5 | vault-a | S2 | broke 3/3 | held 3/3 | held 3/3 |
| P2 | race-m1 | vault-a | S2 | broke 3/3 | held 3/3 | held 3/3 (and held 3/3 on S1) |

## 1c. Checkpoint 3: a slow token, two more flawed guards, the daily-cap race

**The slow token** (`contracts/slow-token`, its own cargo workspace so the existing contract bytes do
not change; wasm sha256 `388d8510df1f578e...`). With holding off it is the test token. With holding
on, `ft_transfer` moves the money at once, then parks its answer using NEAR's yield/resume (a call
can pause until another transaction wakes it). The guard's callback cannot run until the harness
releases it. Only the token account can switch holding on or release; testers cannot (below).

**Spike result: yield/resume works on this sandbox, so no hop chain was built.** All three
conditions from the design held in the first run (`sequences-race/s3-held-answer.json` on
guard-vulnerable): (a) the guard's callback waited: checks in blocks 81 and 85, both callbacks in
block 90; (b) release (sent at head 86) made them land; (c) the trace shows it: token transfer in
82, the token's wake-up receipt (`on_release`) in 89, guard callback in 90. The wake-up is its own
receipt, run by the token account, so the judge (which looks for the guard's own later receipt)
reads the callback block correctly. Why yield/resume over a chain of hops: the hops would be paid
from the small gas budget the guard gives the token, and running out after the money moved would
make a good guard look broken; a parked answer costs a fixed 5 TGas for any delay.

**Two more one-flaw guards** (built by `tools/race/build_mutant.sh <id>`, diffs in `MUTATION.md`):

- `race-m2` (`853a2ec2e616c9ae...`): vault-a where an "in flight" mark older than 2 blocks is treated
  as abandoned, so the invoice can be paid again. **Synthetic**: none of the researched guards does
  this. Its job is to be the slow token's own positive control: it holds with the normal token
  (the first answer always comes back 2 blocks after the check) and breaks only when the answer is late.
- `race-m3` (`a16b7573df5cfc33...`): vault-a where the day's spend is added in the callback instead
  of reserved at the check, so payments whose checks all run before the first callback all fit
  under the 500 cap.

**Matched pairs, checkpoint 3 cells** (same runner and rules as 1b; `token` = which token the
sandbox used). The full matrix is 30 cells: the 17 checkpoint-2 cells plus the 13 below. It took
three runs to get a clean one; all are committed, with a fourth after the review follow-ups:

| run | what it ran | last line (from its `summary.md`) |
|---|---|---|
| `c3-matrix-run1/` | all 30 cells, S4-held still asking for offsets [0, 2, 4] | `race-c3: 30 cells, 28 passed; counted tries 84, not counted 10; wall 501 s` (the 2 failures are the two S4-held cells: all 10 tries thrown away, see below) |
| `c3-matrix-s4held/` | only the two S4-held cells, after the fix ([0, 4, 8]) | `race-c3: 2 cells, 2 passed; counted tries 6, not counted 1; wall 73 s` |
| `c3-matrix-fresh-7e9361f/` | all 30 cells, on a fresh `git archive` copy of `7e9361f` (section 1d) | `race-c3: 30 cells, 30 passed; counted tries 90, not counted 0; wall 498 s` |
| `c3-matrix-fresh-d2e2093/` | all 30 cells, fresh copy of `d2e2093` (judge with the refused-early rule) | `race-c3: 30 cells, 30 passed; counted tries 90, not counted 0; wall 463 s` |

Each line was re-derived from that folder's result files with the current judge (every try's
verdict and outcome recomputed): no disagreements. The table below is from the first two runs:

| scenario | guard | token | must | got | counted | cell |
|---|---|---|---|---|---|---|
| S3 held answer, offsets [0, 4] | race-m2 | slow | broke | broke | 3 of 3 | PASS |
| S3 | vault-a | slow | held | held | 3 of 3 | PASS |
| S3 | guard-vulnerable | slow | broke | broke | 3 of 3 | PASS |
| S3 | guard-fixed | slow | held | held | 3 of 3 | PASS |
| S3 sequential twin | race-m2 | slow (holding off) | held | held | 3 of 3 | PASS |
| S1 same block | race-m2 | test | held | held | 3 of 3 | PASS |
| S2 next block | race-m2 | test | held | held | 3 of 3 | PASS |
| S2 next block | race-m1 | slow (holding off) | broke | broke | 3 of 3 | PASS |
| S4 cap, timed, offsets [0, 0, 1] | race-m3 | test | 100 above cap | 100 above cap | 3 of 3 | PASS |
| S4 cap, timed | vault-a | test | 0 above cap, 500 paid | same | 3 of 3 | PASS |
| S4 cap, held, offsets [0, 4, 8] | race-m3 | slow | 100 above cap | 100 above cap | 3 of 3 | PASS |
| S4 cap, held | vault-a | slow | 0 above cap, 500 paid | same | 3 of 4 (1 thrown away: landed at [0, 3, 8]) | PASS |
| S4 sequential twin | race-m3 | test | 0 above cap | 0 above cap | 3 of 3 | PASS |

Raw: `race-ordering-2026-11-11/c3-matrix-run1/` (30 cells; every row above except the two S4-held
rows) and `c3-matrix-s4held/` (the two S4-held rows). In S3, the first callback lands 4 or 5 blocks
after the last check (for example checks 113 and 117, callbacks 122), so the ordering is proven with
room to spare, not by a tie.

**One thing went wrong, and the judge caught it.** S4-held first asked for offsets [0, 2, 4]. Held
mode sends a payment only after it has seen the previous one parked, which takes 4 blocks, so all 10
tries landed at [0, 4, 8]. The judge called every one `not-produced` and none was scored, even
though the balances happened to show what was expected (`c3-matrix-run1/summary.md`, the two FAIL
rows). Fix: held mode now refuses any gap under 4 blocks at load time, with that reason, and S4-held
asks for [0, 4, 8]. What this changes: spacings of 2 and 3 blocks are not tested by either mode
(timed mode stops at 1, held mode starts at 4).

**What each pair shows.**

- **race-m2 needs the slow token to be caught:** held on S1 and S2 with the normal token, broke by 100
  on S3 when the first answer was held 4+ blocks; vault-a held on S3; sent one after the other it held.
- **race-m3 is caught with or without the slow token:** 600 paid against a 500 cap (100 above) when
  all three checks ran before the first callback, both timed [0, 0, 1] and held [0, 4, 8]; vault-a paid
  exactly 500 (the third payment refused at its check); sent one after the other, race-m3 refused the
  third payment too.
- **The slow token with holding off changes nothing:** race-m1 still broke on S2 and the race-m2 twin
  still held under `--token slow`.

**Negative controls for the slow token.**

- **Nobody releases** (`sequences-race/s3-no-release.json`, `python3 -I tools/race/run.py timeout`):
  NEAR woke both parked answers by itself, the token logged `HOLD-TIMEOUT seq=1` and `seq=2`, and the
  judge said `not-produced`. The balances showed 100 beyond policy, and that was **not** counted as
  a break. About 40 s (200 blocks). Raw: `c3-timeout/`.
- **Testers cannot hold or release** (`sequences-race/s3-tester-cannot-hold.json`, run once with
  `--token slow` on vault-a): the outsider's `set_hold` and `release` both failed in the contract
  ("only the token account"); the agent's `set_hold` was refused by NEAR before any code ran (its key
  may only call the guard); `is_holding` stayed `false`. Raw: `c3-tester-cannot-hold/`.

## 1d. Fresh-copy regression at each checkpoint

Each checkpoint commit was exported with `git archive` into an empty folder, put under a new git
repository, and run in this order with no build folders: hunter tests (cold), `./verify.sh fast`,
`(cd harness && cargo test --release)`, check tests, hunter tests (warm), lookup tests, race judge
tests, `tools/race/testnet_rows.py`, the checkpoint's own race command, then `./arena check` on
vault-a, leaky-control-v2, intents-honest, intents-planted and native-fixed, then `git status
--porcelain`. One Mac, Apple silicon, shared with other builders' sandbox runs (hence the slow
`verify.sh fast`). Summaries: `race-ordering-2026-11-11/regression/`.

| checkpoint | commit | verify fast | Rust tests | check / hunter / lookup / judge | race command (fresh copy) | vault-a | leaky | intents-honest | intents-planted | native-fixed | git status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C1 | `53f45b3` | 5 passed (1,576 s) | 70 passed, 1 ignored | 105 / 79 cold, 79 warm / 37 / 20 | `tools/race/c1.sh`: 5 runs, both checks in one block 5, broke 3, held 2 (raw: `c1-fresh-53f45b3/`) | held 51/51 | broke 5 of 51, the same 5 | held 53/53 | broke 2 of 53, the same 2 | held 48/48 | empty |
| C2 | `c92513c` | 5 passed (2,203 s) | 75 passed, 1 ignored | 105 / 79, 79 / 37 / 20 | `run.py`: 17 cells, 17 passed; 51 counted, 0 not counted (raw: `c2-matrix-fresh-c92513c/`) | held 51/51 | broke 5 of 51, the same 5 | held 53/53 | broke 2 of 53, the same 2 | held 48/48 | empty |
| C3 | `7e9361f` | 5 passed (2,893 s) | 75 passed, 1 ignored | 105 / 79, 79 / 37 / 20 | `run.py`: 30 cells, 30 passed; 90 counted, 0 not counted (raw: `c3-matrix-fresh-7e9361f/`). `run.py timeout`: not-produced, 2 HOLD-TIMEOUT. Tester cannot hold: refused 3 of 3 | held 51/51 | broke 5 of 51, the same 5 | held 53/53 | broke 2 of 53, the same 2 | held 48/48 | empty |

The same 5 for leaky: ai-01, ai-02, c261110-1, p210408638-1, scripted-02 (as in
`check-fixes-2-2026-11-11/console-leaky-control-v2.txt`). The same 2 for intents-planted: ai-10 and
intents-01. The Rust test count rose from 70 to 75 because of the 5 new `race::tests`.

## 2. Doc changes made with this checkpoint

| Where | Before | After, and why |
|---|---|---|
| `README.md` Limits | "races were tested with both calls in the same block only. On testnet, 3 of 10 trials on Nov 10 had the two checks one block apart." | Same-block claim kept, now pointing at this file. Testnet half corrected: the 3 split trials were one block apart twice and **two** blocks apart once (row 3). |
| `README.md` "Why this is a NEAR problem" | "one block apart in the other 3" and "both checks ran before the first result was recorded in all 10 trials" | Row 3's checks were two blocks apart (277089182 and 277089184), and its later check ran in the **same** block as the first callback (277089184). Block numbers alone cannot show the order inside one block, so that trial is shown by its outcome (the guard paid 200), not by heights. |
| `evidence/testnet-2026-11-11.md` "One difference from Nov 9" | "in 3 (rows 3, 8, 9) they ran one block apart", "at or before" | **Not edited:** that file is pinned byte for byte (`tools/admission/evidence-baseline.sha256`), so its paragraph still says all three were one block apart. The correction is here instead: rows 8 and 9 ran one block apart, and the later check ran strictly before the first callback. Row 3 ran **two** blocks apart (A checked in 277089182, B in 277089184), and B's check ran in the same block as A's callback (277089184), so under the strict rule row 3 is a tie, shown only by its outcome (the broken guard paid 200). Its table, and the "at or before" column that counts row 3 as True, are unchanged. |
| `docs/bench-details.md`, `docs/guard-tests.md` (2 places), `site/index.html` | "tested with both calls/requests in the same block only" | Same claim, now with the source: block heights in this file. |
| Checkpoint 3: same places | "nothing later yet" | 4 and 8 blocks later are tested with the slow token; 2 and 3 are not. |
| Checkpoint 2: `README.md` Limits, `docs/bench-details.md`, `docs/guard-tests.md:173`, `site/index.html` + `site/build.mjs` | "same block only" / "N+1 inferred, not tested" | Same block **or one block later** is now tested (section 1b); nothing later yet. |

## 3. What this does not show

- **Spacings of 2 and 3 blocks.** Timed mode stops at 1 (the normal callback lands 2 blocks after the
  check); held mode starts at 4 (see 1c).
- **Guards that pay in native NEAR or into NEAR Intents** have no token to slow down; only timed mode
  applies to them, and these runs did not include them.
- **No unit tests of the slow token itself** outside the sandbox. Its behaviour is shown by the runs
  above (holding off = same results as the test token in the two control cells; holding on; release;
  timeout; tester refused). Release order (oldest first) is in the code, not separately tested.
- **Only `inv-pay` for double payment and three invoices for the cap.** Other invoices and more legs
  are not tried.
- **40 runs, one sequence, two legs, very likely all on one Mac** (the reviewer's run is not saved, so
  where it ran is not recorded). 1 of 40 already split by a block (1 above). Three
  or more legs, or a busier machine, may split more often; `tools/race/c1.sh` now lists such a run and
  exits non-zero if the judge does not count it.
- **The guard-test run in `docs/guard-tests.md` (`./run.sh t1`) records no heights.** It deploys the
  same guard bytes (`0382023b...`) as guard-vulnerable/guard-fixed here, but its own run is not traced.
- **Order inside one block is not recorded** by the trace. The judge therefore never counts a tie.
