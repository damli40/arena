# Do the gatekeeper and the engine agree?

Arena keeps the rules for an attack file in three places:

| Copy | File | Its job |
|---|---|---|
| The written schema | `schema/attack.schema.json` | tells people what a file may contain |
| The gatekeeper | `tools/hunter/validate.py` | decides which files get in |
| The engine | `harness/src/seq.rs` | runs the steps in a file |

`python3 -I tools/hunter/validate.py --self-test` already checks that the gatekeeper and the
schema list the same values and limits. Until Nov 12 nothing checked the engine. The risk is a
file the gatekeeper lets in that the engine then refuses, or runs as something else. A refused
file does more harm than it looks: `run_files` in `harness/src/main.rs` loads each file with `?`,
so one unreadable file stops the whole run, not only that attack.

## The comparison test

```
python3 -I tools/agreement/compare.py
```

It writes 3,478 attack files and gives each one to both sides, with no sandbox:

- 178 hand-picked cases: valid files at every limit (12 steps, races of 2 and 4, waits of 1
  and 200 blocks, 60 seconds of waiting in total, gas 1 and 300, deposit 0 and 10^18, an
  argument string of 128 characters, exactly 1,024 bytes of arguments), and files just past each
  limit or broken on purpose (unknown step kinds, a step with two keys, a race holding a view,
  a race inside a race, an empty race, waits written as text, decimals or negatives, numbers too
  big for 64 bits, the owner as actor, unknown targets, extra keys, duplicate keys, `NaN`, `-0`,
  lone surrogate escapes, bad UTF-8, a 5,000-digit number, nesting 2,000 deep, U+2028 and
  U+0085 inside an argument, `parents` holding objects or lists, a date in Arabic-Indic digits,
  the `signer` target in and out of the Chain Signatures suite, and a race step with the
  stagger keys `offsets` and `hold`);
- 3,000 random files from a fixed seed (`--seed 20261112`): valid files, and valid files
  changed one to three times at random (a value swapped for another type, a key dropped or
  added, a step doubled or wrapped in a race).

The gatekeeper side calls `validate_path`, the same function the hunter and `tools/check` use.
The engine side calls a new check-only command, `arena-harness check-seq`
(`harness/src/seqcheck.rs`). It runs the real `seq::load_sequence`. Then it walks the steps
with its own COPY of `seq::execute`'s decisions (not the same code: `execute` needs a running
sandbox, so `check-seq` repeats its checks). It stops wherever a run would stop before sending anything (unknown step,
empty race, an actor other than agent or outsider, an unknown target, no method, a bad add_key
permission). For each step it prints what it would send: kind, actor, target, method, args,
gas, deposit, wait.

The test fails if:

- the gatekeeper accepts a file the engine refuses;
- the gatekeeper accepts a file the engine would run differently. The comparison checks the
  JSON type as well, so `0` and `-0.0` differ, and so do `5` and `5.0`;
- the gatekeeper crashes instead of giving a reason.

Files the engine accepts and the gatekeeper refuses are counted, not failed. The gatekeeper is
meant to be the stricter one (for example, the engine has no 12-step limit and no 60-second
total).

Our run on Nov 12, after the fixes below:

```
agreement: 3478 files (seed 20261112), 0 disagreements; both accept 1492 and read them the same, both refuse 1600, engine-only accepts 386 (the gatekeeper is meant to be stricter)
```

Exit code 0, about 10 seconds once the harness is built (`--harness <path>` skips the cargo
step).

### The copy can drift, and what holds it

Because `check-seq` copies the engine's logic instead of calling it, someone can change the
engine and leave the copy behind. Then this test compares the gatekeeper with an old picture of
the engine and still passes. A reviewer showed this on Nov 12 with two one-line edits to
`seq.rs`: (A) a missing `target` means `token` instead of `vault`; (B) `execute` ignores
`wait_blocks` above 100, so a 150-block file passes the gatekeeper and stops the whole run.
Every test, and this comparison, still passed. A second review found four more that passed
the first version of test 6 below: (C) `do_race` refuses a race element not wrapped in
`{"call": ...}`; (D) `execute` skips `wait_blocks` above 100 with `continue`; (E) `do_view`
uses `get_config` when the method is missing; (F) `do_race` returns early for more than 4
calls.

Six Rust unit tests in `seqcheck.rs` now run with `cargo test` to narrow that gap:

1. the schema's step kinds equal the engine's six;
2. `load_sequence` knows the same six;
3. `execute` tests the step keys in the order the copy uses, and reads only `offsets` and `hold` on top of them (the staggered race);
4. the copy reads the six kinds and refuses an empty race, the owner, and `intents` without
   an Intents guard;
5. a regression test of the copy: a table of what the copy decides at the boundaries (missing, non-string and unknown
   targets; `wait_blocks` and `wait_seconds` at 0, 1, 200, 201 and the 64-bit maximum, and as
   -1, 5.0 or "5"; races of 1 to 6 calls). It tests the copy against itself, so it guards
   against breaking the copy, not against the engine drifting away from it;
6. a stopgap snapshot, the only drift protection: the full text of every engine function the
   copy mirrors (`target_id`, `method_of`, `build_tx`, `do_call`, `do_add_key`, `do_view`,
   `do_race`, `execute`, `Arena::actor`, and `race::run` for a staggered race), with blank and comment-only lines dropped, must
   equal `harness/src/seqcheck.snapshot`. Any edit to a code line of those functions fails
   it and prints the line that changed.

Edits A to F each make test 6 fail (we applied each alone, ran `cargo test`, then reverted
`seq.rs`). Tests reduce the risk of drift; they cannot remove it. The snapshot only sees those
ten functions: a change inside a helper they call (`args_of`, `adapt`, `translate_args`) or a new
engine path can still slip past. (`load_sequence` is not copied: `check-seq` calls the real
one.) It also fails on harmless edits to those functions, by design. The real fix is
"Next step" below: one shared function that both `execute` and `check-seq` call.

### What it does not cover

- It is testing, not proof. It covers the cases it generates; another file could still disagree.
- It stops where the engine starts sending. What the six actions do on chain (a contract
  panic, a protocol refusal, how the adapter rewrites a call for a `--guard-config` guard) is
  not tested here; the sandbox runs cover that.
- `check-seq` is a copy of the engine's decisions, not the engine. See "The copy can drift"
  above.
- Three suites are modelled: the main library, the intents suite (`check-seq --intents`) and,
  since the rebase onto main on Nov 12, the Chain Signatures suite (`check-seq --chainsig`,
  where the `signer` target exists; 309 of the 3,478 files: 300 random from seed + 1, so the
  main and intents files are the same as before, and 9 hand cases). A guard that both pays
  into Intents and signs via Chain Signatures is not modelled (no suite allows both targets).
  Any new call field that only `build_tx` reads would still pass silently; test 6 fails when
  `build_tx` or `target_id` change, which is the reminder.
- A race step with `offsets` or `hold` (the staggered race, `harness/src/race.rs`) is refused
  by the gatekeeper (a step has exactly one key) and run by the engine, so it is counted as
  engine-only, never failed. `check-seq` refuses `hold` unless given `--token slow`, as the
  run does. The files in `sequences-race/` are not gatekeeper-valid for that reason; they are
  run by `tools/race/run.py`, never through the hunter or the admission gate.
- `ARXIV_RE` in `validate.py` (and the schema's matching pattern) still uses `\d`, which
  accepts digits from other scripts. It only checks a recorded paper id, not a step; left for
  review because changing it means changing the schema too.
- The `intents` target is tested both ways: refused in the main library, accepted in the
  intents suite with `check-seq --intents`. Which guards actually deploy Intents is a run-time
  fact and is not modelled.

## What we found (Nov 12)

Before the first fixes, the same command printed 10 disagreements and exit code 1. Every one was the
gatekeeper letting through something the engine reads differently or not at all. We found no
case of the engine running a step as a different kind: duplicate keys (`{"call": A, "call":
B}`) are read the same by both (the last one wins), and a step with two keys, a view inside a
race, or a wait written as text are refused by the gatekeeper.

| # | What broke | Smallest example | Status |
|---|---|---|---|
| D1 | `meta.injection.scenario_id` had no type check. The schema says string; the gatekeeper accepted anything, including `NaN`, `Infinity` and arrays nested 200 deep, which the engine cannot parse. One such file stops a whole run. | `"scenario_id": NaN` | Fixed: one line in `check_meta` requires a string |
| D2 | A lone surrogate escape in any string (an arg, a title, the email) passed the gatekeeper. Python reads it; the engine's JSON reader refuses the file. | `"args": {"id": "inv-1\ud800"}` | Fixed: two lines in `check_attack` refuse it with a reason |
| D3 | `-0` is the integer 0 to Python but the decimal -0.0 to the engine. The gatekeeper checked `amount: 0`; the engine would send `-0.0` to the contract. In `deposit_yocto` the engine attaches no deposit, which happens to match 0. | `"args": {"amount": -0}` | Fixed: `validate_path` refuses the number `-0` |
| D4 | A file with bad UTF-8 crashed the gatekeeper (`UnicodeDecodeError`) instead of giving a reason. In `tools/check` or a catalog run, a crash stops the run. | a title holding the bytes `ED B3 BF` | Fixed: `validate_path` catches it and reports "not readable JSON" |
| D5 | A number over 4,300 digits crashed the gatekeeper (`ValueError` from Python's limit on big integers). | `"amount": 111...1` (5,000 digits) | Fixed: same line as D4 |
| D6 | Found in review. `source: "combined"` with `parents` holding objects or lists crashed the gatekeeper (`TypeError`: it built a set before checking the types). | `"parents": [{}, {}]` | Fixed: types are checked before the set |
| D7 | Found in review. `DATE_RE` used `\d`, so a date in Arabic-Indic digits passed. | `"added": "٢٠٢٦-11-12"` | Fixed: `[0-9]` |
| D8 | Found in review, in this test, not the gatekeeper. `compare.py` split the engine's output with `splitlines()`, which also breaks on U+2028 and U+0085. A valid argument holding one would have been misread. | `"args": {"memo": "a\u2028b"}` | Fixed: split on `\n` only |

The fixes in `validate.py` change no verdict on the 48 library files, the 2 intents
files or the 62 saved hunt attacks (we compared the output before and after).

Not a disagreement, but worth knowing:

- The engine is looser than the gatekeeper in ways that are fine today because the gatekeeper
  runs before the engine: a `target` that is not a string means `vault`, a `gas_tgas` that is not a whole
  number means maximum gas, a `deposit_yocto` that is not a whole number means no deposit,
  `load_sequence` does not check the actor of a call inside a race (the run checks it later).
  Any file that reaches the engine without passing the gatekeeper gets these silent readings.
- One refused file stops a whole `run` (the `?` on `load_sequence` in `run_files`). That is the
  engine's choice, not a disagreement, but it raises the cost of every gap above.

## Next step (after the open branches merge)

Not done yet. To apply once the branches that change `validate.py`, the schema and `seq.rs`
have merged, so it is written against the final rules.

1. **The schema holds every number and list.** Limits the JSON schema language cannot say
   (60 seconds of waiting in total, 1,024 bytes of arguments, depth 2, at least one
   state-changing step) go in one `x-arena-limits` object in `attack.schema.json`.
2. **The gatekeeper reads them instead of copying them.** `validate.py` loads the schema at
   start-up (standard library `json`) and sets `MAX_STEPS`, `TARGETS`, `RACE_MAX` and the rest
   from it. The hand-written checks and their readable reasons stay; only the numbers and lists
   move. `--self-test` then checks the schema is complete rather than that two copies match.
3. **The engine reads them too, and dispatches in one place.** `seq.rs` embeds the same schema
   with `include_str!` and takes its step kinds and targets from it. `execute` calls one
   function to decide each step's kind, the same function `check-seq` uses, so the check-only
   path cannot drift from the real one. `load_sequence` runs that plan, so a bad file is
   refused when it is loaded, and `run_files` records a refused file and moves on instead of
   stopping the run.
4. **Keep the comparison test.** It checks behaviour (what each side does with a file), which
   shared numbers alone cannot. Run it in CI next to `--self-test`.

The cost: step 3 edits `execute`, the busiest function in `seq.rs`, which is why it waits for
the merges.
