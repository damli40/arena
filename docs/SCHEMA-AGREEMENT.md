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

It writes 3,160 attack files and gives each one to both sides, with no sandbox:

- 160 hand-picked cases: valid files at every limit (12 steps, races of 2 and 4, waits of 1
  and 200 blocks, 60 seconds of waiting in total, gas 1 and 300, deposit 0 and 10^18, an
  argument string of 128 characters, exactly 1,024 bytes of arguments), and files just past each
  limit or broken on purpose (unknown step kinds, a step with two keys, a race holding a view,
  a race inside a race, an empty race, waits written as text, decimals or negatives, numbers too
  big for 64 bits, the owner as actor, unknown targets, extra keys, duplicate keys, `NaN`, `-0`,
  lone surrogate escapes, bad UTF-8, a 5,000-digit number, nesting 2,000 deep);
- 3,000 random files from a fixed seed (`--seed 20261112`): valid files, and valid files
  changed one to three times at random (a value swapped for another type, a key dropped or
  added, a step doubled or wrapped in a race).

The gatekeeper side calls `validate_path`, the same function the hunter and `tools/check` use.
The engine side calls a new check-only command, `arena-harness check-seq`
(`harness/src/seqcheck.rs`). It runs the real `seq::load_sequence`, then walks the steps the way
`seq::execute` does and stops wherever a run would stop before sending anything (unknown step,
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
agreement: 3160 files (seed 20261112), 0 disagreements; both accept 1355 and read them the same, both refuse 1457, engine-only accepts 348 (the gatekeeper is meant to be stricter)
```

Exit code 0, about 10 seconds once the harness is built (`--harness <path>` skips the cargo
step).

Three Rust unit tests in `seqcheck.rs` also run with `cargo test`. They check that the
schema's step kinds equal the engine's six, that `load_sequence` knows the same six, and that
`execute` still tests the step keys in the order `seqcheck` copies. If someone changes
`execute`, the third test fails until `seqcheck.rs` is updated to match.

### What it does not cover

- It is testing, not proof. It covers the cases it generates; another file could still disagree.
- It stops where the engine starts sending. What the six actions do on chain (a contract
  panic, a protocol refusal, how the adapter rewrites a call for a `--guard-config` guard) is
  not tested here; the sandbox runs cover that.
- `seqcheck.rs` copies `execute`'s order of checks instead of sharing the code. The unit test
  catches a change in which keys `execute` tests and in what order, but not every change
  inside a branch. "Next step" below removes the copy.
- The `intents` target is tested both ways: refused in the main library, accepted in the
  intents suite with `check-seq --intents`. Which guards actually deploy Intents is a run-time
  fact and is not modelled.

## What we found (Nov 12)

Before the fixes, the same command printed 10 disagreements and exit code 1. Every one was the
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

The three fixes in `validate.py` change no verdict on the 48 library files, the 2 intents
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
