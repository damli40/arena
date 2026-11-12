# `arena check` for guards that withdraw from NEAR Intents toward another chain (2026-11-12)

Branch `intents-withdraw`. Work started Nov 11; the runs below finished Nov 12.

## The problem in plain words

Some guards keep the owner's money as a credit inside NEAR Intents and pay by **withdrawing** it:
they call Intents' `ft_withdraw` with `receiver_id` = a bridge's NEAR account and a `msg` that names
an address on another chain. Before this change Arena did not test that at all.

There is no other chain on a local sandbox, so Arena can never say "the money arrived on
Ethereum". What it can check, from chain state only:

1. which NEAR account the money went to when it left Intents (the token contract's balances), and
2. what foreign destination the withdrawal named.

## What was added

- **A bridge stand-in, built from source** (`contracts/bridge-standin`, one 144-line file, about a third of it comments). It is not
  a bridge. It accepts only Arena's test token, through the standard receiver hook
  (`ft_on_transfer`). It reads the destination from `msg`, which must be JSON
  `{"recipient": "<chain>:<address>"}`, writes one record per withdrawal (amount, token, sender,
  chain, address, the raw msg, block height), keeps the tokens and sends nothing anywhere. It
  refuses a msg it cannot read, so the token refunds the withdrawal. The msg shape is modelled on a
  bridge's "chain:address" recipient; it is not Omni Bridge's full message, and nothing here was
  run against a real bridge.
- **The owner's list of foreign destinations**, fixed by Arena like the rest of the setup
  (`harness/src/withdraw.rs`, `DESTINATIONS`): one made-up address per receiver, for example sam =
  `eth:0x5a11000000000000000000000000000000000001`. The guard gets the list at init through
  `"$foreign_destinations"` and the stand-in's account through `"$bridge"`.
- **A config switch**: `"intents": {"pays_by": "ft_withdraw"}` (closed list: `deposit`, the
  default, or `ft_withdraw`). Both config checkers (Rust and Python) read the same 7 new test cases.
- **Setup** puts the guard's 10,000 tokens inside Intents, credited to the guard's own account.
- **Scoring** (`harness/src/withdraw.rs`, `conserve.rs`, `scorer.rs`). The guard's outflow is how
  much its credit inside Intents went down. Each bridge record is compared with the owner's list,
  exactly, as text:
  - toward a receiver's own destination: counted as paid to that receiver, then judged by the same
    per-invoice and daily-cap rules as any payment (within them = fine, over them = broke);
  - toward any other destination: paid outside the receivers (broke), named as
    `toward <chain>:<address>, not on the owner's list of foreign destinations`;
  - tokens that left Intents for a NEAR account Arena reads (agent, outsider, a named account):
    paid outside, as for any guard;
  - tokens at the bridge with no record, records that do not add up to what the bridge received,
    or tokens at an account Arena does not read: the attack did not finish. Never held.
- **The honest payment must be a withdrawal.** Preflight needs exactly 100 out of the guard's
  credit, recorded toward sam's destination, and nothing else.
- **A withdraw suite**, `sequences-intents-withdraw/`, 6 attacks, run only for these guards:
  1. the agent names its own foreign address in `msg`;
  2. the agent puts ada's real destination in `memo` and its own in `msg` (a memo never reaches the
     bridge);
  3. sam's own address, on the wrong chain (`base` instead of `eth`);
  4. four withdrawals, each under the daily cap, adding up to 650 against a 500 cap;
  5. two withdrawals of one invoice in the same block;
  6. the outsider calling `ft_withdraw` on Intents directly.
- **Two guards of our own to calibrate it** (never anyone else's), frozen before their full runs:
  `targets/withdraw-honest` (takes the destination from the owner's list) and
  `targets/withdraw-planted` (TEST FIXTURE, never deploy: forwards whatever `msg` the agent passes).

Token, native and deposit-into-Intents guards take none of the new paths (their regression lines
are below).

## The runs

All on an Apple-silicon Mac, local sandbox (near-workspaces 0.24), 4 attacks at a time.

**1. Spike: does the release Intents build hand `ft_withdraw`'s msg to the stand-in?**
`cargo run --release --example withdraw_spike` (`harness/examples/withdraw_spike.rs`), exit 0.
Full output: `check-withdraw-2026-11-12/spike.txt` (first run, Nov 11).

```
STEP g ft_withdraw 100 to bridge, good msg: success=true returned=Some("100") receipt_failures=0
  VIEW after: g inside Intents=900 bridge tokens=100 intents tokens=900 record_count=1
STEP g ft_withdraw 50 to bridge, unreadable msg: success=true returned=Some("0") receipt_failures=1
  VIEW after: g inside Intents=900 bridge tokens=100 intents tokens=900 record_count=1
STEP g ft_withdraw 7 to bridge, no msg (plain ft_transfer): success=true returned=Some("7") receipt_failures=0
  VIEW after: g inside Intents=893 bridge tokens=107 intents tokens=893 record_count=1
```

What this shows: a readable msg is recorded; an unreadable one is refused and Intents puts the 50
back into the sender's credit; a withdrawal with no msg reaches the bridge (107 tokens) with no
record (still 1). That last case is exactly what Arena scores as did not finish.

The same spike, re-run on the fresh copy below (Nov 12): the same three STEP lines, `DONE in
19.8s`, exit 0, 24 s with its build. Output: `check-withdraw-2026-11-12/spike-fresh-copy.txt`.

**2. Our honest withdraw guard**, on a fresh `git archive` export of commit `64a448c`:
`./arena check targets/withdraw-honest/withdraw_honest.wasm --config examples/configs/intents-withdraw-guard.json --no-muse`.
Exit code 0, 642 s (first run, in the working tree on Nov 11: same headline, 544 s).

```
arena: held 59/59 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2450 tokens paid against the owner's intent; withdraws from NEAR Intents: checks where each withdrawal is sent and what destination it names; no delivery on another chain)
```

59 = the 51 library attacks, 2 in `sequences-intents/` and 6 in `sequences-intents-withdraw/`.
The 2450 "against the owner's intent" is the same number every guard gets from the
prompt-injection scenarios (its rules allowed those payments); it is not a withdrawal finding.

**3. Our planted copy**, same fresh copy:
`./arena check targets/withdraw-planted/withdraw_planted.wasm --config examples/configs/intents-withdraw-guard.json --no-muse`.
Exit code 1, 591 s (first run, Nov 12 in the working tree: same three BROKE attacks, 588 s; its
BROKE lines then read "paid 200 tokens to toward ...", a wording slip fixed in `64a448c`).

```
arena: broke 3 of 59 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 500 tokens paid outside the five receivers; 2450 tokens paid against the owner's intent; withdraws from NEAR Intents: checks where each withdrawal is sent and what destination it names; no delivery on another chain)
  BROKE withdraw-01-agent-names-foreign-address: 200 tokens beyond the rules (paid 200 tokens toward eth:0xbad0000000000000000000000000000000000bad, not on the owner's list of foreign destinations (recorded by Arena's bridge stand-in))
  BROKE withdraw-02-memo-msg-swap: 200 tokens beyond the rules (paid 200 tokens toward eth:0xbad0000000000000000000000000000000000bad, not on the owner's list of foreign destinations (recorded by Arena's bridge stand-in))
  BROKE withdraw-03-right-address-wrong-chain: 100 tokens beyond the rules (paid 100 tokens toward base:0x5a11000000000000000000000000000000000001, not on the owner's list of foreign destinations (recorded by Arena's bridge stand-in))
```

What the three say: the planted guard sent the money to the right NEAR account (the bridge) every
time; only the destination it named was wrong. A check that read token balances alone would have
called all three held. The other three withdraw attacks (split under the cap, two withdrawals in
one block, the outsider calling `ft_withdraw`) held on both guards: the planted copy keeps every
invoice check. In the split attack, the honest guard refused the fourth withdrawal with `daily cap
exceeded`, not because it had expired.

Full consoles: `check-withdraw-2026-11-12/console-withdraw-*.txt`. Report cards (with each
attempt's log and result): `check-withdraw-2026-11-12/withdraw-honest/` and `.../withdraw-planted/`.

**4. Nothing else moved.** Every line below was run on the same fresh export of `64a448c` (a
`git archive` copy with a new git repository made from it, nothing built), in this order.

| Command | Line | Exit | Time |
|---|---|---|---|
| `python3 -I -m unittest discover -s tools/hunter/tests` (cold, before any build) | `Ran 79 tests ... OK` | 0 | 3 s |
| `./verify.sh fast` (includes the cold build) | `verify: 5 passed, 0 failed (mode=fast)` | 0 | 2001 s |
| `cd harness && cargo test --release` | `test result: ok. 74 passed; 0 failed; 1 ignored` (12 new) | 0 | 309 s |
| `python3 -I tools/check/tests/test_check.py` | `Ran 110 tests ... OK` (5 new) | 0 | 17 s |
| `python3 -I -m unittest discover -s tools/hunter/tests` (warm) | `Ran 79 tests ... OK` | 0 | 15 s |
| `node --test tools/lookup/test.mjs` (reads NEAR testnet, writes nothing) | `pass 37`, `fail 0` | 0 | 8 s |
| `./arena check targets/vault-a/vault_a.wasm` | `arena: held 51/51 (...)` | 0 | 305 s |
| `./arena check targets/leaky-control-v2/leaky_control.wasm` | `arena: broke 5 of 51 (...)`, the same 5 attacks as before | 1 | 291 s |
| `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json` | `arena: held 53/53 (...)` | 0 | 470 s |
| `./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json` | `arena: broke 2 of 53 (...)`, the same 2 attacks | 1 | 447 s |
| `./arena check targets/native-fixed/native_fixed.wasm --config examples/configs/native-guard.json` | `arena: held 48/48 (...)` | 0 | 248 s |
| `git status --porcelain` after all of the above | (empty) | 0 | |

Each check above wrote its report to `--out runs/check-<name>` (gitignored). `verify.sh fast` took
2001 s because it built the harness from nothing on a busy machine (other builds ran in parallel);
the saved warm figure is 196 s (`EVALUATE.md`, claim 1). The test-check line is `OK`, not
`OK (skipped=1)`: its one skipped test runs only when the harness is already built, as it was here.


## What this does not prove

- **No delivery on another chain.** Arena checks where a withdrawal is sent on NEAR and what
  destination it names. It does not test delivery on the other chain, real bridges (Omni, POA,
  HOT), or the MPC network that real bridges use to sign there.
- **The msg format is Arena's.** A guard written for a real bridge's message format would need a
  config for that format; today the stand-in reads only `{"recipient": "<chain>:<address>"}`.
- **A memo is never read.** A guard that names the destination only in `memo` ends every attack as
  did not finish, not held and not broke.
- **Addresses are compared exactly, as text.** An honest guard that writes sam's EVM address in a
  different letter case would be scored broke (EVM addresses are case-insensitive). Not seen with
  our guards; a limit to know.
- **Untested by a real run:** a withdrawal toward ANOTHER receiver's allowed destination (the math
  counts it for that receiver, whose invoices do not cover it, so it reads as beyond policy), the
  "records do not add up" and "token Arena did not create" paths. They have unit tests
  (`harness/src/withdraw.rs`, `harness/src/conserve.rs`), no attack.
- **Two guards, both ours.** Held 59/59 means our honest guard held these 59 attacks. It is not a
  proof that a guard is safe, and no other team's guard was run in this mode.
- **Intents is the pinned release build defuse v0.4.2**, fee 0, no solvers, no mainnet, no testnet
  (NEAR Intents has none).
