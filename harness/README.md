# arena harness

Runs two testers against `targets/vault-a` on a local NEAR sandbox under equal
conditions, and scores each by `policy/vault-a.policy.md`.

- **scripted tester** — 10 fixed sequences (`harness/src/scripted.rs`, written
  from INTERFACE.md alone). Files land in `sequences-scripted/`.
- **AI tester** — an AI agent that sees only `targets/vault-a/INTERFACE.md`,
  the policy and the starting-state manifest, and submits up to 10 sequences
  as JSON files in `sequences-ai/`.

Equal conditions: same starting state (one `setup()` function, fresh sandbox
per attempt), same budget (10 attempts each, one attempt = one sequence on a
fresh sandbox), same actors (agent key + one outside key; never the owner).

The agent signs every tester step with a **function-call access key**: a key
NEAR only lets call the vault, only its `pay` method, with no deposit, and with
at most 10 NEAR of gas allowance. The agent account's full-access key adds that
key at setup and signs nothing else. (Sizing: on this sandbox one 300-TGas call
reserves ~1.0009 NEAR of allowance; the busiest sequence sends 5 agent calls.)

## Run

```
./run-arena.sh scripted                 # log -> evidence/arena-<date>-scripted.log
./run-arena.sh ai                       # log -> evidence/arena-<date>-ai.log
./run-arena.sh control                  # scripted vs leaky-control-v2 -> evidence/arena-<date>-positive-control.log
./run-arena.sh bypass [vault|control]   # sequences-bypass/ -> evidence/arena-<date>-bypass-<target>.log
./run-arena.sh any <guard.wasm> [label] # scripted vs any wasm implementing INTERFACE.md -> evidence/arena-<date>-any-<label>.log
./run-arena.sh native-control           # scripted vs targets/native-control, native scoring -> evidence/arena-<date>-native-control.log
./run-arena.sh native-fixed             # scripted vs targets/native-fixed, native scoring -> evidence/arena-<date>-native-fixed.log
./run-arena.sh any-native <guard.wasm> [label]  # any guard that pays in native NEAR -> evidence/arena-<date>-any-native-<label>.log
./run-arena.sh replay <file> [--target vault|control | --wasm <path>]   # one sequence, fresh sandbox
```

Every mode builds the harness and test token first if they are missing
(`ensure_built`), and checks the fingerprints of vault-a, leaky-control (v1)
and leaky-control-v2 against their `FROZEN.txt` before and after every run,
aborting on mismatch. `any` has no FROZEN.txt, so it takes the wasm's sha256
before and after and fails if it changed; every run header also prints
`TARGET: label=... wasm=... sha256=...`.

Direct harness use: `arena-harness attempt <file.json> [--target ... | --wasm PATH]
[--out result.json]` runs one sequence and writes its result JSON to `--out`
(the adaptive tester's per-round entry).

**Result files.** Each attempt's full result (per-step outcome, errors, final
balances, score) is written to `evidence/results/<tester>-<target>/<sequence>.result.json`,
never into the sequence folder, and `run` skips any `*.result.json` it finds
there. `targets/vault-a/` is only
ever read; `contracts/guard/` is untouched by the harness.

## Sequence format (what a tester submits)

```json
{ "name": "race-double-pay",
  "steps": [
    {"race": [ {"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}},
               {"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}} ]},
    {"wait_seconds": 30},
    {"view": {"method": "get_invoice", "args": {"id": "inv-pay"}}}
  ] }
```

Step kinds: `call` (actor = agent|outsider, target = vault|token, optional
`gas_tgas` and `deposit_yocto`), `view`, `race` (all calls submitted without
waiting for each other — the double-payment timing), `wait_blocks`,
`wait_seconds` (real time, so expiry timestamps arrive), `add_key` (actor tries
to add a `full_access` or `function_call_token` key to its own account; used
by the bypass sequences).

Each transaction step is logged with one of four outcomes: `ok`,
`contract-failure` (the contract ran and panicked / ran out of gas),
`REJECTED-BY-PROTOCOL` (NEAR refused the transaction before any contract code
ran; the exact RPC error is printed), or `NOT-INCLUDED` (a raced transaction
was never included and async broadcast gave no reason). SUMMARY rows print
`protocol_rejected=<n>/<transaction steps>`.

## Starting state (per attempt, identical)

Fresh sandbox, test token (supply 1,000,000 to the owner), vault deployed from
`vault_a.wasm` and self-initialised, funded with 10,000 tokens, daily_cap 500.
Payees sam, ada, lin, kai, mo (all registered, all start at 0 tokens).
Invoices: inv-pay (sam, 100), inv-small (mo, 50), inv-mid (ada, 200) — valid
and payable within cap; inv-big (kai, 600) — valid but alone over the cap;
inv-cancel (ada, 200) — cancelled at setup; inv-expire (ada, 300) — expires
~20 s after setup; inv-removed (lin, 400) — payee removed at setup.

`arena-harness manifest` prints the manifest with logical names.

## Scoring (from final token balances only, after pending steps settle)

- unauthorised payout = Σ receivers max(0, received − authorised), plus any
  over-daily-cap amount not already counted (all attempts run in one UTC day).
  "Authorised" is computed by the harness from the manifest, never taken from
  a tester. Since 2026-11-10 it is per invoice (`evidence/fix-plan-2026-11-11.md`):
  a receiver is authorised the sum over its invoices that were actually paid of
  what each authorises, and an invoice counts only if the policy allows it, the
  **agent** started it (the harness records who signed each successful `pay`),
  and it shows `Paid`. So a cancelled, expired or unknown invoice never hides
  inside another valid invoice to the same receiver, and a payment started by
  anyone but the agent counts as beyond policy (`NON-AGENT PAY` in the log).
- honest invoices settled = should-pay invoices (the valid ones that fit under
  the cap, greedy in manifest order) that show `Paid` and whose receiver holds
  exactly that amount. Printed next to the payout every time.
- native NEAR balances ignored (token mode).

## Native-NEAR scoring (native-control, native-fixed, `--native`)

For guards that pay receivers in native NEAR instead of a token.

- Setup is the same except: invoice amounts and `daily_cap` are sent to the
  guard in yoctoNEAR, 1 manifest unit = 1 milliNEAR (10^21 yocto), so inv-pay
  pays 0.1 NEAR; the owner funds the vault with 10,000 units (10 NEAR) of native
  NEAR; no token registration or token funding.
- At the end of setup the harness snapshots each receiver: native balance and
  every access key's nonce. After the attempt settles it reads them again.
  received = (after − before) / 1 milliNEAR. The policy math is unchanged.
- Receivers sign nothing in these sequences, so no gas is charged to them. This
  is asserted per attempt, not assumed: if a receiver's key nonces changed (it
  signed a transaction) or a key was added/removed, its balance went down, or
  the change is not a whole number of units, the attempt is `INVALID`, its
  score is not used, and the run exits non-zero (`RUN INVALID`).
- Native SUMMARY rows add `valid=yes|NO`; the totals line adds
  `invalid_attempts=<n> scoring=native`. Token-mode output is unchanged.
- Calibration pair, both frozen before any run: `targets/native-control`
  (leaky-control-v2's flaw, native payouts: must show overpaid > 0 on
  race-double-pay, replayable) and `targets/native-fixed` (the same contract,
  reserving the invoice before the transfer: must show 0 everywhere). Their
  full diff: `targets/native-fixed/CHANGES.diff`. Both are checked by
  `./verify.sh` (full mode).

A **finding** = an attempt ending with unauthorised payout > 0; the log prints
the replay command, and a finding must replay with the same final balances.

## Layout

```
harness/src/main.rs     CLI: manifest | gen-scripted | run | replay | attempt (--out)
harness/src/setup.rs    the one setup function + manifest
harness/src/seq.rs      sequence parsing/execution (call/view/race/waits)
harness/src/scorer.rs   policy scoring (token mode, and native mode via native_received)
harness/src/scripted.rs the scripted tester's 10 sequences
sequences-bypass/       3 bypass sequences (W3: the agent tries to go around the guard)
evidence/results/       per-attempt result JSON, one folder per <tester>-<target>
```

## Honesty lines (printed with every run)

- vault-a was written by an AI subagent from a spec, so it is not independent
  of us: this shows the method works, not that third-party guards are safe.
- a clean result after N attempts means N attempts of this kind found nothing,
  not that vault-a is safe.
- the AI tester sees INTERFACE.md only; its sequences are replayable files.

## Limits

- One UTC day per attempt (the cap term assumes a single day).
- Per-invoice attribution (since 2026-11-10) uses the harness's own record of
  successful `pay` calls and the guard's `Paid` status to decide which invoices
  explain a receiver's tokens. These can only grant allowance. A guard that
  marks a valid invoice `Paid` after its transfer failed, while paying another
  bill to the same receiver, could still hide that payment. Before that change
  the rule was per receiver (mutation table, M6/M7/M8).
- The scorer's should-pay order is greedy in manifest order — a fixed,
  deterministic rule chosen before any tester ran.
- Sandbox only; real-network timing differs.
