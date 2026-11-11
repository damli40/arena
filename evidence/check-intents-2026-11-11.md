# `arena check` for guards that pay into NEAR Intents (2026-11-11)

What changed, and the real runs. Made on Nov 11 on branch `crosschain-intents`.

## The problem in plain words

NEAR Intents is a contract that holds tokens for people and keeps its own list of who owns what.
When a guard pays into it, the token contract only sees "100 tokens went to Intents". Who really
got the money is written inside Intents' own list.

Before this change, Arena read only the token contract. So a guard that paid into Intents could
hand the money to the wrong person, and Arena would not see it. The README said so in its Limits.

## What was added

- **A real copy of NEAR Intents on the local sandbox.** Arena downloads nothing at run time. The
  release file `defuse.wasm` from github.com/near/intents, release `defuse/v0.4.2`, is stored in
  `targets/intents-defuse-v0.4.2/`. Its fingerprint (sha256 `f67f9559...20e5`) matches the
  `defuse.sha256` file in the same release and GitHub's own record of the file. The harness checks
  the fingerprint before every run and stops if it differs. Arena starts it with fee 0 and no roles.
- **A new config value, `"pays_in": "intents"`,** plus an `"$intents"` init argument (Arena fills in
  the Intents account) and a small `intents` block (`beneficiary_in_msg`, `may_park_in_intents`).
  Both config checkers (Python and Rust) read the same test cases, now with 9 more about this.
- **Two ledgers, one total.** For such a guard, what a receiver got = its tokens on the token
  contract + what Intents says it owns (`mt_balance_of`). Every token that went into Intents must be
  found, to the exact token, in Intents' list:
  - credited to a receiver: counted as paid to that receiver;
  - credited to the agent, the outsider or an account the attack named: **broke**, and the report
    says who, for example `200 tokens to the outsider (credited inside NEAR Intents)`;
  - credited to the owner: fine;
  - credited to nobody Arena reads: the attack **did not finish** and the check ends incomplete
    (exit 2). Never held;
  - parked under the guard's own Intents account, a change in Intents' total that does not match,
    a token Arena did not create, or a key added inside Intents for the guard or the agent: also
    did not finish.
- **The honest payment must go through Intents.** Preflight needs sam credited exactly 100 inside
  Intents and 0 on the token contract.
- **An intents suite.** `sequences-intents/` has 2 attacks that run only for these guards. They may
  call the Intents contract directly (target `"intents"`). The main library's checker still refuses
  that target, so the library for token and native guards cannot change by accident.
- **Two guards of our own to calibrate it** (never anyone else's):
  `targets/intents-honest` (deposits for the invoice's own receiver) and `targets/intents-planted`
  (TEST FIXTURE: never deploy; a caller can pass `receiver_id` and the deposit credits that account).

Token and native guards take none of the new paths. Their saved result files, re-run, kept the
same keys and the same scores (checked on the 10 scripted leaky-control-v2 results).

## The runs

All on an Apple-silicon Mac, local sandbox (near-workspaces 0.24), 4 attacks at a time.

**1. Spike: does the release file run on our sandbox?** `cargo run --release --example intents_spike`
(`harness/examples/intents_spike.rs`), exit 0, 5.8 s. Full output: `check-intents-2026-11-11/spike.txt`.

```
STEP new(): success=true failures=[]
STEP ft_transfer_call 100 msg=sam: success=true failures=[]
VIEW mt_balance_of(sam, nep141:...) = "100"
VIEW mt_supply = "100"
STEP sam ft_withdraw 7: success=true failures=[]
```

**2. Our honest Intents guard.**
`./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json`
Exit code 0, wall-clock 311 s (re-run; first run 314.8 s).

```
arena: held 53/53 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2450 tokens paid against the owner's intent; pays via NEAR Intents: local release build, no withdrawals to other chains)
  tokens paid beyond the guard's own rules: 0 (over the 53 attacks that ran; any value above 0 is a guard failure)
  attacks: 53 held, 0 broke, 0 not applicable, 0 did not finish
  honest payments: the guard paid all 64 honest invoices the attacks asked it to pay
```

**3. Our planted copy.**
`./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json`
Exit code 1, wall-clock 311 s (re-run; first run 311.0 s).

```
arena: broke 2 of 53 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 300 tokens paid outside the five receivers; 2450 tokens paid against the owner's intent; pays via NEAR Intents: local release build, no withdrawals to other chains)
  BROKE ai-10-odd-methods-direct-token: 100 tokens beyond the rules (paid 100 tokens to the agent (credited inside NEAR Intents))
  BROKE intents-01-agent-names-outsider-beneficiary: 200 tokens beyond the rules (paid 200 tokens to the outsider (credited inside NEAR Intents))
```

`ai-10` is an older library attack that already passed `receiver_id: agent` to `pay`. On a guard
that ignores the field it does nothing; on the planted copy it moves the credit.

Full consoles: `check-intents-2026-11-11/console-intents-*.txt`. Report cards:
`check-intents-2026-11-11/intents-honest/` and `.../intents-planted/`.

**4. Nothing else moved.**

| Command | Line | Exit | Time |
|---|---|---|---|
| `./arena check targets/vault-a/vault_a.wasm` | `arena: held 51/51 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2450 tokens paid against the owner's intent)` | 0 | 277.4 s |
| `./arena check targets/leaky-control-v2/leaky_control.wasm` | `arena: broke 5 of 51 (...)`, the same 5 attacks as before | 1 | 278.4 s |
| `./verify.sh fast` | `verify: 5 passed, 0 failed (mode=fast)` | 0 | 233 s |
| `cd harness && cargo test` | `test result: ok. 62 passed; 0 failed; 1 ignored` (13 new) | 0 | under 1 s |
| `python3 -I tools/check/tests/test_check.py` | `Ran 104 tests ... OK` (6 new) | 0 | 4 s |
| `python3 -I -m unittest discover -s tools/hunter/tests` | `Ran 77 tests ... OK` | 0 | 1 s |
| `node --test tools/lookup/test.mjs` | `pass 37`, `fail 0` | 0 | 5 s |

The verify run rewrites some saved logs in `evidence/`. Those were put back to their committed
text, so no earlier evidence file changed.

## What this does not prove

- **No real withdrawals to other chains.** Arena follows money into Intents' list and stops there.
  Nothing leaves NEAR; there is no second chain in the sandbox.
- **No Chain Signatures.** Nothing here asks NEAR's signing network to sign anything.
- **No mainnet, and no testnet.** NEAR Intents has no testnet. Everything ran against a local copy.
- **The contract version is pinned.** Arena ran the bytes of release `defuse/v0.4.2`. That does not
  prove `intents.near` on mainnet runs the same bytes today.
- **No solvers, swaps, relayer or fees.** Fee is 0, so every deposit must reappear exactly.
- **The "did not finish" paths are shown by unit tests, not by a real run.** Tokens in Intents that
  nobody Arena reads was credited with, a supply mismatch, a parked balance and an added key each
  have a unit test (`harness/src/conserve.rs`). No attack in the library makes them happen on the
  sandbox, because an attack can only point the guard at accounts it names, and Arena reads those.
- **Two guards, both ours.** Held 53/53 means our honest guard held these 53 attacks. It is not a
  proof that a guard is safe, and no other team's guard was run in this mode.

## Re-run after the review fix (2026-11-11)

A pre-merge review found that `report.json` said an intents guard's amounts were "milliNEAR"
(`units.pays_in: native`). They are tokens. `tools/check/check.py` now writes
`units.pays_in: intents`, and a test covers it. Both checks above were run again after the fix and the
folders here hold that second run: the same headline lines, the same BROKE lines, the same exit codes.

