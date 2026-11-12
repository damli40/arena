# `arena check` for guards that ask Chain Signatures to sign (2026-11-11)

What changed, and the real runs. Made on Nov 11 on branch `chain-signatures`.

## The problem in plain words

NEAR Chain Signatures lets a NEAR contract get a transaction for another chain (Ethereum, for
example) signed. The contract sends a 32-byte hash of that transaction to the signer contract
(`v1.signer` on mainnet). The signer's nodes sign it together (MPC: several parties each hold part
of the key, and no single one can sign alone) and hand back a signature.

So a guard that does this can move money on another chain without a single NEAR token leaving it.
Before this change Arena read only token and NEAR balances, so such a guard could sign anything and
Arena would say held. The README's Limits said Chain Signatures requests were not tested.

## What was added

- **A stand-in signer, `contracts/signer-standin/`.** It takes the same `sign` request shape as
  `v1.signer` (the new `payload_v2` form and the older `payload` + `key_version` form), writes down
  every request (who asked, the hash, the path, the key version, the block) and returns a fake
  signature marked `NOT A SIGNATURE`. It signs nothing and talks to no other chain. It is built from
  source in this repo; nothing was downloaded. The harness checks its fingerprint (sha256
  `fa83ea44...56c1`) before every run.
- **The owner's allowed list, `policy/chain-signatures-allowed.json`.** Two foreign transactions
  the owner allows (`ftx-sam`, `ftx-ada`) and one the attacks use that the owner did not allow
  (`ftx-agent`, paying the agent's own foreign address). Each payload is the sha256 of
  `arena-foreign-tx-v1|<chain>|<receiver>|<amount>`. Arena recomputes every hash itself before any
  attack and stops if one does not match. This is Arena's own format, not a real Ethereum
  transaction encoding.
- **A config value, `"signs_via": "chain-signatures"`,** plus `$signer` and `$allowed_foreign_txs`
  init arguments. Token guards only (refused with `"pays_in": "native"` or `"intents"`). The guard
  is still scored on its token payments as before; signing is scored on top.
- **The signing score is a count, never an amount.** For each attack, Arena reads the stand-in's
  records and counts the guard's requests the owner did not allow: a hash not on the list, an
  allowed hash signed a second time (`SIGNED TWICE`), or a path or key version other than the one
  the config declares. Any count above 0 is broke. Arena cannot know what an unknown hash was worth,
  so it never turns the count into tokens. Requests made by other accounts are listed, not counted.
  If the records cannot be read, go backwards, have gaps, or a request uses a form Arena does not
  know, the attack did not finish: never held.
- **A signing preflight.** Before the attacks, the agent asks for `ftx-sam`, which the owner
  allowed. The guard must ask the signer exactly once, for that hash, with the declared path and key
  version. Otherwise the check stops with exit 2 and says why.
- **A chain-signatures suite.** `sequences-chainsig/` has the preflight and 6 attacks that run only
  for these guards: the agent passes another payload, replays an allowed one, swaps path or key
  version, races two requests, an outsider calls the signer directly, and the agent asks for an
  unlisted transaction.
- **Two guards of our own to calibrate it** (never anyone else's): `targets/chainsig-honest`
  (signs only listed hashes, each once, with its fixed path) and `targets/chainsig-planted`
  (TEST FIXTURE, NEVER DEPLOY: signs whatever hash the caller passes, with no list and no once-only
  check).

## The runs

All on an Apple-silicon Mac, local sandbox, from the repo folder, on the code of commit
84f4df0 (runs 1 and 2) and 84f4df0 plus the wrong-path config (run 3). Commit 6f27e2a then changed
only the report fix below; the fresh-copy regression re-ran all three on 6f27e2a.

**1. Honest guard.** Exit 0, 344 s wall. Full output: `check-chainsig-2026-11-11/console-chainsig-honest.txt`.

```
./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard.json
arena: held 57/57 (0 not applicable; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2450 tokens paid against the owner's intent; signs via Chain Signatures: Arena's stand-in signer, no real MPC signing, nothing sent to another chain)
  signing requests outside the owner's list: 0 (a COUNT of requests ...)
  signing preflight: signed ftx-sam once (not an attack; not in any count)
```

57 = the 51 library attacks plus the 6 in `sequences-chainsig/`.

**2. Planted guard.** Exit 1, 355 s wall. Full output: `check-chainsig-2026-11-11/console-chainsig-planted.txt`.

```
./arena check targets/chainsig-planted/chainsig_planted.wasm --config examples/configs/chainsig-guard.json
arena: broke 3 of 57 (...; 3 signing requests outside the owner's list (a count, not an amount); ...)
  BROKE chainsig-01-agent-passes-other-payload: 0 tokens beyond the rules; 1 signing request outside the owner's list (a count, not an amount)
  BROKE chainsig-02-replay-allowed-payload: 0 tokens beyond the rules; 1 signing request outside the owner's list (a count, not an amount)
  BROKE chainsig-04-race-two-sign-requests: 0 tokens beyond the rules; 1 signing request outside the owner's list (a count, not an amount)
```

The other three chainsig attacks held on the planted guard, as they should. The planted flaw only
lets through a hash the caller *passes*. 03 tries a different path and key version, but the planted
guard still signs with its own fixed ones. 05 has three steps: the outsider calls the signer
directly (not the guard's request: listed, not counted), the outsider asks the guard to sign ftx-ada
(both guards refuse, because both keep the "only the agent may ask" check), and the agent's key tries
the signer (NEAR refuses it). [Corrected 2026-11-12: this line first named only the first step; see
Corrections below.] 06 names an unlisted transaction without passing a
hash, so the planted guard checks it against the list like the honest one and refuses. The token score of both guards is the same as vault-a's: 0 beyond policy, 2450 against
the owner's intent.

**3. A config that does not match the guard.** `examples/configs/chainsig-guard-wrong-path.json`
declares path `ethereum-2`; the honest guard signs with `ethereum-1`. Exit 2, 19 s.

```
./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard-wrong-path.json
arena: not run
COULD NOT FINISH:
  Arena cannot score this guard's signing. On the signing preflight (the agent asks for ftx-sam, which the owner allowed) the guard made 1 signing requests, matched [], and 1 were outside the owner's list. ...
```

**A bug this run found, fixed in 6f27e2a.** In run 3 the report also printed
`signing requests outside the owner's list: 0`, although no attack ran and the preflight had just
found 1. A 0 there reads as "checked and clean". The line is now left out when no attack ran (test
`test_not_run_gives_no_signing_count`), and the preflight message says `signing request(s)`.

**4. Fresh-copy regression.** See `clean-copy-chainsig-2026-11-12.md`.

## What this does not show

- **No real signing.** The stand-in returns a fake signature. Nothing here tests `v1.signer`'s
  MPC nodes, its fees, its timing, or what happens when it fails or is slow.
- **Nothing reaches another chain.** Arena checks what the guard *asked* to have signed. It does not
  build, send or check a transaction on Ethereum or anywhere else.
- **The payload format is Arena's own** (a sha256 of a short text line), not a real RLP-encoded
  Ethereum transaction. A guard that hashes real transactions needs a config Arena does not have yet.
- **Only two guards, both ours.** No other team's Chain Signatures guard was tested.
- **Not every refusal path ran in a real attack.** The "a tester transaction ran code on an account
  Arena does not know" path is covered by unit tests, not by a sandbox run that triggered it.
- **Local sandbox only.** No testnet or mainnet writes.

## Corrections (2026-11-12, after the merge review)

A review of commit cacf4f2 found three things. We fixed them on the same branch; the new runs are in
`clean-copy-chainsig-2026-11-12b.md`.

1. **The score did not check who asked the guard to sign.** In attack 05, the outsider asks the guard
   to sign ftx-ada, which is on the list. A guard without an "only the agent" check would have signed
   it once, and Arena would have scored that as an allowed match, so 05 could not fail on that step.
   Our two guards both refuse the outsider, so the numbers above did not change, but the attack was
   weaker than its description said. Now Arena finds the step that caused each guard request and
   counts a request caused by a step the outsider sent as unauthorised (only the agent and the
   outsider send steps; an earlier version of this line also named the owner).
2. **A refused request was invisible.** The stand-in refused two request shapes the real signer
   accepts (`key_version` given in place of `domain_id`, which the real contract reads as the same
   field), and a refused request leaves no record. A guard using those shapes would have shown 0
   requests on every attack. Now any failed call on the stand-in inside a transaction where the guard
   ran makes the attack "could not finish", and the stand-in accepts both names (a request with
   neither is refused, as in the real one). New stand-in sha256 `bd5b7928...a9ef`. The description
   above, "the same `sign` request shape", said more than we checked: the stand-in follows our
   reading of the real contract, not a copy of it.
3. **The badge said "N unauthorised signing requests"** without the "a count, not an amount"
   qualifier the report lines carry. It now says `(count, not amount)`.

## Second review (2026-11-12)

A review of `cacf4f2..b6cedd0` found three more things, fixed on the same branch. New runs:
`clean-copy-chainsig-2026-11-12c.md`.

1. **A guard could turn broke into "could not finish".** Any reason Arena could not score an attack
   used to win over a finding. So a guard that signs an off-list hash AND makes one malformed sign
   call (for example 0 yoctoNEAR attached) ended "could not finish" instead of broke. Now a recorded
   unauthorised request makes the attack broke, whatever else failed. The count is then a lower
   bound and that attack's token numbers are not used. Tests:
   `a_recorded_unauthorised_request_is_broke_even_with_a_failed_signer_call` (Rust) and
   `test_recorded_unauthorised_request_is_broke_even_if_a_sign_call_failed` (Python).
2. **Two limits now in the README and CHECK-YOUR-GUARD.** An attacker can force "could not finish"
   on an honest guard (too little gas for the forwarded sign call, or a huge `path` filling the
   stand-in's storage); that blocks a verdict but never fakes a pass. And a request the outsider
   queues in one step and the agent's next step makes the guard sign is credited to the agent, so a
   listed hash passes.
3. **Wording.** Only the agent and the outsider send attack steps, so "the owner" and "an account
   the attack named" were removed from who may ask; only the agent may. "Outside the owner's list"
   was wrong for a listed hash the outsider caused. Lines now say "unauthorised signing requests"
   and give the reasons (off the list, signed twice, a different path or key, or asked for by
   someone other than the agent).
