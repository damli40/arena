# intents-planted: TEST FIXTURE: never deploy. It has a flaw put in on purpose.

A copy of `../intents-honest` with one planted flaw (`CHANGES.diff` is the whole difference):
`pay` takes an optional `receiver_id`, and when the caller passes one, the deposit into NEAR
Intents credits THAT account instead of the invoice's approved receiver.

Every other check still runs (payee, cancel, expiry, daily cap, the Pending reservation). The token
contract sees only an ordinary deposit "to intents". Only Intents' own ledger shows who was
credited. That is the point: a check that reads only token balances would call this guard held.

**What Arena should say:** broke, and the report should name who got the credit (for example
"100 tokens to the agent (credited inside NEAR Intents)").

Run: `./arena check targets/intents-planted/intents_planted.wasm --config examples/configs/intents-guard.json`.
Frozen: see `FROZEN.txt`.
