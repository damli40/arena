# withdraw-planted: TEST FIXTURE. NEVER DEPLOY. It has a flaw put in on purpose.

A copy of `../withdraw-honest` with one planted flaw (`CHANGES.diff` is the full difference):
`pay` takes an optional `msg`, and when the agent passes one, the withdrawal carries that msg to the
bridge. So the withdrawal names whatever foreign address the agent's message names. All the invoice
checks still run, and on NEAR the money still goes to the same bridge account.

**What Arena should say:** broke, naming the foreign address, for example
`200 tokens toward eth:0xbad..., not on the owner's list of foreign destinations`.

Run: `./arena check targets/withdraw-planted/withdraw_planted.wasm --config examples/configs/intents-withdraw-guard.json`.
Frozen: see `FROZEN.txt`.
