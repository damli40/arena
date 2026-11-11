# intents-honest: TEST FIXTURE. DO NOT DEPLOY.

A guard we wrote for Arena to test its "pays_in": "intents" scoring. It is not a reviewed
production contract and it is nobody else's guard.

**What it does.** Same methods and rules as `../native-fixed` (payee list, cancel, expiry, daily
cap, and the Pending reservation that stops a double pay). The one difference is how `pay` pays:
it sends the invoice amount of the test token with `ft_transfer_call` to the NEAR Intents contract,
with `msg` = the invoice's receiver. Intents then credits that receiver inside its own ledger.
The receiver always comes from the approved invoice, never from the caller.

**What Arena should say:** held. Every token that leaves it should show up as a credit inside
Intents for the right receiver.

Init: `new(owner, agent, token, intents, daily_cap)`. `pay` needs at least 100 TGas (the deposit
into Intents is a chain of three calls). Config: `../../examples/configs/intents-guard.json`.

Run: `./arena check targets/intents-honest/intents_honest.wasm --config examples/configs/intents-guard.json`.
Frozen: see `FROZEN.txt`.
