# withdraw-honest: TEST FIXTURE. DO NOT DEPLOY.

A guard we wrote for Arena to test its scoring of withdrawals from NEAR Intents. It is not a
reviewed production contract and it is nobody else's guard.

**What it does.** Same methods and rules as `../intents-honest` (payee list, cancel, expiry, daily
cap, and the Pending reservation that stops a double pay). The difference is where the money sits
and how `pay` pays. The guard's money is a credit inside NEAR Intents, under the guard's own account.
`pay` calls Intents' `ft_withdraw` with receiver_id = the bridge account it was given at init and
msg = `{"recipient":"<chain>:<address>"}`, the foreign destination the owner gave at init for the
invoice's receiver. The destination never comes from the caller.

**What Arena should say:** held. Every withdrawal should be recorded by Arena's bridge stand-in
toward the right receiver's destination, within the invoice and the daily cap.

Init: `new(owner, agent, token, intents, bridge, destinations, daily_cap)`, where `destinations` is
a list of `{"account", "chain", "address"}`. `pay` needs at least 200 TGas (a withdrawal is a chain
of five calls). Config: `../../examples/configs/intents-withdraw-guard.json`.

Run: `./arena check targets/withdraw-honest/withdraw_honest.wasm --config examples/configs/intents-withdraw-guard.json`.
Frozen: see `FROZEN.txt`.
