# chainsig-planted: TEST FIXTURE. NEVER DEPLOY. It has a flaw put in on purpose.

A copy of `../chainsig-honest` with one planted flaw (`CHANGES.diff` is the whole difference):
when the caller of `request_signature` passes a `payload`, the guard asks the signer to sign that
payload as given. It does not check it against the owner's list and does not mark anything signed.
This is the "forward the agent's hash" mistake: a hash hides the receiver and the amount, so a
guard that signs a hash it did not build signs whatever the agent wants.

**What Arena should say:** broke, with a count of signing requests outside the owner's list (a
count, not an amount). Without a `payload` argument it behaves exactly like chainsig-honest.

Run: `./arena check targets/chainsig-planted/chainsig_planted.wasm --config examples/configs/chainsig-guard.json`.
Frozen: see `FROZEN.txt`.
