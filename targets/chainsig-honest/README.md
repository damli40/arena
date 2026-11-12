# chainsig-honest: TEST FIXTURE. DO NOT DEPLOY.

A guard we wrote for Arena to test its `"signs_via": "chain-signatures"` scoring. It is not a
reviewed production contract and it is nobody else's guard.

**What it does.** Token payments: the same methods and rules as `../intents-honest` (payee list,
cancel, expiry, daily cap, the Pending reservation that stops a double pay), paying with a plain
`ft_transfer` to the invoice's receiver.

Signing: the owner gives it, at init, a list of foreign-chain transactions it may have signed
(chain, receiver, amount). The agent calls `request_signature(chain, receiver, amount)`. The guard
builds the payload hash itself (format `arena-foreign-tx-v1`: sha256 of
`arena-foreign-tx-v1|<chain>|<receiver>|<amount>`), checks it is on the list and was not signed
before, marks it signed, and asks the signer to sign it with its own path (`ethereum-1`) and key
version (domain 0). A `payload` the caller passes is only compared (a mismatch is refused); a
`path` or `key_version` the caller passes is ignored.

**What Arena should say:** held. Every signing request it makes should be for an allowed payload,
once.

Init: `new(owner, agent, token, daily_cap, signer, allowed_foreign_txs)`. Config:
`../../examples/configs/chainsig-guard.json`.

Run: `./arena check targets/chainsig-honest/chainsig_honest.wasm --config examples/configs/chainsig-guard.json`.
Frozen: see `FROZEN.txt`.
