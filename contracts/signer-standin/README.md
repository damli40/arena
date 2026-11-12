# signer-standin: Arena's stand-in for NEAR's Chain Signatures contract. NOT the MPC network.

It holds no key and produces no signature. Arena deploys it on its local sandbox in place of
`v1.signer`, for guards whose config says `"signs_via": "chain-signatures"`.

- **Takes `v1.signer`'s `sign` request shape, as Arena reads it** (github.com/near/mpc):
  `{"request": {"payload_v2": {"Ecdsa": "<64 hex>"}, "path": "...", "domain_id": 0}}` or the
  older `{"request": {"payload": [32 bytes], "path": "...", "domain_id": 0}}`. Either form may
  give `key_version` instead of `domain_id`: the real contract reads it as another name for the
  same field. It refuses a call with less than 1 yoctoNEAR or 10 TGas attached, with no
  `domain_id`/`key_version` or with both, an Ecdsa payload that is not 32 bytes, or a domain that
  does not fit the payload type. These checks are our reading of the real contract, not a copy:
  the real one may accept or refuse a request this one does not.
- **A refused request leaves no record.** So Arena treats any failed call on the stand-in inside a
  transaction where the guard ran as "could not finish", never held.
- **Records every request** (caller, form, payload hex, path, domain id, block
  height, deposit). Free views: `request_count()`, `requests(from_index, limit)`.
- **Returns a fake signature at once**, all zeros, with `"arena_stand_in": "NOT A SIGNATURE ..."`.
  The real contract answers later through yield/resume, after the MPC nodes sign.

Differences on purpose: no yield/resume, no timeout, no key derivation (`public_key` and
`derived_public_key` return a text saying there is no key), and it keeps the whole deposit (the
real one refunds the excess). Nothing here shows whether the real network would accept a request,
or whether another chain would accept the transaction.

Build (pinned toolchain, offline once the crates are cached):
`cargo build --release --target wasm32-unknown-unknown` in this folder, then copy
`target/wasm32-unknown-unknown/release/signer_standin.wasm` here. The harness checks its sha256
(`harness/src/chainsig.rs`, `SIGNER_SHA256`) before every run. See `FROZEN.txt`.
