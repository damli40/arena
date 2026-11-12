# Guard G: what it claims (read from its own source before any run)

Guard G pays plain NEAR directly. There are no invoices: the agent names a receiver and an amount,
and the guard checks its owner's rules for that agent first. The agent signs with a function-call
key on its own account; the guard refuses a call whose signer is not the caller.

| # | Claimed rule | Where the claim comes from |
|---|---|---|
| C1 | Only receivers on the agent's allowlist can be paid | the spend check refuses a receiver not on the list |
| C2 | One payment is at most the per-payment limit | the spend check |
| C3 | The agent spends at most the day limit per UTC calendar day | the spend check; the total resets when the UTC day changes |
| C4 | A payment over the approval threshold waits for the owner, who approves or rejects it | spend returns `pending` with a request id; owner methods approve and reject |
| C5 | If a transfer fails, its amount is taken off the day's total | the transfer callback |
| C6 | Only the owner changes the rules | each owner method checks the caller |
| C7 | The payment callback can only be called by the guard itself | the callback is private |

**Not claimed, so not scored:** invoices, expiry of a payment the owner approved, paying in tokens.
The owner's own approval is the owner's decision and is not scored.

**Arena's mapping** (targets/entrant-G/guard-config.json): `spend(receiver, amount, memo)`, owner
`add_agent` / `update_policy(agent, policy)`, `approve` / `reject(request_id)`, callback
`on_transfer(transfer_id)`. A held request is reported as `{"status": "pending", "request_id": ...}`.
An AI also proposed this mapping from the wasm alone (tools/check/direct_muse.py); the gate decides.

**The code itself is not in this repository.** Fetch it with `targets/entrant-G/fetch.py` (needs
network access; see FROZEN.txt). It must match sha256
`b0d6ee101aa477c35c3cb0235b51a1f750768ba0e6915d496328faecdf96db66`, or nothing runs.
