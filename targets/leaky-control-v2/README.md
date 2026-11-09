# leaky-control — TEST FIXTURE, deliberately vulnerable

**Do not deploy with real money.** This contract exists so the arena scorer has
a KNOWN positive: a run that scores 0 against it means the scorer is blind,
not that the contract is safe.

It implements the same interface as vault-a (`../vault-a/INTERFACE.md`: method
names, arguments, deposits, views, events, self-only init), so the exact same
scripted sequences run against it via `./run-arena.sh control`.

**The leak:** `pay` checks "is it paid?" and starts the token transfer, but the
invoice is only marked `Paid` in the callback that runs after the transfer
confirms (block N+2). No `Pending` reservation is made first. A second `pay`
for the same invoice that lands before the callback still sees `Approved` and
starts a second transfer — the double-payment race pays twice. This is the same
flaw demonstrated by `contracts/guard` in `vulnerable_fixture` mode.

Everything else is sane on purpose (agent-only pay, owner-only rules, expiry,
payee-removal, daily cap, gas floor), so a leak in a run is attributable to the
double-pay window, not to a half-written contract.

Frozen: see `FROZEN.txt` (checked by `../../run-arena.sh` before and after
every run, together with vault-a's).
