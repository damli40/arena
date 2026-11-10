# arena: double-payment race on a local NEAR sandbox

**Question:** if a payment guard records an invoice as "paid" only after the token
transfer confirms, can two `pay` calls for the same invoice both get through?

**Answer from this run (2026-11-08): yes.** 5 out of 5 races paid the invoice twice.
The fixed guard paid once in 5 out of 5 races, and still recovered after a transfer that really failed.

**Second question (same day):** what if the token transfer finishes but the guard's callback
(`on_transfer`, the step that writes the result down) fails? **Answer from the second run:**

- Vulnerable guard: the callback's "paid" note is rolled back. The invoice still says `Approved`
  although Sam (the receiver) has the money. One retry paid Sam a second time (200 for a 100 invoice).
- Fixed guard: the invoice stays `Pending` forever. No double payment, but it is stuck. If the money
  arrived, a careless "reset and retry" would pay twice. If it did not arrive, an honest invoice is frozen.
- New in the fixed guard: the owner can call `reconcile(id)`. It checks the guard's real token
  balance and settles the invoice from that evidence. In both stuck cases it reached the right
  answer, and Sam was paid exactly once.
- **Changed Nov 10 2026 (`evidence/fix-plan-2026-11-11.md`).** `reconcile` could pay twice: if the
  money left, the callback died, and someone then sent the guard the same amount, the balance looked
  untouched and `reconcile` reopened the invoice (`evidence/proofs-adversarial-review-2026-11-11.md`, H1).
  Now `reconcile` only ever settles "the money left" (`Paid`). For anything else the owner closes the
  invoice with `resolve_stuck(id, sent)`. See "How `reconcile` decides" below.

Local only. `near-workspaces` starts a throwaway `near-sandbox` node (nearcore 2.14.0)
on this machine. No testnet, no mainnet.

## Why it happens

On NEAR, a contract calling another contract does not happen in one step. Each hop runs in a later block:

| block | what runs |
|---|---|
| N   | guard `pay` checks "is it paid?" and starts the transfer |
| N+1 | token `ft_transfer` moves the tokens |
| N+2 | guard `on_transfer` callback marks the invoice "paid" |

The vulnerable guard writes "paid" only at N+2. Any second `pay` that runs in block N or N+1
still sees "not paid" and starts a second transfer. In the run, both `pay` calls ran in the same block.

The fixed guard sets the invoice to `Pending` at block N, in the same step as the check.
The second `pay` sees `Pending` and is refused ("payment already in flight"). If the transfer
fails, the callback puts the invoice back to `Approved` so it can be paid again.

## Run it

```
./run.sh
```

This builds the contracts with the pinned toolchain, plus a second, test-only guard build
(see "Fault injection" below), then runs 12 tests (10 before the Nov 10 fix). Evidence for each test prints to stdout.
Saved runs: `evidence/run-2026-11-08.log` (t1-t4), `evidence/run-2026-11-08-callback.log` (t1-t10, old
`reconcile`), and `evidence/verify-2026-11-11-run.log` (t1-t12, new `reconcile`).

## Arena harness (2026-11-09)

`./run-arena.sh scripted|ai` runs two testers against the frozen `targets/vault-a/`
under equal conditions and scores them by `policy/vault-a.policy.md` (see
`harness/README.md`). Saved logs: `evidence/arena-2026-11-09-scripted.log`
and `evidence/arena-2026-11-09-ai.log`. Result: 10+10 attempts, 0 unauthorised
payouts; vault-a refused every wrong action and settled honest invoices.
`./run.sh` and the guard are untouched by this.

| test | what it shows | result |
|---|---|---|
| t1 | vulnerable guard, 2 `pay` calls sent together, 5 trials | receiver got 200 every time (invoice is 100) |
| t2 | fixed guard, same race | receiver got 100 every time, the other call refused "payment already in flight" |
| t3 | both guards, second `pay` sent after the first finished | both refuse "invoice already paid" (the bug needs the timing) |
| t4 | fixed guard, receiver not registered on the token, so the transfer fails; register, retry | fail → invoice back to `Approved`, retry pays 100, a third call is refused |
| t5 | transfer reaches Sam, callback panics (fault build), then one retry | vulnerable: Sam 100, record `Approved`; retry accepted, Sam **200**. fixed: Sam 100, stuck `Pending`; retry refused, Sam stays 100 |
| t6 | transfer fails (Sam not registered), callback panics; owner registers Sam; one retry | vulnerable: Sam 0, `Approved`; retry pays 100 but record still `Approved` (next retry would pay twice). fixed: Sam 0, stuck `Pending`; retry refused, invoice frozen |
| t7 | fixed, t5 situation, then owner `reconcile` | right away: refused "too early". After waiting: balance shows the money left → `Paid`. Retry refused. Sam stays 100 |
| t8 | fixed, t6 situation, then owner `reconcile`, then `resolve_stuck(sent=false)` | balance unchanged → stays `Pending` (it proves nothing, see t11). Agent may not resolve. Owner `resolve_stuck(sent=false)` → `Failed`. `pay` refused; the old id cannot be re-approved. Owner approves a new id; it pays 100 once. Sam 100. (Before Nov 10: `reconcile` set `Approved` here.) |
| t9 | fixed, two invoices stuck at once | `reconcile` refuses: "ambiguous: 2 invoices are Pending". Nothing changes |
| t10 | normal build | the fault code is not in `guard.wasm`, and a `crash-` invoice pays normally. Callback gas measured (below) |
| t11 | fixed, transfer reaches Sam, callback panics, **owner tops the guard up by 100**, then `reconcile` (review H1) | stays `Pending` (the old code set `Approved`, and the retry paid Sam 200). Retry refused. `resolve_stuck(sent=true)` → `Paid`. Next pay refused. Sam 100. Ledger re-synced afterwards |
| t12 | `resolve_stuck` refusals | refused for an `Approved` invoice, refused before the 100-block wait, refused in `vulnerable_fixture`. Nothing changes |

Each step in t5-t9 prints Sam's balance, the guard's balance, the invoice status and a case label:
(a) stuck, Sam paid; (b) stuck, Sam unpaid; (c) not stuck, record matches reality;
(d) record says unpaid but Sam already paid, so a retry will pay twice.

**Callback gas.** The callback gets 15 TGas (a fixed gas budget reserved when `pay` runs).
Measured from the sandbox receipts: about 1.55 TGas on both paths, in both modes. That is about 10%
of the budget. So with today's small state, running out of gas in the callback is unlikely. It is not impossible.

## How `reconcile` decides (fixed mode only)

The guard keeps a ledger: how many tokens it should hold. A `Pending` invoice still counts as held.
The ledger goes down only when a transfer is confirmed. The owner sets it once with `sync_ledger`
after funding the guard. `sync_ledger` reads the real balance and is refused while anything is `Pending`.

`reconcile(id)` asks the token for the guard's real balance, then:

- balance = ledger − invoice amount → the money left → `Paid`.
- balance = ledger → **nothing changes; the invoice stays `Pending`.** This reading fits "the
  transfer never happened", but it also fits "it happened, and the same amount was then sent to the
  guard" (an owner top-up, or a gift). The balance cannot tell these apart. Until the Nov 10 fix this arm set
  `Approved`, and in the second story the agent's retry paid Sam twice (t11 shows the fix).
- anything else → refuse. It does not guess.

It also refuses when:

- the caller is not the owner;
- more than one invoice is `Pending` (one balance cannot say which transfer happened);
- fewer than 100 blocks have passed since the invoice went `Pending` (a slow transfer could still land);
- anything changed between the balance request and the answer (a counter, `epoch`, detects this).

It never sends a transfer and never reopens an invoice.

## `resolve_stuck(id, sent)`: the owner closes a stuck invoice (fixed mode only, added Nov 10)

The owner checks the chain (for example the transfer receipt on an explorer) and states the outcome:

- `sent = true` → `Paid`, and the ledger drops by the amount, as a confirmed transfer would.
- `sent = false` → `Failed`. This is terminal: `pay` refuses it, and `approve_invoice` refuses to
  reuse the id. To pay the bill, the owner approves a **new** invoice id.

Same rules as `reconcile`: owner only, fixed mode only, the invoice must be `Pending`, and 100 blocks
must have passed. It never sends tokens.

**The trade-off.** A stuck bill now stays stuck until the owner acts; nothing reopens it on its own.
The agent can never be handed the same invoice twice by `reconcile`. A double payment is still
possible in one way: the owner says `sent = false` for a transfer that did happen, then approves a new
invoice for the same bill. That is the owner's own recorded decision, not something the agent or an
outside transfer can cause.

Why a balance and not something else: on NEAR the guard cannot ask "did transfer X happen?".
It can only read the balance. The ledger turns that balance into a yes/no answer.

## Fault injection (test builds only)

The guard has a cargo feature, `fault-injection`. With it, `on_transfer` panics for invoice ids
that start with `crash-`. This stands in for a callback that runs out of gas or hits a bug.
`./run.sh` builds it into `contracts/target-fault/`, so it cannot overwrite the normal `guard.wasm`.
No account can switch it on at runtime: the normal build does not contain the code. t10 checks
this twice, by searching the wasm bytes and by paying a `crash-` invoice on the normal build.

## Layout

- `contracts/test-token`: minimal NEP-141 token (the NEAR fungible-token standard). Owner gets the supply at init.
- `contracts/guard`: one contract, `mode` = `vulnerable_fixture` or `fixed`. `vulnerable_fixture` is a test fixture. Never deploy it with real money. Only `fixed` has the hardened callback, the ledger, `reconcile` and `resolve_stuck`.
- `tests/tests/race.rs`: the sandbox tests.

## Build notes

- `contracts/rust-toolchain.toml` pins Rust 1.86.0. Newer Rust produces wasm the NEAR VM may reject.
  Cargo's Rust-version-aware resolver (`resolver = "3"`) picked near-sdk 5.27.0. The latest, 5.30.1, needs Rust 1.95.
- `contracts/.cargo/config.toml` adds `--cfg near`. Without it, near-sdk 5.2x builds a fallback
  mode that still deploys and runs, but every refusal shows up as a bare `unreachable` trap with no message.
- `tests/` uses current stable Rust. It runs on this machine and is never compiled to wasm.

## Limits

- Sandbox only. Real-network block timing differs, but the gap between call and callback
  (at least two blocks) is how NEAR works, not something the sandbox adds.
- The callback failure is a forced panic. A real out-of-gas was not produced. Both roll back the
  callback's writes, so the result should be the same. That is inferred, not tested.
- The fixed callback has no `expect` or `unwrap` and uses saturating math. "It cannot panic on its own"
  comes from reading the code. Gas exhaustion or missing storage money could still stop it.
- The 100-block wait in `reconcile` and `resolve_stuck` is a rule of thumb. Since the Nov 10 fix a transfer
  that lands late can no longer cause a second agent payment: `reconcile` never reopens an invoice, and
  a `Failed` invoice cannot be paid. If the owner says `sent = false` and the transfer then lands and
  its callback runs, the callback records `Paid` (the "LATE confirm" log). Not tested on the sandbox.
- If someone sends tokens to the guard with a plain transfer while an invoice is stuck, `reconcile`
  either refuses (balance matches neither story) or leaves it `Pending` (balance happens to equal the
  ledger). Either way the owner closes it with `resolve_stuck`. (Before the Nov 10 fix there was no way out, and
  the "equal" case paid twice: t11.)
- `sync_ledger` is refused while anything is `Pending`, so an untracked top-up stays out of the ledger
  until every stuck invoice is closed. t11 re-syncs after `resolve_stuck`.
- `reconcile` handles one stuck invoice at a time. With two stuck it refuses (t9), and there is no tool for that case yet.
- The race was only tested with both calls in the same block. The table above suggests a
  call in block N+1 would also get through. That is inferred and was not tested.

## History of the guard build

| Date | guard.wasm sha256 (workspace build, `./run.sh`) | What changed |
|---|---|---|
| Nov 8 2026 | `fcce82bf9bad46ae9c7d85952470faf664aa5905bea2df7111ab97601b773372` | first version with the ledger and `reconcile`. Every race result before the Nov 10 fix (local and testnet) ran this wasm |
| Nov 10 2026 | `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e` | `reconcile` no longer reopens on "balance unchanged"; new `resolve_stuck`; new status `Failed`. `vulnerable_fixture` logic unchanged |

Rebuilding the Nov 8 source (saved before the edit) with the same command gives `fcce82bf…` again, byte
for byte, so the new hash differs only by the source change. Note: `cargo build -p guard` alone gives
a different hash than the workspace build (feature unification with `test-token`); the hashes above
are from the workspace build that `./run.sh` runs. Test-only fault build (Nov 10):
`4c737b9d05a9e6bfba340e5b1ce1e66d72164c257fdbfc20928381de37114e83`.
