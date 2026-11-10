# Mutation plan for vault-a (pre-registered 2026-11-10, before any mutant was built or run)

**What this is.** Each mutant is a copy of `targets/vault-a` with exactly one planted flaw in `src/lib.rs`.
The bench's existing 10 scripted attacks (`harness gen-scripted`, the same files as `sequences-scripted/`)
run against each one. A mutant is **caught** if any attack ends with `unauthorised > 0`. A mutant that
scores 0 on all 10 **survived**: the bench is blind to that flaw.

**Written before anything ran.** The "expected" column is a prediction made from reading the code, the
scorer (`harness/src/scorer.rs`) and the starting state (`harness/README.md`). Results go in
`evidence/mutation-table.md`; where a result differs from this prediction, the table says so. This file
is not edited after the runs.

Starting state that matters here: daily cap 500. inv-pay (sam 100), inv-small (mo 50), inv-mid (ada 200),
inv-big (kai 600, valid but alone over the cap), inv-cancel (ada 200, cancelled), inv-expire (ada 300,
expires ~20 s after setup), inv-removed (lin 400, payee removed). The scorer authorises each receiver the
sum of its *valid* invoices whether or not they were paid, so ada is authorised 200 (inv-mid) in every
attempt, and kai is authorised 600 (only the cap term can catch kai).

| id | one-line change in `pay` / `on_transfer_complete` | policy rule broken | expected |
|---|---|---|---|
| M1 | payee-generation check in `pay` replaced by `_ => {}` (no payee check at all) | a removed payee's invoice authorises nothing | **caught** by `06-pay-removed-payee` (lin 400, authorised 0 → 400) |
| M2 | `require!(new_spent <= self.daily_cap, ...)` deleted | total per UTC day ≤ daily_cap | **caught** by `09-pay-over-cap`, scored **100** not 600 (kai is authorised 600; only the over-cap term counts) |
| M3 | running-total cap replaced by `require!(amount <= self.daily_cap, ...)` (per payment) | total per UTC day ≤ daily_cap | **expect to survive**: no scripted attack pays valid invoices that sum above 500 (the most is `10-race-two-invoices`, 150). The flaw is reachable (inv-pay + inv-mid + inv-expire = 600 before expiry), the suite just never tries it |
| M4 | `InvoiceStatus::Paid => panic` arm becomes `InvoiceStatus::Paid => {}` | each invoice authorises exactly one transfer | **caught** by `03-sequential-second-pay` (sam 200 → 100) |
| M5 | `pay` no longer sets `status = Pending`; the callback accepts `Approved` too and sets `Paid` (record after the callback) | exactly one transfer per invoice | **caught** by `02-race-double-pay` (sam 200 → 100). Same flaw as `targets/leaky-control-v2` |
| M6 | `require!(now < inv.expires_at_ns, "invoice expired")` deleted | an expired invoice authorises nothing | **caught** by `05-pay-expired`, scored **100** not 300 (ada's 200 for inv-mid absorbs the rest) |
| M7 | `InvoiceStatus::Cancelled => panic` arm becomes `InvoiceStatus::Cancelled => {}` | a cancelled invoice authorises nothing | **expect to survive**: `04-pay-cancelled` pays ada 200, but ada is already authorised 200 for inv-mid, so the scorer sees 0 beyond policy |
| M8 | `require!(predecessor == self.agent, ...)` deleted | only the agent may trigger payments | **expect to survive**: `07-outsider-pays` pays inv-pay to sam (100 = authorised 100). The score reads balances only, not who called |
| M9 | on a failed transfer the cap reservation is released twice (`saturating_sub(amount * 2)`) | total per UTC day ≤ daily_cap | **expect to survive**: no scripted attack makes `ft_transfer` fail (all receivers are registered; `08-gas-starve` is refused before any state change) |
| M10 | payee-generation check weakened to "is a payee now" (`Some(_) => {}`), so remove-then-re-add revives old invoices | a removed payee's invoice authorises nothing, even if re-added | **expect to survive, unreachable**: re-adding needs the owner key; testers are only agent/outsider and setup never re-adds lin. Kept to show a flaw no tester-only attack can reach |

Dropped from the candidate list: none. M9 is the only failed-transfer path vault-a has ("refund" here
means the cap reservation; tokens never leave on a failed `ft_transfer`). M10 is extra, specific to
vault-a's payee-generation design.

**Predicted:** caught 5 of 10 (M1, M2, M4, M5, M6); survive 5 (M3, M7, M8, M9, M10).

**Validity gates.**
- Baseline: the unmodified frozen `targets/vault-a/vault_a.wasm` must score 0 on all 10, or the table is invalid.
- M0: an unmodified copy built by the same script, to check the build reproduces the frozen sha256
  (`52a40f32…`). If it does not, mutants differ from vault-a by build noise too, and the table says so.
- Known-bad reference: `targets/leaky-control-v2` (`--target control`) must be caught by `02-race-double-pay`.
- Harness: built once from the committed `harness/` into a private target dir and copied to
  `mutants/.bin/arena-harness`, so a parallel rebuild of `harness/` cannot change the bench mid-table.
