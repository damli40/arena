# Testnet race plan, Nov 11 guard (written 2026-11-10 WAT, before any trial)

This is step 3h of `fix-plan-2026-11-11.md`, unblocked. It is written before the run so a result that
differs from the plan is visible. The machine clock reads Nov 10; the file carries the Nov 11 name to sit
next to the fix plan.

## What runs

- **Question:** with the fixed guard build, does the testnet race still split the two modes the way the
  Nov 9 run did? Two `pay` calls for one 100-token invoice, sent at the same moment.
- **Wasm (checked before deploying; the runner refuses any other guard via `EXPECT_GUARD_SHA256`):**
  - guard.wasm sha256 `0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e` (Nov 11 build, the
    `reconcile` fix; Nov 9 ran `fcce82bf…`)
  - test_token.wasm sha256 `c8071a2265b6dbd595f319972dc3271d928a73b5a98456538ae5246abf8d3e61` (unchanged)
- **Trials:** 5 per mode, modes `vulnerable_fixture` then `fixed`, fresh accounts every trial, tag `r11`.
- **Method:** the same as Nov 9 (`testnet-2026-11-09.md`, "Method"): two keys on the agent, both `pay`
  calls broadcast together, `max_gas()` (1,000 TGas), RPC `rpc.testnet.fastnear.com`, key nonces checked.

## Expected results

| Mode | Expected receiver payout per trial | Expected rule held |
|---|---|---|
| `vulnerable_fixture` | 200 on the 100 invoice, in 5 of 5 | 0 of 5 |
| `fixed` | 100, in 5 of 5; the other `pay` refused (`payment already in flight`) | 5 of 5 |

Why the same as Nov 9: the fix changed `reconcile` and added `resolve_stuck` (fixed mode only). The race
path (`pay` → transfer → callback) did not change, and `vulnerable_fixture` logic did not change (only the
unreachable `Failed` enum variant was added). Local sandbox t1/t2 with this wasm: `[200×5]` / `[100×5]`.

A trial where both calls did not reach the chain and overlap is reported but does not count, as on Nov 9.

## What changed in the runner (`tools/testnet/src/main.rs`)

1. **New funder with a random key.** `arena-race-funder-1111.testnet`, made by ONE call to the official
   testnet faucet helper (`helper.testnet.near.org`, the call `dev_create_account` makes), with a freshly
   generated random ed25519 key saved first to `~/.near-credentials/testnet/` (mode 600, never printed).
   Created on the first attempt: 10.00 NEAR (`testnet-2026-11-11-newfunder.log`). The old funder
   `dev-20261109195231-98743803426969.testnet` (key derived from its own id) was swept into it: 1.05 NEAR,
   tx `Hu1z953g7iFq4LmLHXUVC5exq8p2WWv9AqxyyaVeB8Er` (`testnet-2026-11-11-consolidate.log`). The old account
   is not deleted (it keeps 0.052 NEAR and is the parent of the Nov 9 trial accounts and the receipts
   contract).
2. **Funder key from the credentials file**, not `SecretKey::from_seed`. `from_seed` remains only in
   `consolidate`, to empty old dev accounts.
3. **Delete after each trial.** All five trial accounts (token, guard, sam, owner, agent) are deleted with
   the funder as beneficiary, AFTER the payouts, invoice record and nonces are read. The **last trial of
   each mode is kept alive** (agent and owner swept down to 0.05 NEAR + storage), so the live contracts can
   be opened. Every transaction stays in chain history either way.
4. **Smaller up-front funding:** agent 2.3 NEAR (was 5; 2.3 worked in Nov 9 run 9), token and guard 1.95 each
   (was 2.0; the code alone takes ~1.88). Owner 0.25, sam 0.05 unchanged.
5. **Stop rule:** before each trial the runner reads the funder balance and does not start a trial it cannot
   finish (needs up-front + 0.1 NEAR). Funder balance before and after each trial is recorded.

## Cost estimate (written before the run)

| Item | NEAR |
|---|---|
| Funder balance at start | **11.046** |
| One trial, handed out up front: owner 0.25 + agent 2.3 + sam 0.05 + token 1.95 + guard 1.95 | 6.50 |
| Burned per trial in fees (≈30 txs; gas price 0.0001 NEAR per TGas, read from RPC; only used gas is burned) | ≈0.02–0.05 |
| A deleted trial costs | ≈0.02–0.05 (everything else comes back) |
| A kept trial stays locked: token 1.95 + guard 1.95 + sam 0.05 + owner ≈0.05 + agent ≈0.05 | ≈4.05 |
| **Peak need**: kept `vulnerable_fixture` trial (4.05) + one `fixed` trial in flight (6.50) + 9 trials of fees (≤0.45) + 0.1 margin | **≈11.1 worst case, ≈10.8 expected** |
| Funder at end (expected) | ≈2.7 |

The worst case is about 0.05 NEAR over the balance, the expected case about 0.25 under. It runs because the
stop rule makes the overrun safe: if fees are higher than expected, the runner stops before a trial
instead of stranding NEAR in a half-built one, and the report will say how many trials ran. The fees are
measured after trial 1; if they are above 0.05 per trial the run is stopped and reported.

The receipts contract pays its own gas: it holds 2.695 NEAR, of which 1.953 is locked by storage, so
≈0.74 is free. Publishing 8 receipts needs ≈0.1 (storage + gas). No top-up expected.

---

## Amendment after trial 1 (written 2026-11-10 ~17:45 WAT, before resuming)

**What happened.** Run 1 trial `r11vf0` (vulnerable_fixture) finished: receiver +200, both checks in block
277088399, both callbacks in 277088401, as expected. Right after it the runner printed the funder at
**8.71 NEAR**, which looked like 2.3 NEAR lost on a trial that was supposed to return everything. I stopped
the run by hand (it was creating trial `r11vf1`). That reading was wrong: it was taken before the deleted
accounts' NEAR had arrived. The five delete transactions, read back from archival RPC, returned 6.4934 of
the 6.50 NEAR handed out (agent 2.2985, token 1.9508, guard 1.9483, owner 0.2460, sam 0.0497).

**Measured cost.** Creating one trial account costs the funder **0.0071 NEAR** (nearblocks, tx
`4njTHje8…`), not the ≈0.0004 I assumed. So a deleted trial costs ≈0.043 NEAR (5 × 0.0071 + 0.0066 spent
by the trial's own accounts). That is under the 0.05 stop line written above, so the run continues.
Also lost per deleted account: a ≈0.00023 NEAR gas refund that arrives after the account is gone.

**Clean-up.** The four half-built `r11vf1` accounts were deleted back into the funder
(`testnet-2026-11-11-reclaim-vf1.log`; the guard account was never created). Funder now **10.974 NEAR**.

**Runner changes before resuming.** (1) It waits 10 s before reading the funder after a trial, and re-reads
up to 3 times before the stop rule fires. (2) Stop line: up-front + 0.04 NEAR (covers the five creations)
instead of + 0.1.

**New cost estimate.** 9 trials left (vulnerable_fixture 4, fixed 5). Before the last fixed trial the
funder should hold 10.974 − 8 × 0.043 − 4.054 (kept vulnerable trial) ≈ **6.58**; that trial needs 6.54.
About 0.04 NEAR to spare. If it is short, the stop rule fires and the report says so.

**How it resumes (no result is re-run or dropped).** Trial `r11vf0` counts (it is in
`testnet-2026-11-11-run1-raw.json`). Run 2: `vulnerable_fixture` × 4, tag `r11b`, last one kept. Run 3:
`fixed` × 5, tag `r11c`, last one kept. Expected results unchanged: 200 × 5 and 100 × 5.
