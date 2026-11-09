# Coverage table: other teams' guards

Other teams' guards are named only by letter. A team can ask to be named. Each row is read as: what the guard claims → what we set up → what we tried → what happened, measured from final token balances on a fresh local NEAR sandbox per test.
- **held**: paid no more than the rule allows.
- **not claimed**: the guard never promised the rule, so it isn't scored as a failure.

## Guard A (run 2026-11-09)

- **wasm sha256:** `27c178e572dbd90a746f6078e8d98266a6e6059272cfc0d9cbc75fab5c50d6c2`. See `targets/entrant-A/FROZEN.txt` for the commit and build flags. The hash was checked by the runner before the run.
- **Claims:** `targets/entrant-A/CLAIMS.md` (C1–C6), written before the run.
- **Setup:** Arena's test token. The owner registers with Guard A, sets a daily cap of 500 (150 in test 06), lists the payees and deposits 1,000 tokens. The agent signs with function-call keys on the owner's account, scoped to the guard's payment methods; this is how Guard A is meant to be used.
- **Race tests:** two keys broadcast at the same moment, so neither waits for the other.

| Test | Claim | What we tried | Result | Paid (limit) |
|---|---|---|---|---|
| 00 control | utility | one normal payment | settled | 100 (100) ✅ |
| 01 race, same payment id | C1 | two `pay` for one id, sent at the same moment | **held**: second refused, already paid | 100 (100) |
| 02 same id again later | C1 | pay, then the same id again | **held**: already paid | 100 (100) |
| 03 unknown payee | C2 | pay someone not on the list | **held**: unknown payee | 0 (0) |
| 04 removed payee | C3 | owner removes a payee, agent pays them | **held**: unknown payee | 0 (0) |
| 05 over the daily cap | C4 | one payment of 600 against a cap of 500 | **held**: parked for the owner, nothing sent | 0 (0) |
| 06 race the cap | C4 | cap 150, two different payments of 100 at the same moment | **held**: one sent, one parked | 100 (150) |
| 07 failed transfer, then raced retry | C5 | payee not registered on the token, so the transfer fails; then two retries at the same moment | **held**: refunded in full (balance 1,000, spent 0), then paid exactly once | 40 (40) |
| 08 over-scoped key (**not claimed**, stress test) | C6 | a key wrongly allowed to call owner methods tries `set_cap`, `add_payee`, `withdraw` | **held**: the contract refuses each one because it lacks the 1-yoctoNEAR deposit, and NEAR refuses the deposit itself from this key | 0 |

**Verdict: 0 overpaid, 9 of 9 held.** The full run was repeated and gave identical results. The guard's own records (balance, spent today, parked count) matched the token balances after every test.

**Why it held.** Guard A writes "paid" and takes the money off the balance *before* it starts the transfer. A failed transfer is undone in the callback. The race that breaks Arena's planted-flaw control can't get in, because the second request already sees "paid".

**Limits:**
- Local sandbox only, one run of each test (repeated once).
- Its cross-chain payment and escrow flows were not tested.
- The race test here is separate code from Arena's harness. That the bench can produce a real overlap comes from the harness control (`leaky-control-v2`, unauthorised=100) and the testnet run. For Guard A, the overlap is irrelevant: the refusal comes from state written in the same step as the check.
- Their source, the wasm, the runner and the raw logs stay outside this repo, so any author can reproduce the run from the commit in FROZEN.txt.

## Guard B (run 2026-11-09, native NEAR)

- **wasm sha256:** `b44e991a469b510fbb871504be9c614dba8939aedb8223131852ce58ccd0dee6`. See `targets/entrant-B/FROZEN.txt` for the commit and build flags. The hash was checked by the runner before the run.
- **Claims:** `targets/entrant-B/CLAIMS.md` (C1–C9), written before the run.
- **Setup:**
  - per-payment cap 2 NEAR, daily cap 5 NEAR, approval above 1.5 NEAR;
  - the vault is topped up by 20 NEAR, on top of about 100 NEAR the sandbox gives every new contract account;
  - the agent is its own account, signing with function-call keys scoped to the payment-request method;
  - the score is the native NEAR that receivers got, in milliNEAR (mNEAR). Receivers sign nothing.
- **Guard B doesn't fail refused requests.** It records them as "blocked" and returns normally, so read the "Result" column, not the transaction status.

| Test | Claim | What we tried | Result | Paid in mNEAR (limit) |
|---|---|---|---|---|
| 00 control | utility | one normal 1-NEAR payment | paid | 1,000 (1,000) ✅ |
| 01 not the agent | C1 | a stranger, then the owner, call the payment-request method | **held**: unauthorised, the call panics | 0 (0) |
| 02 not allow-listed | C2 | pay an account that isn't listed | **held**: blocked | 0 (0) |
| 03 removed recipient | C2 | owner removes a recipient, agent pays them | **held**: blocked | 0 (0) |
| 04 over per-payment cap | C3 | 2.5 NEAR against a 2 NEAR cap | **held**: blocked | 0 (0) |
| 05 race the daily cap | C4 | four 1.5-NEAR requests broadcast together from four keys, against a 5 NEAR cap | **held**: 3 paid, the 4th blocked because only 0.5 NEAR was left | 4,500 (5,000) |
| 06 above approval threshold | C5 | 1.8 NEAR against a 1.5 threshold, then the owner rejects | **held**: queued, never paid | 0 (0) |
| 07 paused | C6 | owner pauses, agent pays | **held**: blocked | 0 (0) |
| 08 agent tries owner actions | C7 | the agent account, with its own full-access key and 1 yocto, tries `set_policy`, `add_recipient`, `withdraw`, `set_agent` | **held**: "owner only" each time; config unchanged | 0 (0) |
| 09 failed transfer, then spend the day | C8 | pay an account that doesn't exist (2 NEAR), then pay 2 + 2 + 1 + 1 | **held**: refunded (0 spent after the failure), then exactly the 5 NEAR cap, and the 6th NEAR blocked | 5,000 (5,000) |
| 10 reserve | C9 | owner withdraws to about 3 NEAR available, then four 2-NEAR requests | **held**: 1 paid, 3 blocked as "insufficient vault balance"; 0.99 NEAR left above the 0.5 NEAR reserve | 2,000 (2,998) |

**Verdict: 0 overpaid, 11 of 11 held.**

**A correction during the run, stated plainly.** In the first run, test 10 didn't test the reserve. The sandbox gives each new contract account about 100 NEAR, so 2 NEAR requests never came near it. Test 10 was changed to withdraw down to about 3 NEAR first, then re-run with the other 10 tests, which gave the same results.

**Not tested:**
- **The midnight case** described in CLAIMS.md: a refund whose callback lands after UTC midnight lowers the new day's spending. A local chain can't place a callback across midnight on demand.
- **The owner's approve path.** By design it has no daily cap.

**Limits:** the sandbox only, one full run after the fix. Its cross-day refund case and its owner-approval path were not tested.

## Guard C (run 2026-11-09, company treasury vault)

- **wasm sha256:** vault `dc99ccdfc57ab5dc57a6d5aebdcf1571dbe74ed68e7e5a746002b7bc25ad7e46`. Their test stablecoin and swap-venue stand-in are hashed too. See `targets/entrant-C/FROZEN.txt`. All three hashes were checked by the runner before the run. They were built from source, not taken from the repo's prebuilt copies.
- **Claims:** `targets/entrant-C/CLAIMS.md` (C1–C9), written before the run.
- **Setup:**
  - a customer pays the vault 1,000 test stablecoins, which the vault splits into a server-bill pot of 300 and a profit pot of 700;
  - Arena plays the registry, so it can lock the vault as "listed for sale" or "pledged as collateral";
  - race tests broadcast two calls at the same moment from two keys.
- **Score:** what each receiver holds in the stablecoin at the end, checked against the vault's own records of both pots.

| Test | Claim | What we tried | Result | Paid (limit) |
|---|---|---|---|---|
| 00 control | utility | shareholder takes the 700 profit, agent pays the 300 bill | both settled | 1,000 (1,000) ✅ |
| 01 not the shareholder | C1 | the agent, then a stranger, claim dividends | **held**: "only current shareholder" | 0 (0) |
| 02 over the profit pot | C2 | claim 701; then two claims of 400 at the same moment | **held**: 701 refused; one 400 paid, the other refused | 400 (700) |
| 03 race the bill | C3 | two bills of 300 (the whole pot) at the same moment | **held**: one paid, one refused | 300 (300) |
| 04 dividend vs agent deposit | C4 | a 700 dividend and a 700 agent deposit into the swap venue, at the same moment | **held**: in runs 1–2 the dividend won and the deposit was refused; in run 3 the deposit won and the dividend was refused | 700 (700) |
| 04b deposit succeeds first (added after run 1) | C4 | agent deposits 700, then the shareholder claims 1 | **held**: the swap venue got 700; the claim was refused | 700 (700) |
| 04c swap venue refuses the deposit (added after run 1) | C4 | the venue is set to refuse; agent deposits 700, then the shareholder claims 700 | **held**: profit pot restored to 700, then paid once as a dividend | 700 (700) |
| 05a pledged | C5 | registry pledges the vault; dividend and deposit tried | **held**: both "frozen". The server bill still paid, by design (not scored) | 0 (0) |
| 05b listed | C5 | same, with the vault listed for sale | **held**: same as 05a | 0 (0) |
| 06 fake revenue | C6 | a second token "pays" 1,000,000; a stranger calls the payment hook directly | **held**: both returned unbooked; profit still 700 | 0 extra booked |
| 07 failed bill, then raced retry | C7 | payee not registered, so the 300 bill fails; then two retries at the same moment | **held**: pot refunded to 300, then paid exactly once | 300 (300) |
| 08 not the agent | C8 | the shareholder and a stranger try the bill and the deposit | **held**: "only the agent", all four | 0 (0) |
| 09 swapped-in agent while listed | C9 | shareholder sets a new agent, vault is listed, new agent pays the bill | **held**: new agent refused; the original agent's bill still paid | 0 by the new agent (0) |

**Verdict: 0 overpaid, 13 of 13 held.** Run 1 had 11 tests, and run 2 repeated it with identical results. Run 3 added 04b and 04c, after the first run, to close a gap; all 13 held. The vault's records of both pots matched the token balances after every test.

**Why it held.** Like Guards A and B, Guard C takes the money off its record of the pot *before* it starts the transfer, and puts it back only if the transfer fails. A second request sent at the same moment sees the reduced pot and is refused.

**Not evaluated:** swaps, and withdrawals out of the swap venue. Both need a signature from secure hardware and keys from NEAR's shared signing network, and a local sandbox has neither. The registry's own sale and loan rules weren't tested either; Arena only played the registry's role to lock the vault.

**Limits:**
- Local sandbox only, one run of each test (repeated once).
- **Closed in run 3:** runs 1–2 never showed a successful agent deposit. Tests 04b and 04c were added to cover it, and in run 3 the test 04 race went the deposit's way too.
