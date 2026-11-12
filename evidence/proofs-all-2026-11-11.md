# Proofs for every guard result that is a claim about code (2026-11-11 to 12)

Branch `proofs-all`. Plain words, then numbers. Where to look: the table right below is
the whole result; each section after it gives the command, the line it prints, and its limits.

| # | What | Result | Bound | Must-fail check |
|---|---|---|---|---|
| 1 | The proved guard source builds the wasm that ran on testnet | **matches**: `0382023b…`, 187,013 bytes; both kept testnet accounts serve it | exact (a byte-for-byte rebuild) | deleting one line gives `02a7515d…`, a different hash |
| 2 | Direct-pay rules (cap, payee list, approval threshold, refunds) never pay beyond their own policy | **hold** for the design where a refund only counts on its own day, for every policy, amount and order of up to 8 steps; the design where a refund comes off today's counter breaks the daily cap across a midnight | up to 8 steps, every policy and amount | 6 planted design flaws, each found |
| 3 | Five reusable money properties (`proofs/properties/`) | each catches its planted flaw in the template; one of them, no-double-pay, was applied to Arena's own guard and **holds** there (real source). The other four were not applied to Arena's guard | up to 3 pay calls (real source) | template: 5 of 5 flaws caught; Arena's guard: the existing one-line mutant |
| 4 | Four other teams' guards | 38 claims: 34 hold, 3 hold for the contract's part, **1 counterexample** (one of the four guards, daily cap across midnight) | 2 to 5 payment requests, owner actions, one midnight | 64 of 64 planted flaws caught |
| 5 | Regressions | `proofs/run.sh` 33 passed, 0 failed; `tla/run.sh` 25 of 25 as planned | as before | as before |

## 1. Reproducible build

See `repro-build-2026-11-11.md`. `proofs/run.sh repro` needs no network only once the Rust 1.86.0 toolchain and the crates are
already cached; on a clean machine both download the initial time. It compares the build with a hash
written into `proofs/repro/build.sh`, not with the chain. The comparison with what testnet serves
is `proofs/repro/build.sh --onchain` (read-only RPC, EVALUATE entry 23b).

## 2. Direct-pay rules (z3)

`proofs/z3/direct_pay_proof.py`, run by `proofs/run.sh proof3`. Log:
`proofs-all-2026-11-11/z3-direct-pay-k8.log` (every query, with each counterexample as steps).

**What it is.** A model of the rules a direct-pay guard enforces (the agent names the receiver and
the amount): refuse unless the caller is the agent, the receiver is listed, the amount is at most
the per-payment cap and today's total stays within the daily cap; above the approval threshold,
hold for the owner; charge today's total before the transfer and give it back if the transfer
fails; reset at UTC midnight. z3 chooses the policy (any caps, any threshold, any payee list of 3),
every amount, and the order of up to 8 steps (requests by the agent or anyone else, callbacks that
succeed or fail, owner approvals and rejections, midnights). "Holds" means z3 proved no such run
breaks the property.

**Lines you should see** (54 queries, 151 s on a machine shared with other jobs):

```
RESULT hold-at-request/refund-same-day  daily                holds     K=8 (...) as expected
RESULT hold-at-approve/refund-today     daily                VIOLATED  K=8 (...) as expected
z3 5.3.3, 54 queries, 151 s, unexpected: 0
```

| Design | agent only | payee list | hold above threshold | per-payment cap | daily cap | daily cap incl. approved |
|---|---|---|---|---|---|---|
| `hold-at-request/refund-same-day` (held payments count today, expire at midnight; refund only on the same day) | holds | holds | holds | holds | holds | holds |
| `hold-at-approve/refund-today` (held payments count when approved; refund from today's counter) | holds | holds | holds | holds | **broken** | broken (not claimed) |
| `hold-at-approve/refund-same-day` (the same, with the refund limited to the same day) | holds | holds | holds | holds | holds | broken (not claimed) |

The design names in the log and the JSON were renamed after this run so that each says what the
design does; the script prints the new names. No result, count or timing changed.

**The refund-from-today counterexample, in words** (z3's, steps 1-8): the agent pays the whole daily cap
on day 0; the transfer is still in flight at midnight; on day 1 the agent pays 1, then the day-0
transfer fails and its refund is taken off **day 1's** counter; now the agent can pay the whole
cap again on day 1. Day 1 delivers cap + 1. Section 4 finds the same flaw in the real source of one of the four
other teams' guards.

**Planted design flaws** (each must break the named property, and nothing else):
charge only after the transfer succeeds (daily), cap check without this payment's amount (daily),
no hold above the threshold (hold), no payee check (payee), no per-payment cap (per-payment cap),
anyone may request (agent only). 6 of 6 found.

**Limits.** A model of the rules, not any contract's code; the tie to code is section 4. Fixed
payee list during the run, no pause, one agent, no vault-balance limit, unbounded integer amounts.
At 6 steps the refund-from-today daily breach is not reachable (it needs 7), so the bound matters; we run 8.

## 3. The property library

`proofs/properties/README.md`. Five properties, 116 lines in all; each 8 to 15 lines. Harnesses:
the template 123 lines, Arena's guard 97 lines (reusing the existing 647-line world).

- `proofs/properties/run.sh`: `properties: 7 passed, 0 failed` (unit test + template with no flaw
  and with each of 5 flaws), 39 s.
- Arena's guard, real source, `fixed` mode, every order of 3 pay calls on 2 invoices:
  `PROPERTIES guard=arena build=real mode=fixed pays=3 world=base states=3318 ... broken=[]`
  (`proofs-all-2026-11-11/properties-arena-real-n3.log`, 243 s). Must-fail: the existing one-line mutant (`proofs/guard-real-mutant`) gives
  `no-double-pay BROKEN: id inv-a delivered 2 times, 200 in total` (8,930 states, 509 s).

## 4. Other teams' guards (counts only)

Each other team's guard was checked the same way as section 3, on that team's real
source (unchanged for A, B and C; one call-site edit for G, see below), privately: the source, harnesses and logs stay outside this repo so the teams stay
anonymous. For A, B and C, a fresh build of the source at the recorded commit gave exactly the
sha256 in `targets/entrant-*/FROZEN.txt` (rebuilt Nov 11). Each claim about money from the
guard's own claims file got its own check, and its own planted one-line flaw that the check had
to catch. A claim counts only if its flaw was caught.

Results for the four guards together. We do not say which guard had the counterexample.

| Claims checked | Hold in full | Hold for the contract's own part | Counterexamples | Bounds (every case up to) | Planted flaws caught |
|---|---|---|---|---|---|
| 38 | 34 | 3 | **1** | 2 to 5 payment requests, one UTC midnight, and up to 2 owner actions (per guard, the bound is set by what finished in our time) | 64 of 64 |

- **The counterexample.** In one of the four guards, a refund that lands after UTC midnight is
  taken off the new day's total, so that day can pay above the daily cap (5 against a cap of 4 in
  the run). It is the same design flaw section 2 finds in the model.
- **The 3 partial claims.** Three of the four guards claim that owner settings need a deposit only
  a full-access key can attach. The guard's own half of each holds; the key half is a NEAR rule,
  not modelled.
- **Guard G's source build: not byte-reproduced** on this machine. The team's pinned SDK version
  was not in the local package cache, and we did not fetch it, so the check ran their contract
  logic on a newer SDK with one call-site edit for an API change (the only change to their
  source). The resulting wasm has the same functions and error codes as the deployed build, but it
  is not the same bytes, so its claims are proved on that rebuild, not on the deployed code. One
  network call did happen during this work: rustup downloaded a Rust toolchain once, the initial
  time it was needed.

What the bounded checks do not cover, for all four:
- The contract methods are called as Rust functions, so the wasm wrapper's own checks (`#[private]`,
  `#[payable]`, argument parsing) are not exercised; we confirmed by reading the source that the
  callbacks are marked private.
- Out-of-gas callbacks, more than one midnight, limits on list sizes, and owner settings not listed
  per guard are not modelled.
- The library's `payee-list-only` uses the list at setup; removing a payee during a run is checked
  by each guard's own claim check, not by the library.

**Our own mistakes on the way, kept here.** In one guard's checker, the initial version of the reserve
check flagged audit-log storage using up the 0.5 NEAR reserve after the owner withdrew everything.
That is what the reserve is for, so we changed the check to "no payment takes the balance below
storage + reserve" and record the storage case as an observation. One guard's mutant script initially
split its fields on ':', which some claim names also contain, so two mutants
ran in the wrong world at the start; we fixed the separator and re-ran them. For Guard G, two runs
overlapped once and shared a build folder, which printed a false violation; that run was
discarded, and the script now takes a lock. For Guard A, one planted daily-cap flaw went
uncaught because a second, accidental check in the guard (an overflow-checked subtraction)
still refused the payment; that flaw was replaced by one the guard does not mask. Guard G's
helper downloaded the pinned Rust toolchain once through rustup (a network call to the Rust
project's servers, not to the team).

## 5. What is proved, what is measured

- **Proved within a bound** (every case up to the bound was checked): the double-pay race on
  Arena's guard (real source, 4 pay calls; model, any number), near-tla (3 pay calls), vault-a's
  policy (z3, 10 requests), direct-pay rules (z3, 8 steps, every policy), the library properties,
  and the other teams' money claims (bounds in section 4).
- **Exact**: the source-to-wasm link for Arena's guard (section 1).
- **Measured, not proved**: how an AI model behaves when an email tries to fool it (a model is not
  code we can enumerate; we report trials), and what happened on testnet (an observation of one
  chain at one time).

## 6. Fresh-export check

Commit 06443f8 was exported with `git archive` into an empty folder. The only addition was a link to an existing Python environment with z3 5.3.3 installed. No private files. The network was not used, except for the RPC hash check, which `repro/build.sh` skips without `--onchain`. Each command, with its exit code and wall time:

| command | exit | time | last line printed |
|---|---|---|---|
| `proofs/properties/run.sh` | 0 | 33 s | `properties: 7 passed, 0 failed` |
| `proofs/repro/build.sh` (no git in the export) | 0 | 110 s | `REPRO MATCH: source at this commit builds the testnet wasm` (0382023b..., 187013 bytes) |
| `proofs/run.sh proof3` | 0 | 253 s | `proofs: 1 passed, 0 failed` (54 queries as planned) |
| `proofs/run.sh repro` | 0 | 146 s | `proofs: 2 passed, 0 failed` |
| `proofs/run.sh properties` | 0 | 2,233 s | `proofs: 3 passed, 0 failed` (real: states=3318, broken=[]; mutant: states=8930, broken=["no-double-pay"]) |

The properties mode is slow mostly because it compiles two builds while other jobs share the machine. The two checker runs themselves took 197 s and 494 s.
