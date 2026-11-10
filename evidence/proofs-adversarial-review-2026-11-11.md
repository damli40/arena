# Adversarial review of the proofs (Nov 11 2026)

> **Note added 2026-11-11 (after the fix).** H1 is fixed in `contracts/guard` (`reconcile` no longer reopens on an unchanged balance; owner-only `resolve_stuck`). Evidence: `verify-2026-11-11.md` (t11), `proofs-inductive-2026-11-11.md`. The scorer blind spots (M7, M8) are fixed: `mutation-table-2026-11-11.md`.

**What was attacked:** `evidence/proofs-2026-11-10.md` (Proof 1: Kani + exhaustive run of the real guard; Proof 2: z3 on vault-a's policy) and `evidence/tla-2026-11-10.md` (the near-tla model `tla/Guard.tla`). The job was to make them fail, or show they claim more than they prove.

**Read this first.**
1. **The TLA+ headline "`fixed` never pays twice, including with `reconcile`" is false once anyone else can send tokens to the guard.** I added one ordinary 100-token transfer into the guard from a third account. With the waiting rule on, one forced callback failure and 2 `pay` calls, TLC finds a double pay: the receiver gets 200 on the 100 invoice. This is a bug in the real `reconcile` (it reads "balance unchanged" as "the money did not leave"), not only a model gap. Finding H1.
2. **The TLA+ "fixed passes" also rests on an assumption the code does not enforce** (the transfer has settled before `reconcile` reads the balance). The evidence file says so in its findings, but its headline does not. Finding H2.
3. **Proof 1 survived.** The real guard source still holds at a larger bound (5 `pay` calls: 14,696 states, 0 violations, 0 model mismatches). Its problems are wording: the title and "what it decides" column claim more than the checked world contains (callbacks always finish, no `reconcile`).
4. **Proof 2's numbers survived.** 500 (one UTC day) and 550 (days roll) are the real maxima for this setup. Its problems are scope wording.

Everything I ran, with times, is under "What I ran" at the end. Nothing in the repo was changed except this file.

---

## Findings, ranked by severity

### H1. `reconcile` pays twice if anything else changes the guard's token balance. The TLA+ model hides it, because nobody but the guard can move tokens in it

- **What breaks.** NoOverpay, on the `fixed` guard, with the waiting rule ON.
- **Inputs that trigger it.** Invoice 100 to sam, ledger synced at 1000. `pay` #1 runs, its transfer succeeds (sam 100, guard 900), its callback dies (out of gas, or the fault build). The invoice is stuck `Pending`. Then **anyone sends 100 tokens to the guard** (the owner topping it up, or a gift). The guard now holds 1000 again. The owner calls `reconcile`. The balance equals the ledger, so `on_reconcile` decides "the money did not leave" and sets `Approved`. `pay` #2 is accepted and its transfer succeeds: **sam 200**.
- **Shown in TLC.** A scratch copy of `tla/Guard.tla` with one added action (`DonTx`: a `donor` account holding 100 tokens calls the token's `ft_transfer(guard, 100)` once) and the donor added to `Holders`/`Accts`. Bounds: `fixed`, 1 invoice, 2 pays, 1 reconcile, `WaitRule = TRUE`, forced failures on `on_transfer` only, at most 1. Result: **NoOverpay violated**, 4,033 distinct states, under 1 s. Trace, from `tla/trace.py`:
  ```
   5. ran pay (tx 1)                  Pending   sam 0    ledger 1000
   6. ran ft_transfer (tx 1)          Pending   sam 100
   7. FORCED FAILURE of on_transfer   Pending   sam 100
   8. ran reconcile (tx 3)            Pending   sam 100
  10. ran ft_transfer (tx 4, donor -> guard, 100)
  11. ran ft_balance_of (tx 3)        reads 1000
  12. ran on_reconcile (tx 3)         Approved  sam 100
  13. ran pay (tx 2)                  Pending   sam 100
  14. ran ft_transfer (tx 2)          Pending   sam 200   -> NoOverpay violated
  ```
- **Where.**
  - Code: `contracts/guard/src/lib.rs:282-293`. The decision uses only "balance == ledger" or "balance == ledger − amount". Any untracked inflow shifts the balance.
  - Code: `contracts/guard/src/lib.rs:314`. `sync_ledger` is refused while any invoice is `Pending`, so the owner **cannot** re-sync after a top-up during the stuck window. Also, any top-up since the last sync counts, not only one made during the stuck window: an unsynced inflow equal to the stuck amount is enough.
  - Model: `tla/Guard.tla:50` (`Holders == {G} ∪ receivers`) and `:199` (`Next == PayTx ∨ RecTx ∨ RunReceipt ∨ Fault`). No transaction other than the guard's own ever moves tokens. The "two stories" logic is only sound in that closed world.
  - Not listed in the "Not modelled" list of `evidence/tla-2026-11-10.md:177-197`.
- **What it changes.** A headline: `evidence/tla-2026-11-10.md:7-8` ("`fixed` never does, within the bounds, including with forced failures and `reconcile`") and `:25-27`. It does **not** change any Proof 1 number, because Proof 1 leaves `reconcile` out (`evidence/proofs-2026-11-10.md:157`). It does contradict the plain reading of Proof 1's title (see M1).
- **How likely.** It needs a dead callback first (the guard's callback is written to have no panic path, so in practice: out of gas). Then the inflow must equal the stuck amount exactly. An owner topping up "the 100 that looks missing" is the natural way to hit that.
- **Not done.** I did not replay this on the Rust code (mocked chain) or on the sandbox. The trace is model-only, though it follows directly from lines 282-293.
- **Fix.**
  - *Code:* `reconcile` should not reopen an invoice from a balance reading alone. One option: the "money did not leave" arm moves the invoice to a terminal state, and the owner re-issues it under a new id after checking the explorer. Another: the owner settles it by stating the outcome, with the transfer receipt id as evidence. At minimum, write on `reconcile` that any token inflow since the last `sync_ledger` makes it unsafe.
  - *Model:* add a `DonTx`-style environment action (any token holder sends tokens to the guard) to the `fixed_*` checks. Keep this variant as a must-fail.
  - *Wording:* replace `tla-2026-11-10.md:7-8` with: "`fixed` never does within the bounds, **provided** every transfer settles before `reconcile` reads the balance (WaitRule) **and** nothing but the guard moves the guard's tokens. Drop either condition and `fixed` pays 200 on the 100 invoice (`mut_no_wait_rule`; review H1)."

### H2. The TLA+ `fixed` pass depends on an assumption the code does not enforce. The headline states the pass without it

- **What breaks.** The meaning of "`fixed` passes". `WaitRule` in the model is "the `pay` transaction that made the invoice Pending has fully settled" (`tla/Guard.tla:122`, `TxSettled`). The code only checks "100 blocks have passed" (`contracts/guard/src/lib.rs:246-253`). The guard's own comment calls this "a waiting rule, not a proof" (`lib.rs:40-43`). `mut_no_wait_rule` shows a double pay with **no** forced failure, only a slow transfer.
- **Inputs.** A transfer receipt delayed 100+ blocks (congestion) while the owner reconciles. Hypothesis only; not replayed (the evidence file says so at `:66-68`).
- **Where the wording drops it.** `evidence/tla-2026-11-10.md:7-8`, `:25-27` ("hold in every order of up to 3 `pay` calls, 1 `reconcile` and 2 failures"), and `tla/README.md:60-64` ("Every order of receipts TLC could build, within the bounds above, kept both invariants").
- **What it changes.** Wording only. The facts are already in Finding 1 of the same file. But a reader of the headline would not learn that the pass is conditional.
- **Fix (exact text).**
  - `tla-2026-11-10.md:25-27` → "What these numbers decide: **assuming** each transfer has settled before `reconcile` reads the balance, and nothing else moves the guard's tokens, the fixed guard's checks hold in every order of up to 3 `pay` calls, 1 `reconcile` and 1 failure on 2 invoices, or 2 failures on 1 invoice. The code enforces 100 blocks, not settlement; without the assumption the fixed guard pays twice (Finding 1)."
  - `tla/README.md:62-64` → "Every order of receipts TLC could build, within the bounds above, kept both invariants, **under the assumption WaitRule (a `reconcile` reads the balance only after the pay it is resolving has settled) and with no token transfers into the guard from anyone else**. It is a statement about this model…"
  - Also `:26`: "2 failures" was run only with 1 invoice. Say so in that sentence, not only at `:205-206`.

### M1. Proof 1's title and "what it decides" are broader than the world it checked

- **What it overstates.** Within the checked world, Proof 1 is sound (it survived a larger bound, below). But that world leaves out the guard's only recovery path. Callbacks always run to completion. `reconcile`, `sync_ledger`, the ledger and `approve_invoice` are absent (`proofs/guard-model/src/lib.rs:8-10`; `proofs/guard-real/src/lib.rs:304-331` always runs the callback). H1 and H2 are double pays of this same guard, on the paths that were left out.
- **Where.**
  - `evidence/proofs-2026-11-10.md:28`: "## Proof 1: one invoice is never paid twice"
  - `:9`: "Within this bound, the fix is correct in every order NEAR can run the steps"
  - `:11`: "The proof depends on that one line"
  - `proofs/README.md:7`: "Can one invoice be paid twice, in any order NEAR runs the steps?"
- **What it changes.** Wording only.
- **Fix (exact text).**
  - `:28` → "## Proof 1: the `pay` / callback race cannot pay one invoice twice (callbacks complete; `reconcile` not included)"
  - `:9`, third column → "Within this bound, `pay` and `on_transfer` never pay an invoice twice in any order of `pay`, transfer and callback receipts, as long as every callback runs. Not covered: a callback that dies, and the `reconcile` path after it, where the fixed guard can pay twice (TLA+ `mut_no_wait_rule`; review H1)."
  - `:11`, third column → "This result depends on that one line: remove it and the double pay is back."
  - `proofs/README.md:7` question → "Can the `pay`/callback race pay one invoice twice (callbacks complete, no `reconcile`), in any order NEAR runs those receipts, up to 4 `pay` calls?"

### M2. Proof 2 assumes vault-a's own "one transfer in flight" lock. It does not prove it, and the trust list does not name it

- **What it assumes.** z3 treats "pay + callback" as one step, and an invoice that has been paid can never be paid again (`proofs/z3/policy_proof.py:95`, `Not(paid[i])`). The argument that merging the steps "loses no final outcomes" (`policy_proof.py:21-26`; `evidence/proofs-2026-11-10.md:110`) is made about the cap only. It also needs vault-a to refuse a second `pay` while one is in flight. Otherwise one invoice could be paid twice, and z3 could not see it. Proof 1 checks `contracts/guard`, not vault-a.
- **I checked vault-a by hand.** The lock is there: status is checked at `targets/vault-a/src/lib.rs:270-275`, `Pending` is written before scheduling at `:295-299`, and the callback ignores anything not `Pending` at `:341-356`. A unit test covers it (`no_pay_while_pending`, `:516-524`). Gas for the callback is checked before any write (`:256-260`). I found no way to pay one invoice twice. **So the 500 and 550 stand.**
- **Where the wording overreaches.** `evidence/proofs-2026-11-10.md:13`, third column: "Over-payment is ruled out by the narrow policy itself, whatever a fooled agent asks for." No bound, no setup scope. The trust list at `:151` says "vault-a really enforces its rules as written", which is close, but does not name the in-flight lock that the merge argument needs.
- **What it changes.** Wording only.
- **Fix (exact text).**
  - `:13`, third column → "For this setup's 7 invoices, with no owner action during the run, the narrow policy rules out over-payment whatever a fooled agent asks for (z3, up to 10 requests; the result needs vault-a's in-flight lock, which z3 assumes and does not check)."
  - Add to `:151`: "that vault-a refuses a second `pay` while one is in flight (`targets/vault-a/src/lib.rs:270-299`), which the one-step-per-payment encoding relies on".
  - Note at `:110`: the bound K = 10 is not what limits these results. Only 4 invoices are payable under the broad policy and 1 under the narrow one, and each pays at most once. So K ≥ 4 already covers every outcome. What really limits them is the **fixed setup** (7 invoices, no owner action during the run). Say that, so a reader does not think more requests could change the answer.

### M3. "Model and contract agree in every state" really means "in every state the search visited first"

- **What breaks.** The conformance claim, not P1. `proofs/guard-real/src/bin/exhaustive.rs:31-33` skips a state already seen **before** it checks that state's mismatches (`:35-40`). The state key (`proofs/guard-real/src/lib.rs:167-182`) holds real storage, waiting items, sent totals and the model. It leaves out the mismatch list and the block height. So suppose path B differs from the model at step k, but later reaches the same key as a clean path A seen earlier. B's mismatch is never counted.
- **Inputs.** Only a transient real-vs-model divergence that later re-converges. For example, a field the model gets wrong, which a later step overwrites to the same value on both sides. I did not find one in the current code. This is a hole in the checker, not a missed bug.
- **What it changes.** Wording of `evidence/proofs-2026-11-10.md:9` and `:26` ("agree in every state"). P1 and P2 in the real run are computed from the real receipts and real `get_invoice` (`lib.rs:304-308`, `exhaustive.rs:41-74`), so they do not depend on the model. The 4,555 / 0 numbers stand.
- **Fix.** In `exhaustive.rs`, check `w.mismatches` before the `seen.insert` early return, or put `!w.mismatches.is_empty()` into the key. Until then say "in every distinct state explored (first visit)".

### L1. A malformed receipt from the real `pay` is recorded as a refusal

- **What breaks.** `run_pay_unchecked` decodes the receipts inside `catch_unwind` (`proofs/guard-real/src/lib.rs:263-279`). The decoder's own panics count as "the guard refused" and roll back storage: "callback for another invoice", "unexpected receipt", "pay created no ft_transfer" (`lib.rs:349-371`). A `pay` that wrote `Pending` but scheduled the wrong callback would look like a clean refusal.
- **Why it is low.** The model would still say "accepted", so the lockstep reports a mismatch (`lib.rs:290-292`), and the filter check disagrees (`exhaustive.rs:84-91`). It is caught, just not under the right name.
- **Fix.** Decode receipts outside `catch_unwind`, or catch only the guard's own call and fail the run loudly on a decode error.

### L2. Doc drift in the proof files

- `evidence/proofs-2026-11-10.md:44`: "The same loop is used by the exhaustive run over the real contract (`proofs/guard-real/src/lib.rs`)". False. `guard-real` has its own scheduler (`World`, `lib.rs:70-333`) and imports only `Model` from `guard-model` (`lib.rs:27`). That is better (the two schedulers are independent), but the sentence is wrong. Replacement: "The exhaustive run over the real contract uses its own scheduler (`proofs/guard-real/src/lib.rs`, `World::step`), written separately, with the same rules."
- `proofs/guard-real/src/lib.rs:17-21` names `tests/exhaustive.rs` and `src/kani_harness.rs`. Neither exists. The driver is `src/bin/exhaustive.rs`, and the only Kani code is the `kani_probe` module (`:378-391`).
- `proofs/guard-model/src/lib.rs:5` names `proofs/guard-kani`. Does not exist; it is `proofs/guard-real`.
- Wording only.

### L3. TLA+ bounds hide two kinds of bug

- All invoices are 100 (`tla/Guard.tla:47`). A code bug that subtracted the **wrong invoice's** amount in `on_transfer` / `on_reconcile` would be invisible with equal amounts. Fix: `Amt == [i \in Inv |-> IF i = 1 THEN 100 ELSE 60]`.
- No witness shows the full "reconcile says Approved → re-pay → paid once" path completing. `Wit_reconcile_says_approved` (`:237-239`) only shows that branch about to run. Fix: add a ghost "reconciled to Approved" and a witness that sees Received = Amt after it.
- Shipped checks use `MaxRec = 1`. I ran `MaxRec = 2` (below): it passes. So this one is resolved for the closed-world model, but should be recorded.
- Wording/coverage only. No number changes.

### L4. The reserved receipt suite name `proof-no-double-pay` claims more than either proof shows

- `evidence/receipts-plan.md:61` and `evidence/receipts-testnet-2026-11-10.md:60`. Nothing is published yet. If a receipt goes out under this name, it signs a claim that H1/H2 contradict.
- Fix: rename to something like `proof-pay-callback-race-n4` before publishing.

### L5. Small things that did not change any number

- **Expiry.** z3 allows inv-expire only on day 0 (`policy_proof.py:96-97`). If setup ran in the last 20 s of a UTC day, the real contract would also accept it on day 1. No effect: 550 already pays every payable non-intended invoice once.
- **Days-roll failure release.** z3 always releases a failed reservation (`policy_proof.py:106`). vault-a releases only if the counter has not rolled (`targets/vault-a/src/lib.rs:366-368`). The real rule releases less, so z3 is generous to the attacker. Safe for an upper bound.
- **"Proof 1 P2 has no must-fail of its own."** Already disclosed at `proofs-2026-11-10.md:158`. The TLA+ suite has one (`mut_no_release_on_failure`), so the property can fire.

---

## Wording: every overstating sentence I found, with a replacement

| File:line | Says | Replace with |
|---|---|---|
| `evidence/tla-2026-11-10.md:7-8` | "`fixed` never does, within the bounds, including with forced failures and `reconcile`." | "`fixed` never does within the bounds, provided each transfer settles before `reconcile` reads the balance and nothing else moves the guard's tokens. Without either condition it pays 200 on 100 (`mut_no_wait_rule`; review H1)." |
| `evidence/tla-2026-11-10.md:25-27` | "hold in every order of up to 3 `pay` calls, 1 `reconcile` and 2 failures" | see H2 (adds the assumption, and "2 failures on 1 invoice only") |
| `evidence/tla-2026-11-10.md:30-31` | "So the pass is not coming from 'nothing interesting happens'." | "So the pass is not coming from 'nothing interesting happens' inside the model. The witnesses cannot show what the model leaves out (H1)." |
| `tla/README.md:62-64` | "Every order of receipts TLC could build, within the bounds above, kept both invariants." | see H2 |
| `evidence/proofs-2026-11-10.md:28` | "Proof 1: one invoice is never paid twice" | "Proof 1: the `pay` / callback race cannot pay one invoice twice (callbacks complete; `reconcile` not included)" |
| `evidence/proofs-2026-11-10.md:9` | "the fix is correct in every order NEAR can run the steps" | see M1 |
| `evidence/proofs-2026-11-10.md:9, :26` | "model and contract agree in every state" | "model and contract agree in every distinct state explored" (M3) |
| `evidence/proofs-2026-11-10.md:13` | "Over-payment is ruled out by the narrow policy itself, whatever a fooled agent asks for" | see M2 |
| `evidence/proofs-2026-11-10.md:44` | "The same loop is used by the exhaustive run" | see L2 |
| `proofs/README.md:7` | "Can one invoice be paid twice, in any order NEAR runs the steps?" | see M1 |
| `evidence/receipts-plan.md:61` | suite `proof-no-double-pay` | `proof-pay-callback-race-n4` (L4) |

Checked and fine: no file says "NEAR's own checker proves" or "proved the contract". `evidence/proofs-2026-11-10.md:18` already says "The Kani result is a proof about the model, not about the contract". `:155` states every bound. `tla-2026-11-10.md:172-175` says plainly that a pass is about the model. The top-level `README.md` and `site/` do not cite the proofs.

---

## The bound: is "up to 4 calls" reasonable?

**For the `pay` / callback race, yes, and a larger bound adds almost nothing.** In `fixed` mode, each invoice moves Approved → Pending → Paid (or back to Approved on failure). `Pending` refuses a new `pay`, and `Paid` refuses everything. So at most one transfer per invoice is ever in flight, whatever N is. A double pay needs 2 calls, and N = 3 adds the retry-after-failure case. That is an argument by hand, not a machine proof. The bounded runs agree with it, and so does the larger run I made:

| Check | Bound | Result | Distinct states | Time |
|---|---|---|---|---|
| Real guard, exhaustive (existing binary) | N = 4 (re-run) | P1, P2 hold, lockstep agrees | 4,555 | 22 s |
| Real guard, exhaustive (existing binary) | **N = 5** | **P1, P2 hold, lockstep agrees, filter agrees**, max sent [100, 50] | **14,696** | **163 s** |
| Kani on the model (scratch copy, extra harness `fixed_n5`, `unwind(16)`) | **N = 5** | **VERIFICATION SUCCESSFUL**, 3 of 5 covers satisfied (the same 3 as N = 4) | — | **355 s** (N = 4: 39 s) |
| TLA+, closed world | **1 invoice, 4 pays, 2 reconciles, 2 failures** | **pass** | **4,342,110** | **115 s** |
| TLA+, closed world | 2 invoices, 3 pays, 2 reconciles, 2 failures | **not finished**: stopped by my 560 s limit with no violation found so far (about 2 M states still queued) | 15.3 M at stop | > 560 s |
| TLA+, **one third-party transfer into the guard** (H1) | 1 invoice, 2 pays, 1 reconcile, 1 failure | **NoOverpay violated** | 4,033 | < 1 s |

**What a larger bound costs.** The real-source run grows about 3x in states and 7x in time per extra call (N = 4: 22 s, N = 5: 163 s). By that trend N = 6 is roughly 20 minutes. I did not run it.

**Where the bound is the wrong lever.** H1 and H2 do not need more calls. H1 needs one extra *kind* of action (a transfer into the guard). H2 needs a different *timing* assumption. Raising N, MaxRec or MaxFails in a closed-world model would never have found either. For this bug class, the bound to widen is **which actors and which delays exist**, not how many calls.

---

## Survived: claims I tried hard to break and could not

- **Proof 1, P1 and P2 on the real guard source**, for `pay` / transfer / callback with callbacks completing. It holds at N = 5 (above). P1 in the real run is computed from the real receipts' amounts and receivers (`proofs/guard-real/src/lib.rs:304-308`, `:357-361`), not from the model, so the two sides cannot agree just because they share a bug.
- **No vacuity from Kani assumes.** A1/A2 (`proofs/guard-model/src/world.rs:95-96`) only pick a valid, waiting slot. In `kani-fixed_n4.log`, 3 of 5 covers are SATISFIED (refused-in-flight, retried-after-failure, paid-once). The 2 UNSATISFIABLE ones are the double-pay covers, as planned. The unwinding assertion passes, and the too-small bound fails as it should.
- **Must-fails bite.** `vulnerable_fixture` reaches 300 on the 100 invoice. The mutant is exactly the guard minus line 186: `proofs/run.sh` diffs it, and I checked the diff logic.
- **The lockstep has teeth**, at least for a gross difference (the self-test with a flipped mutant flag disagrees).
- **Proof 2's 500 and 550.** Under the broad policy the payable invoices are sam 100, mo 50, ada 200 and ada 300 (inv-big 600 exceeds the cap; inv-cancel is cancelled; inv-removed's payee is gone). 550 = every non-intended payable invoice, paid once. 500 = the daily cap, filled by ada 300 + 200. Nothing pays an invoice twice in vault-a (M2), and nothing beats the cap within one UTC day. The cap reserves before the transfer (`targets/vault-a/src/lib.rs:285-291`) and releases only on the same day (`:366-368`). The encoding matches or over-approximates each rule: cap, reset at UTC midnight, expiry, payee generation, cancelled invoices, agent-only `pay` (`:252`). The narrow policy's 0 holds for any number of requests, not only up to 10. I re-ran z3: every result as planned.
- **TLA+ closed-world `fixed` pass at a larger bound** (4 pays, 2 reconciles, 2 failures). And `tla/run.sh` reproduced all 17 checks.

---

## What I ran

All runs on Nov 10-11, this Mac. Nothing in the repo was modified. The suites wrote their usual outputs to `tla/build/`.

- `tla/run.sh`: 17 of 17 as planned (same state counts as the evidence file).
- `proofs/.venv/bin/python -I proofs/z3/policy_proof.py`: ALL AS PLANNED.
- `proofs/guard-real/target/release/exhaustive fixed 4` and `fixed 5` (the existing binary, built 01:36 Nov 10).
- Scratch variants, outside the repo, in my session scratchpad: `tla_donate/` (H1), `tla_big/` (larger TLA+ bounds), `gm5n/` (Kani `fixed_n5`).

Not done: I did not replay H1 on the Rust mocked chain or the sandbox, did not run the full `proofs/run.sh` (its Kani part was re-checked from logs, not re-run), and did not run Kani at N = 3/4 again.
