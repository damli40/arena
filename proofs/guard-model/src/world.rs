//! The NEAR scheduler around the model, written once and driven two ways:
//! by Kani (`proofs.rs`, choices = `kani::any()`), and by `bin/playback.rs`, which
//! replays a Kani counterexample's concrete choices and prints a readable trace.
//!
//! Kani checks sequential code; it does not model concurrency. The "every order NEAR
//! could run things in" part is this loop: at each step it picks which waiting item
//! runs next. Each `pay` slot moves through
//!   PayWaiting -> TransferWaiting -> CallbackWaiting(outcome) -> Done
//! (or PayWaiting -> Done if the guard refuses it). A callback can only run after its
//! transfer, because it only becomes CallbackWaiting then.
//!
//! Every assume:
//!   A1 `assume(k < N)`: the picked slot index is in range.
//!   A2 `assume(phase[k] != Done)`: only a waiting item can be picked.
//! Neither restricts which orders or outcomes are explored.

use crate::*;

/// N (the number of pay calls) is a const parameter of `world`; N = 3 is the
/// pre-registered bound, N = 4 is run as an extra.
pub const AMOUNTS: [u128; 2] = [100, 50];
pub const NAMES: [&str; 2] = ["inv-a", "inv-b"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    PayWaiting,
    TransferWaiting,
    CallbackWaiting(bool),
    Done,
}

/// Reachability targets (Kani `cover!`), listed so the Kani side can use literal messages.
#[derive(Clone, Copy, Debug)]
pub enum Cover {
    RaceTwoInFlight,
    DoublePay,
    PaidOnce,
    RefusedInFlight,
    RetriedAfterFailure,
    // world_full only (2026-11-11)
    CallbackDied,
    H1Reading,
    ReconcileSettledPaid,
    ResolvedFailed,
    ResolvedPaid,
    OutsideTransferThenReconcile,
}

/// The checks (an enum, not strings: Kani needs literal messages, and comparing
/// strings inside the harness would add loops to the bound).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Amount,
    P1,
    Steps,
    P2Approved,
    P2Payable,
    P2Paid,
}

impl Check {
    pub fn msg(self) -> &'static str {
        match self {
            Check::Amount => "receipt amount is the invoice amount",
            Check::P1 => "P1: tokens sent for an invoice never exceed its amount",
            Check::Steps => "every schedule ends within 3N steps",
            Check::P2Approved => "P2: an invoice with nothing sent is Approved",
            Check::P2Payable => "P2: an invoice with nothing sent is payable again",
            Check::P2Paid => "P2 corollary: an invoice with tokens sent is Paid",
        }
    }
}

pub trait Oracle {
    fn any_bool(&mut self) -> bool;
    fn any_usize(&mut self) -> usize;
    fn assume(&mut self, c: bool);
    fn cover(&mut self, c: bool, which: Cover);
    fn check(&mut self, c: bool, what: Check);
    fn note(&mut self, _line: impl FnOnce() -> String) {}
}

pub fn world<O: Oracle, const N: usize>(o: &mut O, mode: Mode, mutant: bool) {
    // Each slot needs at most 3 steps (pay, transfer, callback).
    let max_steps = 3 * N;
    let mut m: Model<2> = Model::new(mode, AMOUNTS, mutant);
    let mut target = [0usize; N];
    for t in target.iter_mut() {
        *t = if o.any_bool() { 1 } else { 0 }; // each pay names either invoice
    }
    o.note(|| format!("the agent submits {N} pays, for {:?}", target.map(|i| NAMES[i])));
    let mut phase = [Phase::PayWaiting; N];
    let mut sent = [0u128; 2];
    let mut refused_in_flight = false;
    let mut retried_after_failure = false;
    let mut failed_once = [false; 2];

    let mut steps = 0usize;
    while phase.iter().any(|p| *p != Phase::Done) {
        steps += 1;
        let k: usize = o.any_usize();
        o.assume(k < N); // A1
        o.assume(phase[k] != Phase::Done); // A2
        let i = target[k];
        match phase[k] {
            Phase::PayWaiting => {
                let before = m.invoices[i].status;
                match m.pay(i, steps as u64) {
                    Ok(amount) => {
                        o.check(amount == AMOUNTS[i], Check::Amount);
                        if failed_once[i] && before == Status::Approved {
                            retried_after_failure = true;
                        }
                        o.note(|| format!("step {steps}: pay #{} ({}) checks status {before:?} -> accepted, transfer scheduled", k + 1, NAMES[i]));
                        phase[k] = Phase::TransferWaiting;
                    }
                    Err(r) => {
                        if r == Refusal::InFlight {
                            refused_in_flight = true;
                        }
                        o.note(|| format!("step {steps}: pay #{} ({}) checks status {before:?} -> refused ({r:?})", k + 1, NAMES[i]));
                        phase[k] = Phase::Done;
                    }
                }
            }
            Phase::TransferWaiting => {
                let ok = o.any_bool(); // the token transfer succeeds or fails
                if ok {
                    sent[i] += AMOUNTS[i];
                } else {
                    failed_once[i] = true;
                }
                o.note(|| format!("step {steps}: transfer for pay #{} ({}) {} (total sent for {}: {})", k + 1, NAMES[i], if ok { "succeeds" } else { "fails" }, NAMES[i], sent[i]));
                phase[k] = Phase::CallbackWaiting(ok);
            }
            Phase::CallbackWaiting(ok) => {
                m.on_transfer(i, ok);
                o.note(|| format!("step {steps}: on_transfer for pay #{} ({}) sees {} -> status {:?}", k + 1, NAMES[i], if ok { "success" } else { "failure" }, m.invoices[i].status));
                phase[k] = Phase::Done;
            }
            Phase::Done => {}
        }
        let in_flight_a = (0..N)
            .filter(|&s| target[s] == 0 && matches!(phase[s], Phase::TransferWaiting | Phase::CallbackWaiting(_)))
            .count();
        // Reachability before the assert: a failing assert stops that path.
        o.cover(in_flight_a >= 2, Cover::RaceTwoInFlight);
        o.cover(sent[0] == 2 * AMOUNTS[0], Cover::DoublePay);
        // P1, at every step.
        o.check(sent[0] <= AMOUNTS[0] && sent[1] <= AMOUNTS[1], Check::P1);
    }
    o.check(steps <= max_steps, Check::Steps);

    // P2, once nothing is waiting.
    for i in 0..2 {
        if sent[i] == 0 {
            o.check(m.invoices[i].status == Status::Approved, Check::P2Approved);
            let mut probe = m;
            o.check(probe.pay(i, 0).is_ok(), Check::P2Payable);
        } else {
            o.check(m.invoices[i].status == Status::Paid, Check::P2Paid);
        }
    }
    o.cover(sent[0] == AMOUNTS[0], Cover::PaidOnce);
    o.cover(refused_in_flight, Cover::RefusedInFlight);
    o.cover(retried_after_failure, Cover::RetriedAfterFailure);
}

// ---------------------------------------------------------------------------------------
// world_full (added 2026-11-11, evidence/fix-plan-2026-11-11.md): the same scheduler, plus
// the paths Proof 1 left out. Besides N `pay` calls it has, each at most once, at any
// moment the scheduler picks:
//   - a callback that DIES (out of gas / the fault build): its writes are rolled back, so it
//     is simply dropped;
//   - the owner's `reconcile(i)` (for either invoice, waiting the 100 blocks or not), which
//     becomes a balance read and then `on_reconcile` with the balance the token held at the
//     moment of the read;
//   - the owner's `resolve_stuck(i, sent)` (either invoice, either answer, waiting or not);
//   - an OUTSIDE transfer: anyone sends 100 tokens to the guard (review H1).
// The guard's token balance starts at FUND and the ledger is synced to it (sync_ledger).
// A transfer fails if the guard holds less than the amount (the token refuses).
// ---------------------------------------------------------------------------------------

pub const FUND: u128 = 1000;
pub const DONATION: u128 = 100;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Rec {
    Waiting,
    ReadWaiting(usize, u64),
    CallbackWaiting(usize, u64, u128),
    Done,
}

pub fn world_full<O: Oracle, const N: usize>(o: &mut O, mode: Mode, reopen_mutant: bool) {
    // N slots x 3 steps, + reconcile 3, + resolve 1, + outside transfer 1.
    let max_steps = 3 * N + 5;
    let mut m: Model<2> = Model::new(mode, AMOUNTS, false);
    m.mutant_reopen_on_balance = reopen_mutant;
    if mode == Mode::Fixed {
        // the owner funded the guard and called sync_ledger (lines 358-387)
        let e = m.sync_ledger().ok().unwrap_or(0);
        let _ = m.on_sync_ledger(e, Some(FUND));
    }
    let mut guard_balance = FUND;
    let mut target = [0usize; N];
    for t in target.iter_mut() {
        *t = if o.any_bool() { 1 } else { 0 };
    }
    o.note(|| format!("the agent submits {N} pays, for {:?}", target.map(|i| NAMES[i])));
    let mut phase = [Phase::PayWaiting; N];
    let mut rec = Rec::Waiting;
    let mut resolve_done = false;
    let mut outside_done = false;
    let mut deaths_left = 1u8;
    let mut sent = [0u128; 2];

    let mut steps = 0usize;
    // items: 0..N pay slots, N reconcile, N+1 resolve_stuck, N+2 outside transfer
    while phase.iter().any(|p| *p != Phase::Done) || rec != Rec::Done || !resolve_done || !outside_done {
        steps += 1;
        let k: usize = o.any_usize();
        o.assume(k < N + 3); // A1
        let block = steps as u64;
        if k < N {
            o.assume(phase[k] != Phase::Done); // A2
            let i = target[k];
            match phase[k] {
                Phase::PayWaiting => {
                    let before = m.invoices[i].status;
                    match m.pay(i, block) {
                        Ok(amount) => {
                            o.check(amount == AMOUNTS[i], Check::Amount);
                            o.note(|| format!("step {steps}: pay #{} ({}) checks {before:?} -> accepted", k + 1, NAMES[i]));
                            phase[k] = Phase::TransferWaiting;
                        }
                        Err(r) => {
                            o.note(|| format!("step {steps}: pay #{} ({}) checks {before:?} -> refused ({r:?})", k + 1, NAMES[i]));
                            phase[k] = Phase::Done;
                        }
                    }
                }
                Phase::TransferWaiting => {
                    let ok = o.any_bool() && guard_balance >= AMOUNTS[i];
                    if ok {
                        sent[i] += AMOUNTS[i];
                        guard_balance -= AMOUNTS[i];
                    }
                    o.note(|| format!("step {steps}: transfer for pay #{} {} (sent {}: {})", k + 1, if ok { "succeeds" } else { "fails" }, NAMES[i], sent[i]));
                    phase[k] = Phase::CallbackWaiting(ok);
                }
                Phase::CallbackWaiting(ok) => {
                    let dies = deaths_left > 0 && o.any_bool();
                    if dies {
                        deaths_left -= 1;
                        o.note(|| format!("step {steps}: on_transfer for pay #{} DIES (rolled back)", k + 1));
                    } else {
                        m.on_transfer(i, ok);
                        o.note(|| format!("step {steps}: on_transfer for pay #{} sees {} -> {:?}", k + 1, if ok { "success" } else { "failure" }, m.invoices[i].status));
                    }
                    phase[k] = Phase::Done;
                }
                Phase::Done => {}
            }
        } else if k == N {
            o.assume(rec != Rec::Done); // A2
            match rec {
                Rec::Waiting => {
                    let i = if o.any_bool() { 1 } else { 0 };
                    let rb = if o.any_bool() { block + RECONCILE_MIN_BLOCKS } else { block };
                    rec = match m.reconcile(i, rb) {
                        Ok(e) => {
                            o.note(|| format!("step {steps}: owner reconcile({}) accepted, balance read scheduled", NAMES[i]));
                            Rec::ReadWaiting(i, e)
                        }
                        Err(r) => {
                            o.note(|| format!("step {steps}: owner reconcile({}) refused ({r:?})", NAMES[i]));
                            Rec::Done
                        }
                    };
                }
                Rec::ReadWaiting(i, e) => {
                    o.cover(guard_balance == m.expected_balance.unwrap_or(u128::MAX) && sent[i] == AMOUNTS[i] && m.invoices[i].status == Status::Pending, Cover::H1Reading);
                    o.cover(outside_done && sent[i] == AMOUNTS[i], Cover::OutsideTransferThenReconcile);
                    o.note(|| format!("step {steps}: token reports guard balance {guard_balance}"));
                    rec = Rec::CallbackWaiting(i, e, guard_balance);
                }
                Rec::CallbackWaiting(i, e, v) => {
                    let r = m.on_reconcile(i, e, Some(v));
                    o.cover(r == Ok(Status::Paid), Cover::ReconcileSettledPaid);
                    o.note(|| format!("step {steps}: on_reconcile({}) with balance {v} -> {r:?}", NAMES[i]));
                    rec = Rec::Done;
                }
                Rec::Done => {}
            }
        } else if k == N + 1 {
            o.assume(!resolve_done); // A2
            let i = if o.any_bool() { 1 } else { 0 };
            let said_sent = o.any_bool();
            let rb = if o.any_bool() { block + RECONCILE_MIN_BLOCKS } else { block };
            let r = m.resolve_stuck(i, said_sent, rb);
            o.cover(r == Ok(Status::Failed), Cover::ResolvedFailed);
            o.cover(r == Ok(Status::Paid), Cover::ResolvedPaid);
            o.note(|| format!("step {steps}: owner resolve_stuck({}, sent={said_sent}) -> {r:?}", NAMES[i]));
            resolve_done = true;
        } else {
            o.assume(!outside_done); // A2
            guard_balance += DONATION;
            o.note(|| format!("step {steps}: someone sends {DONATION} tokens to the guard (balance {guard_balance})"));
            outside_done = true;
        }
        o.cover(deaths_left == 0, Cover::CallbackDied);
        o.cover(sent[0] == 2 * AMOUNTS[0], Cover::DoublePay);
        o.check(sent[0] <= AMOUNTS[0] && sent[1] <= AMOUNTS[1], Check::P1);
    }
    o.check(steps <= max_steps, Check::Steps);
}
