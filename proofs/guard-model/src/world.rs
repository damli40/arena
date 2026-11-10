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
