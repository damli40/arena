//! HARNESS TEMPLATE. Copy this file, replace `Toy` with calls into your guard, keep the rest.
//!
//!   cargo run --release --example template -- [flaw]
//!
//! `Toy` is a tiny direct-pay guard (per-payment cap, daily budget, payee list, approval
//! threshold with owner approval, payment ids, transfers that can fail and refund). With no argument all five
//! properties hold. Each flaw argument plants one mistake, and its property must break:
//!   double-pay | any-payee | no-cap | no-hold | no-budget
//!
//! For a real NEAR guard, `apply` calls your contract on near-sdk's mocked chain and reads
//! the receipts it created (see proofs/guard-real/src/bin/properties.rs for Arena's guard).
use arena_properties::{explore, print, Payment, Policy, World};
use std::hash::{Hash, Hasher};

const CAP: u128 = 100; // per payment
const BUDGET: u128 = 150; // per day
const HOLD: u128 = 80; // above this, wait for the owner
const PAYEES: [&str; 2] = ["sam", "ada"];

// ---- 1. Your guard (here: a toy). Replace with calls into your contract. ----
#[derive(Clone, Hash)]
struct Toy {
    flaw: &'static str,
    spent_today: u128,
    day: u64,
    used_ids: Vec<u8>,
}
impl Toy {
    /// Sent(amount) if the guard sends money now, Held, or Refused.
    fn pay(&mut self, id: u8, to: &str, amount: u128) -> Out {
        if self.flaw != "double-pay" && self.used_ids.contains(&id) { return Out::Refused; }
        if self.flaw != "any-payee" && !PAYEES.contains(&to) { return Out::Refused; }
        if self.flaw != "no-cap" && amount > CAP { return Out::Refused; }
        self.used_ids.push(id);
        if self.flaw != "no-hold" && amount > HOLD { return Out::Held; } // waits for the owner
        if self.flaw != "no-budget" && self.spent_today + amount > BUDGET { self.used_ids.pop(); return Out::Refused; }
        self.spent_today += amount;
        Out::Sent(amount)
    }
    fn on_failed(&mut self, id: u8, amount: u128, day: u64) {
        self.used_ids.retain(|&x| x != id);
        if day == self.day { self.spent_today -= amount; }
    }
}

enum Out { Sent(u128), Held, Refused }

// ---- 2. The world: your guard plus the chain around it, and what may happen next. ----
#[derive(Clone, Hash)]
struct Flight { id: u8, to: &'static str, amount: u128, day: u64, ok: Option<bool>, approved: bool }
#[derive(Clone, Hash)]
struct Sim { guard: Toy, flights: Vec<Flight>, held: Vec<(u8, &'static str, u128)>, requests_left: u8, midnights_left: u8 }

#[derive(Debug)]
enum Step { Pay(u8, &'static str, u128), OwnerApproves(usize), Outcome(usize, bool), Midnight }

impl World for Sim {
    type Step = Step;
    fn steps(&self) -> Vec<Step> {
        let mut v = vec![];
        if self.requests_left > 0 {
            for id in 0..3 { for to in ["sam", "eve"] { for amt in [50, 70, 90, 120] { v.push(Step::Pay(id, to, amt)); } } }
        }
        for i in 0..self.held.len() { v.push(Step::OwnerApproves(i)); }
        for (i, f) in self.flights.iter().enumerate() {
            if f.ok.is_none() { v.push(Step::Outcome(i, true)); v.push(Step::Outcome(i, false)); }
        }
        if self.midnights_left > 0 { v.push(Step::Midnight); }
        v
    }
    fn apply(&mut self, s: &Step) -> bool {
        match *s {
            Step::Pay(id, to, amt) => {
                self.requests_left -= 1;
                match self.guard.pay(id, to, amt) {
                    Out::Sent(sent) => self.flights.push(Flight { id, to, amount: sent, day: self.guard.day, ok: None, approved: false }),
                    Out::Held => self.held.push((id, to, amt)),
                    Out::Refused => {}
                }
            }
            Step::OwnerApproves(i) => {
                let (id, to, amount) = self.held.remove(i); // the owner's decision: paid as asked
                self.flights.push(Flight { id, to, amount, day: self.guard.day, ok: None, approved: true });
            }
            Step::Outcome(i, ok) => {
                self.flights[i].ok = Some(ok);
                let f = self.flights[i].clone();
                if !ok && !f.approved { self.guard.on_failed(f.id, f.amount, f.day); }
            }
            Step::Midnight => { self.midnights_left -= 1; self.guard.day += 1; self.guard.spent_today = 0; }
        }
        true
    }
    fn key(&self) -> u128 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut h);
        h.finish() as u128
    }
    // ---- 3. The ledger: what actually moved, read from the chain, not from the guard. ----
    fn ledger(&self) -> Vec<Payment> {
        self.flights.iter().map(|f| Payment {
            id: Some(f.id.to_string()), by_agent: true, to: f.to.into(), amount: f.amount,
            window: f.day, owner_approved: f.approved, delivered: f.ok == Some(true),
        }).collect()
    }
}

// ---- 4. The policy your guard claims, and the properties to check. ----
fn main() {
    let flaw: &'static str = std::env::args().nth(1).map(|s| &*Box::leak(s.into_boxed_str())).unwrap_or("none");
    let policy = Policy {
        payees: Some(PAYEES.iter().map(|s| s.to_string()).collect()),
        per_payment_cap: Some(CAP),
        window_cap: Some(BUDGET),
        approval_threshold: Some(HOLD),
        invoices: None,
    };
    let props = ["no-double-pay", "payee-list-only", "never-beyond-cap", "approval-threshold", "window-budget"];
    let start = Sim { guard: Toy { flaw, spent_today: 0, day: 0, used_ids: vec![] }, flights: vec![], held: vec![], requests_left: 3, midnights_left: 1 };
    let t0 = std::time::Instant::now();
    let rep = explore(start, &policy, &props);
    print(&rep, &props, &format!("guard=template flaw={flaw} requests<=3 midnights<=1"), t0.elapsed().as_secs_f64());
}
