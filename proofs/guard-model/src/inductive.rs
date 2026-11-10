//! "Any number of calls": an inductive-step proof on the model (added 2026-11-11).
//!
//! In plain words. A bounded check tries every order of, say, 3 calls. This file instead
//! proves two facts that together cover EVERY length of run:
//!   1. the starting state satisfies an invariant (a rule about the state), and
//!   2. from ANY state that satisfies the invariant, ANY single action leads to a state
//!      that still satisfies it.
//! Then by induction every reachable state satisfies it, after 1 call or after a million.
//! The invariant includes "tokens sent for an invoice never exceed its amount", so that
//! holds for any number of calls.
//!
//! The state (`AState`): the model guard (`Model<K>`, the same code the bounded lockstep
//! check runs next to the real contract), the tokens the token contract really moved per
//! invoice (`sent`), the transfers and callbacks still waiting (`slots`), and the guard's
//! real token balance. "Any state" means every field is arbitrary, including amounts,
//! counters, the ledger, block heights and epochs; Kani then keeps only those that
//! satisfy the invariant.
//!
//! The actions: every way the guard's world can move, by anyone, at any time:
//!   pay; a waiting transfer succeeding or failing; a waiting callback running, or DYING
//!   (out of gas: rolled back, dropped); approve_invoice on an existing invoice;
//!   reconcile; on_reconcile with ANY balance and ANY epoch (this over-covers every
//!   possible balance read, including one taken after outside transfers or a slow
//!   transfer); resolve_stuck with either answer at any block; sync_ledger and
//!   on_sync_ledger with any balance; and an OUTSIDE transfer of any amount into the guard.
//! Over-covering is safe for this kind of proof: it can only add ways to fail.
//!
//! What it is NOT: a proof about the wasm. It is about this model. The model is tied to the
//! real source only by the bounded lockstep run in proofs/guard-real (every distinct state
//! it explores, within its bound). The proof is for K invoices (K = 2 and K = 3 are run).

use crate::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotPhase {
    /// The guard created the ft_transfer receipt; the token has not run it yet.
    TransferWaiting,
    /// The token ran it (`true` = tokens moved); `on_transfer` has not run yet.
    CallbackWaiting(bool),
}

/// One `pay` still in flight: its transfer and its callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub used: bool,
    pub inv: usize,
    /// The amount in the ft_transfer receipt (fixed when `pay` ran).
    pub amount: u128,
    pub phase: SlotPhase,
}

#[derive(Clone, Copy, Debug)]
pub struct AState<const K: usize> {
    pub m: Model<K>,
    /// Tokens the token contract moved for each invoice, ever.
    pub sent: [u128; K],
    /// At most K pays in flight can be represented; `step` reports if a pay ever needed
    /// more (it never does under the invariant: the proof asserts it).
    pub slots: [Slot; K],
    pub guard_balance: u128,
}

#[derive(Clone, Copy, Debug)]
pub enum Action {
    Pay { i: usize, block: u64 },
    TransferRuns { slot: usize, ok: bool },
    CallbackRuns { slot: usize },
    CallbackDies { slot: usize },
    ApproveAgain { i: usize, amount: u128 },
    Reconcile { i: usize, block: u64 },
    OnReconcile { i: usize, epoch: u64, balance: Option<u128> },
    ResolveStuck { i: usize, sent: bool, block: u64 },
    SyncLedger,
    OnSyncLedger { epoch: u64, balance: Option<u128> },
    OutsideTransfer { amount: u128 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The action ran and may have changed the state.
    Applied,
    /// The guard refused (or the item does not exist); nothing changed.
    Refused,
    /// `pay` was accepted but no free slot was left to represent it. Must never happen.
    NoSlot,
}

/// The invariant, per invoice i (for `fixed` mode):
///  (a) amount > 0, and sent <= amount                       <- the safety property
///  (b) at most ONE pay in flight for i                      <- one transfer in flight
///  (c) an in-flight slot carries i's amount, and agrees with `sent`:
///      transfer waiting -> nothing sent yet; callback waiting after a success -> sent =
///      amount; after a failure -> nothing sent
///  (d) nothing in flight -> sent is 0 or exactly the amount
///  (e) status Approved -> nothing in flight and nothing sent
/// (b)-(e) are the strengthening that makes (a) inductive: (e) is what `pay` relies on,
/// and it is exactly what the pre-fix `on_reconcile` broke (Approved with sent = amount).
pub fn invariant<const K: usize>(s: &AState<K>) -> bool {
    for sl in s.slots.iter() {
        if sl.used && sl.inv >= K {
            return false;
        }
    }
    for i in 0..K {
        let inv = s.m.invoices[i];
        let amount = inv.amount;
        let sent = s.sent[i];
        if amount == 0 || sent > amount {
            return false; // (a)
        }
        let mut count = 0u32;
        let mut ok_slot = true;
        for sl in s.slots.iter() {
            if sl.used && sl.inv == i {
                count += 1;
                ok_slot &= sl.amount == amount
                    && match sl.phase {
                        SlotPhase::TransferWaiting => sent == 0,
                        SlotPhase::CallbackWaiting(true) => sent == amount,
                        SlotPhase::CallbackWaiting(false) => sent == 0,
                    }; // (c)
            }
        }
        if count > 1 || !ok_slot {
            return false; // (b), (c)
        }
        if count == 0 && !(sent == 0 || sent == amount) {
            return false; // (d)
        }
        if inv.status == Status::Approved && (count != 0 || sent != 0) {
            return false; // (e)
        }
    }
    true
}

/// The property we want for any number of calls.
pub fn no_overpay<const K: usize>(s: &AState<K>) -> bool {
    (0..K).all(|i| s.sent[i] <= s.m.invoices[i].amount)
}

/// The starting state: every invoice approved (any amount > 0), nothing sent, nothing in
/// flight, any balance.
pub fn initial<const K: usize>(mode: Mode, amounts: [u128; K], balance: u128) -> AState<K> {
    let free = Slot { used: false, inv: 0, amount: 0, phase: SlotPhase::TransferWaiting };
    AState { m: Model::new(mode, amounts, false), sent: [0; K], slots: [free; K], guard_balance: balance }
}

/// Apply one action, using the model's own methods (the code checked against the real
/// contract). Refusals leave the state exactly as it was.
pub fn step<const K: usize>(s: &mut AState<K>, a: Action) -> Outcome {
    match a {
        Action::Pay { i, block } => {
            if i >= K {
                return Outcome::Refused;
            }
            let mut m2 = s.m;
            match m2.pay(i, block) {
                Ok(amount) => match s.slots.iter().position(|sl| !sl.used) {
                    Some(k) => {
                        s.m = m2;
                        s.slots[k] = Slot { used: true, inv: i, amount, phase: SlotPhase::TransferWaiting };
                        Outcome::Applied
                    }
                    None => Outcome::NoSlot,
                },
                Err(_) => Outcome::Refused,
            }
        }
        Action::TransferRuns { slot, ok } => {
            if slot >= K || !s.slots[slot].used || s.slots[slot].phase != SlotPhase::TransferWaiting {
                return Outcome::Refused;
            }
            let sl = s.slots[slot];
            // The token moves the tokens only if the guard holds them (else it fails).
            let moved = ok && s.guard_balance >= sl.amount;
            if moved {
                match s.sent[sl.inv].checked_add(sl.amount) {
                    Some(v) => s.sent[sl.inv] = v,
                    None => return Outcome::Refused, // cannot happen under the invariant (sent = 0)
                }
                s.guard_balance -= sl.amount;
            }
            s.slots[slot].phase = SlotPhase::CallbackWaiting(moved);
            Outcome::Applied
        }
        Action::CallbackRuns { slot } => {
            if slot >= K || !s.slots[slot].used {
                return Outcome::Refused;
            }
            let SlotPhase::CallbackWaiting(ok) = s.slots[slot].phase else {
                return Outcome::Refused; // a callback runs only after its transfer
            };
            s.m.on_transfer(s.slots[slot].inv, ok);
            s.slots[slot].used = false;
            Outcome::Applied
        }
        Action::CallbackDies { slot } => {
            if slot >= K || !s.slots[slot].used {
                return Outcome::Refused;
            }
            if !matches!(s.slots[slot].phase, SlotPhase::CallbackWaiting(_)) {
                return Outcome::Refused;
            }
            // Out of gas or a panic: all its writes are rolled back. It just disappears.
            s.slots[slot].used = false;
            Outcome::Applied
        }
        Action::ApproveAgain { i, amount } => {
            if i >= K {
                return Outcome::Refused;
            }
            if s.m.approve_again(i, amount).is_ok() { Outcome::Applied } else { Outcome::Refused }
        }
        Action::Reconcile { i, block } => {
            // reconcile only reads and schedules; it writes nothing (lines 238-270).
            if i >= K {
                return Outcome::Refused;
            }
            if s.m.reconcile(i, block).is_ok() { Outcome::Applied } else { Outcome::Refused }
        }
        Action::OnReconcile { i, epoch, balance } => {
            if i >= K {
                return Outcome::Refused;
            }
            if s.m.on_reconcile(i, epoch, balance).is_ok() { Outcome::Applied } else { Outcome::Refused }
        }
        Action::ResolveStuck { i, sent, block } => {
            if i >= K {
                return Outcome::Refused;
            }
            if s.m.resolve_stuck(i, sent, block).is_ok() { Outcome::Applied } else { Outcome::Refused }
        }
        Action::SyncLedger => {
            if s.m.sync_ledger().is_ok() { Outcome::Applied } else { Outcome::Refused }
        }
        Action::OnSyncLedger { epoch, balance } => {
            if s.m.on_sync_ledger(epoch, balance).is_ok() { Outcome::Applied } else { Outcome::Refused }
        }
        Action::OutsideTransfer { amount } => match s.guard_balance.checked_add(amount) {
            Some(b) => {
                s.guard_balance = b;
                Outcome::Applied
            }
            None => Outcome::Refused,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The review's H1 schedule, as actions on the model: holds with the fix, breaks
    /// the invariant (and then overpays) with the old reconcile arm.
    fn h1(reopen: bool) -> (bool, u128) {
        let mut s = initial::<2>(Mode::Fixed, [100, 50], 1000);
        s.m.mutant_reopen_on_balance = reopen;
        let e = s.m.sync_ledger().unwrap();
        s.m.on_sync_ledger(e, Some(1000)).unwrap();
        let mut all_inv = true;
        let mut go = |s: &mut AState<2>, a| {
            step(s, a);
            all_inv &= invariant(s);
        };
        go(&mut s, Action::Pay { i: 0, block: 1 });
        go(&mut s, Action::TransferRuns { slot: 0, ok: true });
        go(&mut s, Action::CallbackDies { slot: 0 });
        go(&mut s, Action::OutsideTransfer { amount: 100 });
        let e = s.m.reconcile(0, 200).unwrap();
        let bal = s.guard_balance;
        go(&mut s, Action::OnReconcile { i: 0, epoch: e, balance: Some(bal) });
        go(&mut s, Action::Pay { i: 0, block: 201 });
        go(&mut s, Action::TransferRuns { slot: 0, ok: true });
        (all_inv, s.sent[0])
    }

    #[test]
    fn h1_fixed_holds_old_reconcile_breaks() {
        assert_eq!(h1(false), (true, 100), "fixed: invariant holds all the way, sam gets 100");
        assert_eq!(h1(true), (false, 200), "old reconcile: invariant breaks, sam gets 200");
    }
}

#[cfg(kani)]
mod harnesses {
    use super::*;

    fn any_status() -> Status {
        match kani::any::<u8>() % 4 {
            0 => Status::Approved,
            1 => Status::Pending,
            2 => Status::Paid,
            _ => Status::Failed,
        }
    }

    fn any_opt_u128() -> Option<u128> {
        if kani::any() { Some(kani::any()) } else { None }
    }

    /// A completely arbitrary state of the given mode (every field any value).
    fn any_state<const K: usize>(mode: Mode, reopen: bool) -> AState<K> {
        let inv = || Invoice {
            amount: kani::any(),
            status: any_status(),
            confirmed_payouts: kani::any(),
            transfers_started: kani::any(),
            pending_since_block: kani::any(),
        };
        let slot = || Slot {
            used: kani::any(),
            inv: kani::any(),
            amount: kani::any(),
            phase: if kani::any() { SlotPhase::TransferWaiting } else { SlotPhase::CallbackWaiting(kani::any()) },
        };
        let mut invoices = [inv(); K];
        for x in invoices.iter_mut() {
            *x = inv();
        }
        let mut slots = [slot(); K];
        for x in slots.iter_mut() {
            *x = slot();
        }
        let mut sent = [0u128; K];
        for x in sent.iter_mut() {
            *x = kani::any();
        }
        AState {
            m: Model {
                mode,
                mutant_no_pending_write: false,
                mutant_reopen_on_balance: reopen,
                invoices,
                expected_balance: any_opt_u128(),
                pending_count: kani::any(),
                epoch: kani::any(),
            },
            sent,
            slots,
            guard_balance: kani::any(),
        }
    }

    fn any_action() -> (u8, Action) {
        let tag: u8 = kani::any();
        kani::assume(tag < 11);
        let a = match tag {
            0 => Action::Pay { i: kani::any(), block: kani::any() },
            1 => Action::TransferRuns { slot: kani::any(), ok: kani::any() },
            2 => Action::CallbackRuns { slot: kani::any() },
            3 => Action::CallbackDies { slot: kani::any() },
            4 => Action::ApproveAgain { i: kani::any(), amount: kani::any() },
            5 => Action::Reconcile { i: kani::any(), block: kani::any() },
            6 => Action::OnReconcile { i: kani::any(), epoch: kani::any(), balance: any_opt_u128() },
            7 => Action::ResolveStuck { i: kani::any(), sent: kani::any(), block: kani::any() },
            8 => Action::SyncLedger,
            9 => Action::OnSyncLedger { epoch: kani::any(), balance: any_opt_u128() },
            _ => Action::OutsideTransfer { amount: kani::any() },
        };
        (tag, a)
    }

    /// The step, for any invariant state and any action. Covers show every kind of action
    /// can actually apply from an invariant state (the assume does not block it).
    fn step_preserves<const K: usize>(mode: Mode, reopen: bool) {
        let mut s = any_state::<K>(mode, reopen);
        kani::assume(invariant(&s));
        let (tag, a) = any_action();
        let r = step(&mut s, a);
        kani::assert(r != Outcome::NoSlot, "a pay accepted from an invariant state always has a free slot");
        let applied = r == Outcome::Applied;
        kani::cover!(applied && tag == 0, "applied: pay");
        kani::cover!(applied && tag == 1, "applied: transfer runs");
        kani::cover!(applied && tag == 2, "applied: callback runs");
        kani::cover!(applied && tag == 3, "applied: callback dies");
        kani::cover!(applied && tag == 4, "applied: approve_invoice again");
        kani::cover!(applied && tag == 5, "applied: reconcile");
        kani::cover!(applied && tag == 6, "applied: on_reconcile");
        kani::cover!(applied && tag == 7, "applied: resolve_stuck");
        kani::cover!(applied && tag == 8, "applied: sync_ledger");
        kani::cover!(applied && tag == 9, "applied: on_sync_ledger");
        kani::cover!(applied && tag == 10, "applied: outside transfer");
        kani::assert(invariant(&s), "inductive step: the invariant still holds after any one action");
    }

    #[kani::proof]
    fn inductive_step_fixed_k2() {
        step_preserves::<2>(Mode::Fixed, false);
    }

    #[kani::proof]
    fn inductive_step_fixed_k3() {
        step_preserves::<3>(Mode::Fixed, false);
    }

    /// Must FAIL: the planted-flaw mode does not keep the invariant (pay leaves Approved).
    #[kani::proof]
    fn inductive_step_vulnerable_k2() {
        step_preserves::<2>(Mode::VulnerableFixture, false);
    }

    /// Must FAIL: the pre-2026-11-11 on_reconcile ("balance == ledger -> Approved").
    #[kani::proof]
    fn inductive_step_old_reconcile_k2() {
        step_preserves::<2>(Mode::Fixed, true);
    }

    /// Base case: the starting state satisfies the invariant (any amounts > 0, any balance).
    #[kani::proof]
    fn inductive_init_k2() {
        let a: [u128; 2] = [kani::any(), kani::any()];
        kani::assume(a[0] > 0 && a[1] > 0);
        let s = initial::<2>(Mode::Fixed, a, kani::any());
        kani::assert(invariant(&s), "base case: the starting state satisfies the invariant");
    }

    #[kani::proof]
    fn inductive_init_k3() {
        let a: [u128; 3] = [kani::any(), kani::any(), kani::any()];
        kani::assume(a[0] > 0 && a[1] > 0 && a[2] > 0);
        let s = initial::<3>(Mode::Fixed, a, kani::any());
        kani::assert(invariant(&s), "base case: the starting state satisfies the invariant");
    }

    /// The invariant implies the property, and it is satisfiable by the states that
    /// matter (so it is not vacuous): each cover must come back SATISFIED.
    #[kani::proof]
    fn invariant_implies_no_overpay_k2() {
        let s = any_state::<2>(Mode::Fixed, false);
        kani::assume(invariant(&s));
        kani::assert(no_overpay(&s), "the invariant implies: sent <= amount for every invoice");
        let i0 = s.m.invoices[0];
        let busy = s.slots.iter().any(|sl| sl.used && sl.inv == 0);
        kani::cover!(true, "invariant satisfiable");
        kani::cover!(i0.status == Status::Pending && busy && s.sent[0] == i0.amount, "satisfiable: Pending, callback waiting after the tokens moved");
        kani::cover!(i0.status == Status::Pending && !busy && s.sent[0] == i0.amount, "satisfiable: stuck Pending after a dead callback, tokens moved (the H1 state)");
        kani::cover!(i0.status == Status::Failed && !busy && s.sent[0] == 0, "satisfiable: closed as Failed, nothing sent");
        kani::cover!(i0.status == Status::Paid && busy, "satisfiable: Paid while its transfer is still in flight");
    }
}
