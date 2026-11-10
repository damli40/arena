//! A MODEL of `contracts/guard`'s `pay` and `on_transfer`, written by hand.
//!
//! It is NOT the contract. Every line cites the guard source line it mirrors
//! (`contracts/guard/src/lib.rs`, as of the wasm Arena tested). Kani proves things
//! about this model; `proofs/guard-kani` (the conformance run) checks that this model
//! and the real contract agree on every schedule within the bound.
//!
//! Left out on purpose (out of scope, see evidence/proofs-plan.md): `approve_invoice`
//! beyond the initial approvals, `reconcile`, `sync_ledger`, logs, gas, the ledger
//! (`expected_balance` stays None because `sync_ledger` is never called here).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    VulnerableFixture,
    Fixed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    Approved,
    Pending,
    Paid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Invoice {
    pub amount: u128,
    pub status: Status,
    pub confirmed_payouts: u32,
    pub transfers_started: u32,
    pub pending_since_block: u64,
}

/// `mutant_no_pending_write`: a deliberate bug for the must-fail check. In `fixed`
/// mode it skips line 186 (`inv.status = Status::Pending;`), and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Model<const K: usize> {
    pub mode: Mode,
    pub mutant_no_pending_write: bool,
    pub invoices: [Invoice; K],
    pub pending_count: u32,
    pub epoch: u64,
}

/// Why a `pay` was refused (the guard's panic message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    AlreadyPaid,
    InFlight,
}

impl<const K: usize> Model<K> {
    /// Lines 130-143 (`new`) plus one `approve_invoice` per amount (lines 146-167).
    pub fn new(mode: Mode, amounts: [u128; K], mutant_no_pending_write: bool) -> Self {
        let inv = |amount| Invoice { amount, status: Status::Approved, confirmed_payouts: 0, transfers_started: 0, pending_since_block: 0 };
        Model { mode, mutant_no_pending_write, invoices: amounts.map(inv), pending_count: 0, epoch: 0 }
    }

    /// `pay`, lines 169-211. On refusal NOTHING changes: every `require!` in `pay`
    /// runs before the first write, and NEAR rolls back a panicking call anyway.
    /// On success returns (receiver index = invoice index, amount) of the ft_transfer
    /// receipt the guard creates (lines 202-210).
    pub fn pay(&mut self, i: usize, block: u64) -> Result<u128, Refusal> {
        let mode = self.mode; // line 172
        let inv = &mut self.invoices[i]; // line 174 (`expect("unknown invoice")`: ids are always known here)
        if inv.status == Status::Paid {
            return Err(Refusal::AlreadyPaid); // line 176
        }
        match mode {
            Mode::VulnerableFixture => {} // lines 179-182: nothing recorded
            Mode::Fixed => {
                if inv.status == Status::Pending {
                    return Err(Refusal::InFlight); // line 184
                }
                if !self.mutant_no_pending_write {
                    inv.status = Status::Pending; // line 186
                }
                inv.pending_since_block = block; // line 187
            }
        }
        inv.transfers_started += 1; // line 190 (overflow would panic; unreachable at this bound)
        let amount = inv.amount; // line 192
        if mode == Mode::Fixed {
            self.pending_count += 1; // line 198
            self.epoch += 1; // line 199
        }
        Ok(amount)
    }

    /// `on_transfer`, lines 215-226, dispatching to lines 361-385 / 388-420.
    pub fn on_transfer(&mut self, i: usize, confirmed: bool) -> bool {
        match self.mode {
            Mode::VulnerableFixture => {
                let inv = &mut self.invoices[i]; // line 362
                if confirmed {
                    inv.confirmed_payouts += 1; // line 369
                    inv.status = Status::Paid; // line 370
                    true
                } else {
                    false // lines 377-383: nothing reserved, nothing released
                }
            }
            Mode::Fixed => {
                let inv = &mut self.invoices[i]; // line 389 (the `else` branch: id always known here)
                let was_pending = inv.status == Status::Pending; // line 393
                if confirmed {
                    inv.confirmed_payouts = inv.confirmed_payouts.saturating_add(1); // line 403
                    inv.status = Status::Paid; // line 404
                    // lines 405-408: ledger update; expected_balance is None in this scope
                } else if was_pending {
                    inv.status = Status::Approved; // line 411
                }
                if was_pending {
                    self.pending_count = self.pending_count.saturating_sub(1); // line 414
                }
                self.epoch = self.epoch.saturating_add(1); // line 416
                confirmed
            }
        }
    }
}

pub mod world;

#[cfg(kani)]
mod proofs;
