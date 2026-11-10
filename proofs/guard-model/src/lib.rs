//! A MODEL of `contracts/guard`, written by hand.
//!
//! It is NOT the contract. Every line cites the guard source line it mirrors
//! (`contracts/guard/src/lib.rs` as of 2026-11-11, wasm sha256 `0382023b…`). Kani proves
//! things about this model (`proofs.rs`: bounded schedules; `inductive.rs`: any number of
//! calls). `proofs/guard-real` (`src/bin/exhaustive.rs`) runs the REAL contract source next
//! to this model, step by step, and reports any field where they disagree, in every distinct
//! state it explores within its bound. That bounded lockstep check is what ties this model
//! to the real code; nothing else does.
//!
//! Updated 2026-11-11 (evidence/fix-plan-2026-11-11.md): the model now has the ledger
//! (`expected_balance`), `reconcile` / `on_reconcile`, the new `resolve_stuck`, the new
//! status `Failed`, `sync_ledger` / `on_sync_ledger`, and `approve_invoice` on an existing
//! invoice. Refusals that the real build makes by panicking on an integer overflow
//! (`overflow-checks = true` in contracts/Cargo.toml) are modelled as refusals.
//! Still left out: logs, gas, receivers (one fixed receiver per invoice), and the caller
//! checks (`owner only`, `agent only`, `#[private]`): the model is always called by the
//! right account, which only gives an attacker MORE ways in, never fewer.

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
    /// lib.rs:76-79: closed by `resolve_stuck(id, sent = false)`; `pay` refuses it.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Invoice {
    pub amount: u128,
    pub status: Status,
    pub confirmed_payouts: u32,
    pub transfers_started: u32,
    pub pending_since_block: u64,
}

/// lib.rs:44 `RECONCILE_MIN_BLOCKS`.
pub const RECONCILE_MIN_BLOCKS: u64 = 100;

/// Two deliberate bugs for must-fail checks:
/// - `mutant_no_pending_write`: `fixed` `pay` skips line 194 (`inv.status = Status::Pending;`).
/// - `mutant_reopen_on_balance`: `on_reconcile` restores the pre-2026-11-11 arm
///   "balance == ledger -> Approved" (the H1 double pay).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Model<const K: usize> {
    pub mode: Mode,
    pub mutant_no_pending_write: bool,
    pub mutant_reopen_on_balance: bool,
    pub invoices: [Invoice; K],
    pub expected_balance: Option<u128>,
    pub pending_count: u32,
    pub epoch: u64,
}

/// Why a call was refused (the guard's panic message, or an overflow panic).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    AlreadyPaid,
    InFlight,
    ClosedFailed,
    NotFixedMode,
    LedgerNotSynced,
    NotPending,
    Ambiguous,
    TooEarly,
    EpochChanged,
    BalanceReadFailed,
    NeitherStory,
    AlreadyActedOn,
    ZeroAmount,
    Overflow,
}

impl<const K: usize> Model<K> {
    /// Lines 136-149 (`new`) plus one `approve_invoice` per amount (lines 153-174).
    pub fn new(mode: Mode, amounts: [u128; K], mutant_no_pending_write: bool) -> Self {
        let inv = |amount| Invoice { amount, status: Status::Approved, confirmed_payouts: 0, transfers_started: 0, pending_since_block: 0 };
        Model {
            mode,
            mutant_no_pending_write,
            mutant_reopen_on_balance: false,
            invoices: amounts.map(inv),
            expected_balance: None,
            pending_count: 0,
            epoch: 0,
        }
    }

    /// `approve_invoice` on an EXISTING id (lines 153-174): allowed only if it is still
    /// `Approved` and no transfer was ever started; then it is replaced, fresh.
    pub fn approve_again(&mut self, i: usize, amount: u128) -> Result<(), Refusal> {
        if amount == 0 {
            return Err(Refusal::ZeroAmount); // line 155
        }
        let e = self.invoices[i];
        if !(e.status == Status::Approved && e.transfers_started == 0) {
            return Err(Refusal::AlreadyActedOn); // lines 157-160
        }
        self.invoices[i] = Invoice { amount, status: Status::Approved, confirmed_payouts: 0, transfers_started: 0, pending_since_block: 0 }; // 161-173
        Ok(())
    }

    /// `pay`, lines 176-220. On refusal NOTHING changes: every `require!` in `pay`
    /// runs before the first write, and NEAR rolls back a panicking call anyway.
    /// On success returns the amount of the ft_transfer receipt the guard creates
    /// (lines 210-219); the receiver is the invoice's own.
    pub fn pay(&mut self, i: usize, block: u64) -> Result<u128, Refusal> {
        let mode = self.mode; // line 178
        let mut next = *self; // work on a copy: a panic anywhere below rolls everything back
        let inv = &mut next.invoices[i]; // line 180
        if inv.status == Status::Paid {
            return Err(Refusal::AlreadyPaid); // line 183
        }
        match mode {
            Mode::VulnerableFixture => {} // lines 186-189: nothing recorded
            Mode::Fixed => {
                if inv.status == Status::Pending {
                    return Err(Refusal::InFlight); // line 191
                }
                if inv.status == Status::Failed {
                    return Err(Refusal::ClosedFailed); // line 192
                }
                if !next.mutant_no_pending_write {
                    inv.status = Status::Pending; // line 194
                }
                inv.pending_since_block = block; // line 195
            }
        }
        inv.transfers_started = inv.transfers_started.checked_add(1).ok_or(Refusal::Overflow)?; // line 198
        let amount = inv.amount; // line 200
        if mode == Mode::Fixed {
            next.pending_count = next.pending_count.checked_add(1).ok_or(Refusal::Overflow)?; // line 206
            next.epoch = next.epoch.checked_add(1).ok_or(Refusal::Overflow)?; // line 207
        }
        *self = next;
        Ok(amount)
    }

    /// `on_transfer`, lines 223-234, dispatching to lines 408-431 / 435-467.
    /// A callback that dies (out of gas, or the fault build) is NOT a call to this: its
    /// writes are rolled back, so the world simply drops it.
    pub fn on_transfer(&mut self, i: usize, confirmed: bool) -> bool {
        match self.mode {
            Mode::VulnerableFixture => {
                let mut next = *self;
                let inv = &mut next.invoices[i]; // line 409
                if confirmed {
                    // line 416: `+= 1` panics on overflow; the panic rolls the callback back.
                    match inv.confirmed_payouts.checked_add(1) {
                        Some(c) => inv.confirmed_payouts = c,
                        None => return confirmed,
                    }
                    inv.status = Status::Paid; // line 417
                    *self = next;
                    true
                } else {
                    false // lines 423-430: nothing reserved, nothing released
                }
            }
            Mode::Fixed => {
                let inv = &mut self.invoices[i]; // lines 436-439 (id always known here)
                let was_pending = inv.status == Status::Pending; // line 440
                if confirmed {
                    inv.confirmed_payouts = inv.confirmed_payouts.saturating_add(1); // line 450
                    inv.status = Status::Paid; // line 451
                    let amount = inv.amount; // line 452
                    if let Some(b) = self.expected_balance {
                        self.expected_balance = Some(b.saturating_sub(amount)); // lines 453-455
                    }
                } else if was_pending {
                    inv.status = Status::Approved; // line 458
                }
                if was_pending {
                    self.pending_count = self.pending_count.saturating_sub(1); // line 461
                }
                self.epoch = self.epoch.saturating_add(1); // line 463
                confirmed
            }
        }
    }

    /// `reconcile`, lines 238-270: only checks, no writes. Returns the epoch it passes to
    /// `on_reconcile` (line 268).
    pub fn reconcile(&self, i: usize, block: u64) -> Result<u64, Refusal> {
        if self.mode != Mode::Fixed {
            return Err(Refusal::NotFixedMode); // line 240
        }
        if self.expected_balance.is_none() {
            return Err(Refusal::LedgerNotSynced); // lines 241-244
        }
        let inv = self.invoices[i];
        if inv.status != Status::Pending {
            return Err(Refusal::NotPending); // line 246
        }
        if self.pending_count != 1 {
            return Err(Refusal::Ambiguous); // lines 247-253
        }
        if block < inv.pending_since_block.saturating_add(RECONCILE_MIN_BLOCKS) {
            // line 254 computes `pending_since_block + 100`, which panics on overflow
            // (overflow-checks): that is a refusal too.
            return Err(Refusal::TooEarly); // lines 254-261
        }
        if inv.pending_since_block.checked_add(RECONCILE_MIN_BLOCKS).is_none() {
            return Err(Refusal::Overflow);
        }
        Ok(self.epoch)
    }

    /// `on_reconcile`, lines 275-322. `balance`: what the token reported, or None if the
    /// read failed. Returns the status it reports.
    pub fn on_reconcile(&mut self, i: usize, epoch_at_start: u64, balance: Option<u128>) -> Result<Status, Refusal> {
        if self.epoch != epoch_at_start {
            return Err(Refusal::EpochChanged); // lines 281-284
        }
        let actual = balance.ok_or(Refusal::BalanceReadFailed)?; // line 285
        let expected = self.expected_balance.ok_or(Refusal::LedgerNotSynced)?; // line 286
        let mut next = *self;
        let inv = &mut next.invoices[i]; // line 287
        if inv.status != Status::Pending {
            return Err(Refusal::NotPending); // line 288
        }
        let amount = inv.amount; // line 289
        let if_sent = expected.checked_sub(amount); // line 290
        let outcome = if Some(actual) == if_sent {
            inv.status = Status::Paid; // line 294
            inv.confirmed_payouts = inv.confirmed_payouts.saturating_add(1); // line 295
            next.expected_balance = if_sent; // line 296
            Status::Paid
        } else if actual == expected {
            if !next.mutant_reopen_on_balance {
                return Ok(Status::Pending); // lines 298-307: nothing changes
            }
            inv.status = Status::Approved; // MUTANT: the pre-2026-11-11 line
            Status::Approved
        } else {
            return Err(Refusal::NeitherStory); // lines 308-312
        };
        next.pending_count = next.pending_count.saturating_sub(1); // line 313
        next.epoch = next.epoch.checked_add(1).ok_or(Refusal::Overflow)?; // line 314
        *self = next;
        Ok(outcome)
    }

    /// `resolve_stuck`, lines 326-353.
    pub fn resolve_stuck(&mut self, i: usize, sent: bool, block: u64) -> Result<Status, Refusal> {
        if self.mode != Mode::Fixed {
            return Err(Refusal::NotFixedMode); // line 328
        }
        let mut next = *self;
        let inv = &mut next.invoices[i]; // line 329
        if inv.status != Status::Pending {
            return Err(Refusal::NotPending); // line 330
        }
        let ready_at = inv.pending_since_block.checked_add(RECONCILE_MIN_BLOCKS).ok_or(Refusal::Overflow)?; // line 331
        if block < ready_at {
            return Err(Refusal::TooEarly); // lines 332-338
        }
        let outcome = if sent {
            inv.confirmed_payouts = inv.confirmed_payouts.saturating_add(1); // line 340
            let amount = inv.amount;
            if let Some(b) = next.expected_balance {
                next.expected_balance = Some(b.saturating_sub(amount)); // lines 341-343
            }
            Status::Paid
        } else {
            Status::Failed // line 346
        };
        next.invoices[i].status = outcome; // line 348
        next.pending_count = next.pending_count.saturating_sub(1); // line 349
        next.epoch = next.epoch.checked_add(1).ok_or(Refusal::Overflow)?; // line 350
        *self = next;
        Ok(outcome)
    }

    /// `sync_ledger`, lines 358-370: only checks. Returns the epoch it passes on.
    pub fn sync_ledger(&self) -> Result<u64, Refusal> {
        if self.mode != Mode::Fixed {
            return Err(Refusal::NotFixedMode); // line 360
        }
        if self.pending_count != 0 {
            return Err(Refusal::InFlight); // line 361
        }
        Ok(self.epoch)
    }

    /// `on_sync_ledger`, lines 373-387.
    pub fn on_sync_ledger(&mut self, epoch_at_start: u64, balance: Option<u128>) -> Result<u128, Refusal> {
        if !(self.epoch == epoch_at_start && self.pending_count == 0) {
            return Err(Refusal::EpochChanged); // lines 378-381
        }
        let actual = balance.ok_or(Refusal::BalanceReadFailed)?; // line 382
        let epoch = self.epoch.checked_add(1).ok_or(Refusal::Overflow)?; // line 384
        self.expected_balance = Some(actual); // line 383
        self.epoch = epoch;
        Ok(actual)
    }
}

pub mod world;

#[cfg(kani)]
mod proofs;

pub mod inductive;
