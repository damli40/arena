//! Payment guard: an owner approves invoices, an agent asks the guard to pay them.
//!
//! One contract, two behaviours, picked at init with `mode`:
//!
//! * `vulnerable_fixture` - `pay` checks "is this invoice already paid?" and then
//!   starts the token transfer. The invoice is only marked paid later, in the
//!   callback that runs after the transfer confirms. On NEAR the transfer and the
//!   callback run in later blocks, so a second `pay` for the same invoice that
//!   lands in between still sees "not paid" and starts a second transfer.
//!   THIS MODE IS A TEST FIXTURE. DO NOT DEPLOY IT FOR REAL MONEY.
//!
//! * `fixed` - `pay` moves the invoice to `Pending` *before* starting the
//!   transfer, in the same atomic step as the check. A second `pay` sees
//!   `Pending` and is refused. The callback marks it `Paid` on success, or puts
//!   it back to `Approved` on failure so a genuinely failed transfer can be retried.
//!
//!   If the callback itself never completes (it panics, or runs out of gas), the
//!   invoice stays `Pending`. The owner can then call `reconcile(id)`. It reads the
//!   guard's real token balance from the token contract and compares it with the
//!   guard's own ledger of what it should hold. If the balance dropped by exactly the
//!   invoice amount, the money left: `Paid`. Any other reading changes nothing.
//!   In particular "balance unchanged" does NOT reopen the invoice: it could also mean
//!   "the money left, and someone sent the same amount back in" (fixed 2026-11-11,
//!   evidence/proofs-adversarial-review-2026-11-11.md, H1). The owner then closes the
//!   invoice with `resolve_stuck(id, sent)`: `Paid`, or the terminal `Failed`, which
//!   `pay` refuses. Nothing here ever reopens an invoice or retries a transfer.
//!
//! Fault injection: with the cargo feature `fault-injection` (test builds only),
//! `on_transfer` panics for invoice ids starting with `crash-`. The normal build
//! does not contain that code.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    env, ext_contract, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError,
};

const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(15);
const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(15);
const GAS_FOR_BALANCE_VIEW: Gas = Gas::from_tgas(10);
const GAS_FOR_RECONCILE_CALLBACK: Gas = Gas::from_tgas(15);

/// `reconcile` refuses until this many blocks have passed since the invoice went
/// `Pending`. Reason: if the transfer and callback are merely slow (not dead), the
/// balance read could happen before the transfer lands, and reconcile would wrongly
/// say "the money did not leave". This is a waiting rule, not a proof.
pub const RECONCILE_MIN_BLOCKS: u64 = 100;

#[ext_contract(ext_ft)]
#[allow(dead_code)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
    fn ft_balance_of(&self, account_id: AccountId) -> U128;
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    #[serde(rename = "vulnerable_fixture")]
    VulnerableFixture,
    #[serde(rename = "fixed")]
    Fixed,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Approved by the owner, not paid.
    Approved,
    /// A transfer is in flight (only ever used in `fixed` mode).
    Pending,
    /// A transfer confirmed.
    Paid,
    /// Closed by the owner with `resolve_stuck(id, sent = false)` (fixed mode only).
    /// Terminal: `pay` refuses it. To pay the bill, the owner approves a new invoice id.
    Failed,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Invoice {
    pub receiver: AccountId,
    pub amount: U128,
    pub status: Status,
    /// How many transfers for this invoice the guard recorded as confirmed
    /// (by the callback, or by `reconcile`). Should never exceed 1.
    pub confirmed_payouts: u32,
    /// How many transfers for this invoice the guard started.
    pub transfers_started: u32,
    /// Block height when the invoice last went `Pending` (0 if never).
    pub pending_since_block: u64,
}

#[near(serializers = [json])]
pub struct LedgerView {
    /// Tokens the guard believes it holds. `None` until the owner calls `sync_ledger`.
    pub expected_balance: Option<U128>,
    /// How many invoices are `Pending` right now.
    pub pending_count: u32,
    /// Bumped on every change that affects the ledger or the pending set.
    pub epoch: u64,
}

#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct Guard {
    mode: Mode,
    owner: AccountId,
    agent: AccountId,
    token: AccountId,
    invoices: LookupMap<String, Invoice>,
    /// Ledger (fixed mode only): tokens the guard should hold. A `Pending` invoice's
    /// amount still counts as held. Reduced only when a transfer is confirmed.
    expected_balance: Option<u128>,
    pending_count: u32,
    epoch: u64,
}

/// What the token said about the transfer, read by hand instead of via
/// `#[callback_result]`. The macro version panics if the token returns bytes it
/// cannot parse as JSON; this version cannot panic.
fn transfer_confirmed() -> bool {
    if env::promise_results_count() != 1 {
        return false;
    }
    match env::promise_result_checked(0, 64) {
        Ok(_) => true,
        // The token call succeeded but returned more than 64 bytes. Still a success.
        Err(PromiseError::TooLong(_)) => true,
        Err(PromiseError::Failed) => false,
        Err(_) => false,
    }
}

#[near]
impl Guard {
    #[init]
    pub fn new(mode: Mode, owner: AccountId, agent: AccountId, token: AccountId) -> Self {
        Self {
            mode,
            owner,
            agent,
            token,
            invoices: LookupMap::new(b"i"),
            expected_balance: None,
            pending_count: 0,
            epoch: 0,
        }
    }

    /// Owner-only. Approves (or re-approves, if not yet paid or in flight) an invoice.
    pub fn approve_invoice(&mut self, id: String, receiver: AccountId, amount: U128) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(amount.0 > 0, "amount must be > 0");
        if let Some(existing) = self.invoices.get(&id) {
            require!(
                existing.status == Status::Approved && existing.transfers_started == 0,
                "invoice already exists and has been acted on"
            );
        }
        self.invoices.insert(
            id,
            Invoice {
                receiver,
                amount,
                status: Status::Approved,
                confirmed_payouts: 0,
                transfers_started: 0,
                pending_since_block: 0,
            },
        );
    }

    /// Agent-only. Starts the token transfer for an approved invoice.
    pub fn pay(&mut self, id: String) -> Promise {
        require!(env::predecessor_account_id() == self.agent, "agent only");
        let mode = self.mode;
        let token = self.token.clone();
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");

        // The check both modes share.
        require!(inv.status != Status::Paid, "invoice already paid");

        match mode {
            Mode::VulnerableFixture => {
                // BUG (on purpose): nothing is recorded here. The invoice stays
                // `Approved` until the callback runs, blocks later.
            }
            Mode::Fixed => {
                require!(inv.status != Status::Pending, "payment already in flight");
                require!(inv.status != Status::Failed, "invoice closed as failed by the owner; approve a new invoice id to pay it");
                // Reserve the invoice in the same atomic step as the check.
                inv.status = Status::Pending;
                inv.pending_since_block = env::block_height();
            }
        }
        inv.transfers_started += 1;
        let receiver = inv.receiver.clone();
        let amount = inv.amount;
        env::log_str(&format!(
            "pay: invoice={id} transfer #{} started, mode={mode:?}",
            inv.transfers_started
        ));
        if mode == Mode::Fixed {
            self.pending_count += 1;
            self.epoch += 1;
        }

        ext_ft::ext(token)
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_FT_TRANSFER)
            .ft_transfer(receiver, amount, Some(format!("invoice {id}")))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLBACK)
                    .on_transfer(id),
            )
    }

    /// Runs after the token answers. Returns true if the transfer confirmed.
    #[private]
    pub fn on_transfer(&mut self, id: String) -> bool {
        #[cfg(feature = "fault-injection")]
        if id.starts_with("crash-") {
            env::panic_str("FAULT INJECTION (test build only): on_transfer panics for crash- ids");
        }

        let confirmed = transfer_confirmed();
        match self.mode {
            Mode::VulnerableFixture => self.on_transfer_fixture(id, confirmed),
            Mode::Fixed => self.on_transfer_fixed(id, confirmed),
        }
    }

    /// Owner-only, fixed mode only. Settles an invoice stuck in `Pending` as `Paid` if the
    /// guard's real token balance shows the money left. Never reopens it, never re-sends.
    pub fn reconcile(&mut self, id: String) -> Promise {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(self.mode == Mode::Fixed, "reconcile exists only in fixed mode");
        require!(
            self.expected_balance.is_some(),
            "ledger not synced: owner must call sync_ledger first"
        );
        let inv = self.invoices.get(&id).expect("unknown invoice");
        require!(inv.status == Status::Pending, "invoice is not Pending, nothing to reconcile");
        require!(
            self.pending_count == 1,
            format!(
                "ambiguous: {} invoices are Pending, one balance cannot tell which transfer happened",
                self.pending_count
            )
        );
        let ready_at = inv.pending_since_block + RECONCILE_MIN_BLOCKS;
        require!(
            env::block_height() >= ready_at,
            format!(
                "too early: wait until block {ready_at} (now {}) so an in-flight transfer cannot be mistaken for a failed one",
                env::block_height()
            )
        );
        ext_ft::ext(self.token.clone())
            .with_static_gas(GAS_FOR_BALANCE_VIEW)
            .ft_balance_of(env::current_account_id())
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RECONCILE_CALLBACK)
                    .on_reconcile(id, self.epoch),
            )
    }

    /// Settles the invoice from the balance the token reported. Panicking here is safe:
    /// nothing changes and the owner can call `reconcile` again.
    #[private]
    pub fn on_reconcile(
        &mut self,
        id: String,
        epoch_at_start: u64,
        #[callback_result] balance: Result<U128, PromiseError>,
    ) -> Status {
        require!(
            self.epoch == epoch_at_start,
            "state changed while the balance was being read; call reconcile again"
        );
        let actual = balance.unwrap_or_else(|_| env::panic_str("balance read failed")).0;
        let expected = self.expected_balance.unwrap_or_else(|| env::panic_str("ledger not synced"));
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");
        require!(inv.status == Status::Pending, "invoice is no longer Pending");
        let amount = inv.amount.0;
        let if_sent = expected.checked_sub(amount);

        let outcome = if Some(actual) == if_sent {
            // The money left the guard: the transfer happened.
            inv.status = Status::Paid;
            inv.confirmed_payouts = inv.confirmed_payouts.saturating_add(1);
            self.expected_balance = if_sent;
            Status::Paid
        } else if actual == expected {
            // The balance did not move. That fits "the transfer never happened", but also
            // "it happened, and the same amount was then sent to the guard" (review H1).
            // One balance cannot tell these apart, so nothing changes: the invoice stays
            // Pending until the owner calls resolve_stuck.
            inv.status = Status::Approved;
            Status::Approved
        } else {
            env::panic_str(&format!(
                "balance matches neither story: ledger says {expected} if not sent, {} if sent, token says {actual}. Refusing to guess.",
                if_sent.map(|v| v.to_string()).unwrap_or_else(|| "impossible".into())
            ));
        };
        self.pending_count = self.pending_count.saturating_sub(1);
        self.epoch += 1;
        env::log_str(&format!(
            "reconcile: invoice={id} ledger={expected} token_balance={actual} -> {outcome:?}"
        ));
        outcome
    }

    /// Owner-only, fixed mode only. Closes an invoice stuck in `Pending` with the outcome the
    /// owner states after checking the chain (for example the transfer receipt on an explorer).
    /// `sent = true` -> `Paid`, and the ledger drops by the amount, as a confirmed transfer would.
    /// `sent = false` -> `Failed`, terminal: `pay` refuses it; the owner approves a new id to pay.
    /// Same waiting rule as `reconcile`. Never sends tokens, never reopens the invoice.
    pub fn resolve_stuck(&mut self, id: String, sent: bool) -> Status {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(self.mode == Mode::Fixed, "resolve_stuck exists only in fixed mode");
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");
        require!(inv.status == Status::Pending, "invoice is not Pending, nothing to resolve");
        let ready_at = inv.pending_since_block + RECONCILE_MIN_BLOCKS;
        require!(
            env::block_height() >= ready_at,
            format!(
                "too early: wait until block {ready_at} (now {}) so an in-flight transfer cannot be mistaken for a failed one",
                env::block_height()
            )
        );
        let outcome = if sent {
            inv.confirmed_payouts = inv.confirmed_payouts.saturating_add(1);
            if let Some(b) = self.expected_balance {
                self.expected_balance = Some(b.saturating_sub(inv.amount.0));
            }
            Status::Paid
        } else {
            Status::Failed
        };
        inv.status = outcome;
        self.pending_count = self.pending_count.saturating_sub(1);
        self.epoch += 1;
        env::log_str(&format!("resolve_stuck: invoice={id} owner says sent={sent} -> {outcome:?}"));
        outcome
    }

    /// Owner-only, fixed mode only. Sets the ledger to the guard's real token balance.
    /// Allowed only when no invoice is `Pending`, so the balance is unambiguous.
    /// Call it after funding the guard.
    pub fn sync_ledger(&mut self) -> Promise {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(self.mode == Mode::Fixed, "sync_ledger exists only in fixed mode");
        require!(self.pending_count == 0, "cannot sync while an invoice is Pending");
        ext_ft::ext(self.token.clone())
            .with_static_gas(GAS_FOR_BALANCE_VIEW)
            .ft_balance_of(env::current_account_id())
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RECONCILE_CALLBACK)
                    .on_sync_ledger(self.epoch),
            )
    }

    #[private]
    pub fn on_sync_ledger(
        &mut self,
        epoch_at_start: u64,
        #[callback_result] balance: Result<U128, PromiseError>,
    ) -> U128 {
        require!(
            self.epoch == epoch_at_start && self.pending_count == 0,
            "state changed while the balance was being read; call sync_ledger again"
        );
        let actual = balance.unwrap_or_else(|_| env::panic_str("balance read failed"));
        self.expected_balance = Some(actual.0);
        self.epoch += 1;
        actual
    }

    pub fn get_invoice(&self, id: String) -> Option<Invoice> {
        self.invoices.get(&id).cloned()
    }

    pub fn get_ledger(&self) -> LedgerView {
        LedgerView {
            expected_balance: self.expected_balance.map(U128),
            pending_count: self.pending_count,
            epoch: self.epoch,
        }
    }

    pub fn get_mode(&self) -> Mode {
        self.mode
    }
}

impl Guard {
    /// The labelled fixture's callback, unchanged in behaviour: `expect` on a missing
    /// invoice, no ledger.
    fn on_transfer_fixture(&mut self, id: String, confirmed: bool) -> bool {
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");
        if confirmed {
            if inv.status == Status::Paid {
                env::log_str(&format!(
                    "DOUBLE PAYOUT: invoice={id} was already Paid when another transfer confirmed"
                ));
            }
            inv.confirmed_payouts += 1;
            inv.status = Status::Paid;
            env::log_str(&format!(
                "on_transfer: invoice={id} confirmed, confirmed_payouts={}",
                inv.confirmed_payouts
            ));
            true
        } else {
            // Nothing was reserved, nothing to release.
            env::log_str(&format!(
                "on_transfer: invoice={id} transfer FAILED, status now {:?}",
                inv.status
            ));
            false
        }
    }

    /// The fixed callback. Written so it has no panic path of its own: no `expect`,
    /// no `unwrap`, saturating arithmetic, a handful of writes.
    fn on_transfer_fixed(&mut self, id: String, confirmed: bool) -> bool {
        let Some(inv) = self.invoices.get_mut(&id) else {
            env::log_str(&format!("on_transfer: unknown invoice={id}, nothing recorded"));
            return confirmed;
        };
        let was_pending = inv.status == Status::Pending;
        if confirmed {
            if !was_pending {
                // Only possible if reconcile or resolve_stuck already closed this invoice
                // (the waiting rule was not long enough). Record the truth anyway.
                env::log_str(&format!(
                    "on_transfer: LATE confirm for invoice={id}, status was {:?}",
                    inv.status
                ));
            }
            inv.confirmed_payouts = inv.confirmed_payouts.saturating_add(1);
            inv.status = Status::Paid;
            let amount = inv.amount.0;
            if let Some(b) = self.expected_balance {
                self.expected_balance = Some(b.saturating_sub(amount));
            }
        } else if was_pending {
            // Release the reservation so the invoice can be retried.
            inv.status = Status::Approved;
        }
        if was_pending {
            self.pending_count = self.pending_count.saturating_sub(1);
        }
        self.epoch = self.epoch.saturating_add(1);
        env::log_str(&format!("on_transfer: invoice={id} confirmed={confirmed}"));
        confirmed
    }
}
