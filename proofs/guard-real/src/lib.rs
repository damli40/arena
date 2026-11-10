//! A small NEAR "world" around the REAL guard (`contracts/guard`, compiled unchanged).
//!
//! What it models, in plain words:
//! - The guard runs on near-sdk's mocked blockchain (near-sdk's own `unit-testing`
//!   feature, which wraps nearcore's VMLogic). Its storage is carried between calls.
//! - Every `pay` the guard accepts creates two receipts: an `ft_transfer` to the token,
//!   then `on_transfer` back on the guard. The world reads those receipts from the
//!   mocked chain (it does not assume what the guard asked for).
//! - A "scheduler" picks which waiting item runs next: a `pay` not yet run, a transfer
//!   whose `pay` ran, or a callback whose transfer ran. Every choice is a separate run.
//! - The token is modelled as "this transfer succeeded, `amount` moved to `receiver`"
//!   or "it failed, nothing moved". The callback is told which, as a promise result.
//! - A `pay` the guard refuses panics; on NEAR that rolls back its state. Here the world
//!   keeps the storage from before the call.
//!
//! Who uses this world (corrected 2026-11-11, review L2: the files named here before,
//! `tests/exhaustive.rs` and `src/kani_harness.rs`, never existed):
//! - `src/bin/exhaustive.rs` (plain Rust): tries every schedule, really calls `pay` every
//!   time and catches the panic of a refused one.
//! - the `kani_probe` module at the end of this file: a feasibility probe only. Kani
//!   0.68.0 could not compile this crate, so the Kani proof runs on the separate model
//!   (`proofs/guard-model`), and the exhaustive run checks [`pay_would_be_accepted`]
//!   against the real `pay` on every schedule.

#[cfg(not(any(feature = "mutant", feature = "mutant-reopen")))]
pub use guard::{Guard, Mode, Status};
#[cfg(feature = "mutant")]
pub use guard_mutant::{Guard, Mode, Status};
// 2026-11-11: the pre-fix reconcile ("balance == ledger -> Approved"), as a must-fail mutant.
#[cfg(feature = "mutant-reopen")]
pub use guard_mutant_reopen::{Guard, Mode, Status};
use guard_model::{Mode as MMode, Model, Status as MStatus};
use near_sdk::json_types::U128;
use near_sdk::mock::MockAction;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{env, AccountId, MockedBlockchain, PromiseResult};
use std::collections::HashMap;

pub const GUARD: &str = "guard.test";
pub const OWNER: &str = "owner.test";
pub const AGENT: &str = "agent.test";
pub const TOKEN: &str = "token.test";

/// The invoices the owner approves at setup: (id, receiver, amount).
pub const INVOICES: [(&str, &str, u128); 2] = [("inv-a", "sam.test", 100), ("inv-b", "ada.test", 50)];
pub const NINV: usize = INVOICES.len();

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

/// One item waiting to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// An agent `pay(invoice)` transaction not yet executed.
    Pay { inv: usize },
    /// An `ft_transfer` receipt the guard created, as read from the mocked chain.
    /// `tag` links it to its callback.
    Transfer { inv: usize, tag: usize, receiver: String, amount: u128 },
    /// The guard's `on_transfer(id)` callback. `outcome` is None until its transfer has
    /// run (it cannot run before), then the outcome it will see as a promise result.
    Callback { inv: usize, tag: usize, outcome: Option<bool> },
    // ---- full world only (2026-11-11) ----
    /// The owner's `reconcile` transaction, not yet sent (invoice and waiting are chosen
    /// when it runs).
    Reconcile,
    /// The `ft_balance_of` receipt `reconcile` created: the token reads the guard's balance.
    BalanceRead { inv: usize, epoch: u64 },
    /// The `on_reconcile` callback, with the balance the read returned.
    OnReconcile { inv: usize, epoch: u64, balance: u128 },
    /// The owner's `resolve_stuck(id, sent)` transaction (choices made when it runs).
    Resolve,
    /// Someone else sends `DONATION` tokens to the guard (review H1).
    Outside,
}

/// The choices the scheduler makes when an item runs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Choice {
    /// Transfer: the token moves the tokens (else it fails).
    pub ok: bool,
    /// Callback: it dies (out of gas / panic): its writes are rolled back.
    pub dies: bool,
    /// Reconcile / Resolve: which invoice.
    pub inv: usize,
    /// Resolve: what the owner states.
    pub sent: bool,
    /// Reconcile / Resolve: the owner waits RECONCILE_MIN_BLOCKS first.
    pub wait: bool,
}

/// The guard's token balance at setup (full world: the owner funds it and syncs the ledger).
pub const FUND: u128 = 1000;
pub const DONATION: u128 = 100;
pub const WAIT_BLOCKS: u64 = 100;

/// What happened in one step (for readable traces).
#[derive(Clone, Debug)]
pub enum Event {
    PayAccepted { inv: usize, status_before: Status },
    PayRefused { inv: usize, status_before: Status },
    TransferOk { inv: usize, amount: u128 },
    TransferFailed { inv: usize },
    CallbackRan { inv: usize, ok: bool, status_after: Status },
    CallbackDied { inv: usize },
    ReconcileSent { inv: usize, accepted: bool, waited: bool },
    BalanceRead { inv: usize, balance: u128 },
    OnReconcile { inv: usize, accepted: bool, status_after: Status },
    Resolve { inv: usize, sent: bool, waited: bool, accepted: bool, status_after: Status },
    Outside { balance_after: u128 },
}

#[derive(Clone)]
pub struct World {
    pub mode: Mode,
    pub storage: HashMap<Vec<u8>, Vec<u8>>,
    pub pending: Vec<Item>,
    /// Tokens the modelled token contract actually moved, per invoice.
    pub sent: [u128; NINV],
    pub block: u64,
    pub trace: Vec<Event>,
    next_tag: usize,
    /// The hand-written model (proofs/guard-model), stepped in lockstep.
    pub model: Model<NINV>,
    /// Lockstep disagreements between the model and the real contract.
    pub mismatches: Vec<String>,
    /// Full world (2026-11-11): the extra items exist, the ledger is synced at setup.
    pub full: bool,
    /// The guard's real token balance (what `ft_balance_of` would return).
    pub guard_balance: u128,
    /// How many more callbacks may die (full world: 1).
    pub deaths_left: u8,
    /// Invoices whose outcome the OWNER decided (a dead callback, resolve_stuck, or an
    /// accepted on_reconcile). P2 ("nothing sent -> payable again") is not required of
    /// them: a stuck or owner-closed bill is the documented trade-off.
    pub touched: [bool; NINV],
}

pub type Key = (Vec<(Vec<u8>, Vec<u8>)>, Vec<(u8, usize, String, u128, u8)>, [u128; NINV], Model<NINV>, u128, u8, [bool; NINV]);

fn context(predecessor: &str, block: u64) -> near_sdk::VMContext {
    VMContextBuilder::new()
        .current_account_id(acc(GUARD))
        .signer_account_id(acc(predecessor))
        .predecessor_account_id(acc(predecessor))
        .block_height(block)
        .block_timestamp(block * 1_000_000_000)
        .build()
}

/// Install a fresh mocked blockchain holding `storage`.
fn install(storage: HashMap<Vec<u8>, Vec<u8>>, predecessor: &str, block: u64, results: Vec<PromiseResult>) {
    env::set_blockchain_interface(MockedBlockchain::new(
        context(predecessor, block),
        near_sdk::test_vm_config(),
        near_parameters::RuntimeFeesConfig::test(),
        results,
        storage,
        Default::default(),
        None,
    ));
}

fn take_storage() -> HashMap<Vec<u8>, Vec<u8>> {
    near_sdk::mock::with_mocked_blockchain(|b| b.take_storage())
}

/// Read the contract from storage, run `f`, write it back (what the `#[near]` wasm
/// wrapper does around every method). Dropping the contract flushes its LookupMap.
fn with_guard<R>(f: impl FnOnce(&mut Guard) -> R) -> R {
    let mut g: Guard = env::state_read().expect("guard state");
    let r = f(&mut g);
    env::state_write(&g);
    drop(g);
    r
}

impl World {
    /// Deploy + init the guard, then the owner approves every invoice in [`INVOICES`].
    pub fn new(mode: Mode, pays: &[usize]) -> World {
        Self::new_world(mode, pays, false)
    }

    /// `full = true` (2026-11-11): also one owner `reconcile`, one `resolve_stuck`, one
    /// outside transfer and one callback death, anywhere in the schedule; the guard holds
    /// FUND tokens and (fixed mode) the owner has synced the ledger to it.
    pub fn new_world(mode: Mode, pays: &[usize], full: bool) -> World {
        install(HashMap::new(), GUARD, 1, vec![]);
        let g = Guard::new(mode, acc(OWNER), acc(AGENT), acc(TOKEN));
        env::state_write(&g);
        drop(g);
        let storage = take_storage();
        install(storage, OWNER, 2, vec![]);
        with_guard(|g| {
            for (id, recv, amount) in INVOICES {
                g.approve_invoice(id.to_string(), acc(recv), U128(amount));
            }
        });
        let mut storage = take_storage();
        let mut model = Model::new(
            if mode == Mode::Fixed { MMode::Fixed } else { MMode::VulnerableFixture },
            [INVOICES[0].2, INVOICES[1].2],
            // LOCKSTEP_SELFTEST=1 gives the model the OPPOSITE mutant flag from the
            // real build, so the lockstep check must report mismatches (it has teeth).
            cfg!(feature = "mutant") ^ std::env::var_os("LOCKSTEP_SELFTEST").is_some(),
        );
        model.mutant_reopen_on_balance = cfg!(feature = "mutant-reopen");
        let mut pending: Vec<Item> = pays.iter().map(|&inv| Item::Pay { inv }).collect();
        if full {
            pending.extend([Item::Reconcile, Item::Resolve, Item::Outside]);
            if mode == Mode::Fixed {
                // The owner calls sync_ledger; the token reports FUND (lines 358-387).
                install(storage.clone(), OWNER, 2, vec![]);
                let e = with_guard(|g| {
                    let p = g.sync_ledger();
                    drop(p);
                    g.get_ledger().epoch
                });
                storage = take_storage();
                install(storage, GUARD, 2, vec![]);
                with_guard(|g| g.on_sync_ledger(e, Ok(U128(FUND))));
                storage = take_storage();
                let me = model.sync_ledger().expect("model sync");
                model.on_sync_ledger(me, Some(FUND)).expect("model on_sync");
            }
        }
        World {
            mode,
            storage,
            pending,
            sent: [0; NINV],
            block: 3,
            trace: Vec::new(),
            next_tag: 0,
            model,
            mismatches: Vec::new(),
            full,
            guard_balance: FUND,
            deaths_left: if full { 1 } else { 0 },
            touched: [false; NINV],
        }
    }

    /// The guard's own view of an invoice's status (`get_invoice`).
    pub fn status(&self, inv: usize) -> Status {
        install(self.storage.clone(), OWNER, self.block, vec![]);
        let g: Guard = env::state_read().expect("guard state");
        g.get_invoice(INVOICES[inv].0.to_string()).expect("invoice exists").status
    }

    /// A canonical key for "same situation": storage, sent totals, and the waiting
    /// items as a multiset (transfers for the same invoice are interchangeable).
    /// Used by the exhaustive driver to visit each distinct state once.
    pub fn key(&self) -> Key {
        let mut st: Vec<_> = self.storage.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        st.sort();
        let mut pend: Vec<_> = self
            .pending
            .iter()
            .filter_map(|i| match i {
                Item::Pay { inv } => Some((0u8, *inv, String::new(), 0u128, 0u8)),
                Item::Transfer { inv, receiver, amount, .. } => Some((1, *inv, receiver.clone(), *amount, 0)),
                Item::Callback { outcome: None, .. } => None, // implied by its transfer
                Item::Callback { inv, outcome: Some(ok), .. } => Some((2, *inv, String::new(), 0, *ok as u8)),
                Item::Reconcile => Some((3, 0, String::new(), 0, 0)),
                Item::BalanceRead { inv, epoch } => Some((4, *inv, epoch.to_string(), 0, 0)),
                Item::OnReconcile { inv, epoch, balance } => Some((5, *inv, epoch.to_string(), *balance, 0)),
                Item::Resolve => Some((6, 0, String::new(), 0, 0)),
                Item::Outside => Some((7, 0, String::new(), 0, 0)),
            })
            .collect();
        pend.sort();
        // The block height is left out (as before): it only matters through the waiting
        // rule, and every owner action here either waits the full 100 blocks or not at all.
        (st, pend, self.sent, self.model, self.guard_balance, self.deaths_left, self.touched)
    }

    /// Compare every field the model tracks with the real contract's own views
    /// (`get_invoice`, `get_ledger`). Any difference is recorded as a mismatch.
    pub fn compare_with_model(&mut self) {
        install(self.storage.clone(), OWNER, self.block, vec![]);
        let g: Guard = env::state_read().expect("guard state");
        let ledger = g.get_ledger();
        let mut diffs = Vec::new();
        for (i, (id, _, _)) in INVOICES.iter().enumerate() {
            let r = g.get_invoice(id.to_string()).expect("invoice");
            let m = self.model.invoices[i];
            let rs = mstatus(r.status);
            if rs != m.status
                || r.amount.0 != m.amount
                || r.transfers_started != m.transfers_started
                || r.confirmed_payouts != m.confirmed_payouts
                || r.pending_since_block != m.pending_since_block
            {
                diffs.push(format!("{id}: real {:?}/{}/{}/{} model {:?}/{}/{}/{}", r.status, r.transfers_started, r.confirmed_payouts, r.pending_since_block, m.status, m.transfers_started, m.confirmed_payouts, m.pending_since_block));
            }
        }
        if ledger.pending_count != self.model.pending_count || ledger.epoch != self.model.epoch {
            diffs.push(format!("ledger: real pending={} epoch={} model pending={} epoch={}", ledger.pending_count, ledger.epoch, self.model.pending_count, self.model.epoch));
        }
        if ledger.expected_balance.map(|v| v.0) != self.model.expected_balance {
            diffs.push(format!("ledger: real expected_balance={:?} model={:?}", ledger.expected_balance.map(|v| v.0), self.model.expected_balance));
        }
        drop(g);
        self.mismatches.extend(diffs);
    }

    pub fn quiescent(&self) -> bool {
        self.pending.is_empty()
    }

    /// Indexes of the items that may run next (a callback only after its transfer).
    pub fn runnable(&self) -> Vec<usize> {
        (0..self.pending.len())
            .filter(|&i| !matches!(self.pending[i], Item::Callback { outcome: None, .. }))
            .collect()
    }

    /// Call the real `pay` only. Returns the receipts it created and its storage
    /// afterwards. Panics (inside the guard) if the guard refuses. Nothing of the
    /// world's own decoding runs here, so a panic from this function is the guard's.
    fn call_pay(&self, inv: usize) -> (Vec<near_sdk::mock::Receipt>, HashMap<Vec<u8>, Vec<u8>>) {
        install(self.storage.clone(), AGENT, self.block, vec![]);
        let promise = with_guard(|g| g.pay(INVOICES[inv].0.to_string()));
        drop(promise); // the Promise schedules its receipts when dropped
        let receipts = near_sdk::mock::with_mocked_blockchain(|b| b.created_receipts());
        (receipts, take_storage())
    }

    /// Turn an accepted `pay`'s receipts into waiting items. A malformed receipt panics
    /// here, OUTSIDE any catch_unwind, so it stops the run loudly (review L1).
    fn accept_pay(&mut self, inv: usize, receipts: &[near_sdk::mock::Receipt], storage: HashMap<Vec<u8>, Vec<u8>>) -> (Item, Item) {
        self.storage = storage;
        let tag = self.next_tag;
        self.next_tag += 1;
        decode_receipts(inv, tag, receipts)
    }

    /// Run a `pay` that is expected to be accepted (the Kani driver).
    fn run_pay_unchecked(&mut self, inv: usize) -> (Item, Item) {
        let (receipts, storage) = self.call_pay(inv);
        self.accept_pay(inv, &receipts, storage)
    }

    /// Execute pending item `idx`. For a transfer, `transfer_ok` picks its outcome.
    /// `pay_accepted`: Some(answer) means "trust this answer about whether the guard
    /// accepts this pay" (the Kani driver); None means "really call pay and catch a
    /// refusal" (the exhaustive driver, which then also checks the answer).
    pub fn step(&mut self, idx: usize, transfer_ok: bool, pay_accepted: Option<bool>) {
        self.step_with(idx, Choice { ok: transfer_ok, ..Default::default() }, pay_accepted)
    }

    /// Run a guard method that may refuse (panic). Returns (accepted, receipts). On refusal
    /// the storage is rolled back, as NEAR does. Only the guard's own call is inside
    /// catch_unwind (review L1).
    fn call_guard<R>(&mut self, who: &str, results: Vec<PromiseResult>, f: impl FnOnce(&mut Guard) -> R) -> (Option<R>, Vec<near_sdk::mock::Receipt>) {
        let saved = self.storage.clone();
        let block = self.block;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            install(saved.clone(), who, block, results);
            let out = with_guard(f);
            let receipts = near_sdk::mock::with_mocked_blockchain(|b| b.created_receipts());
            (out, receipts, take_storage())
        }));
        match r {
            Ok((out, receipts, storage)) => {
                self.storage = storage;
                (Some(out), receipts)
            }
            Err(_) => {
                self.storage = saved;
                (None, vec![])
            }
        }
    }

    /// Execute pending item `idx` with the scheduler's choices `c`.
    pub fn step_with(&mut self, idx: usize, c: Choice, pay_accepted: Option<bool>) {
        let transfer_ok = c.ok;
        let item = self.pending.remove(idx);
        // Base world: one block per step (unchanged). Full world (2026-11-11): time moves only
        // when the owner waits RECONCILE_MIN_BLOCKS. The guard reads the block height only for
        // pending_since_block and that waiting rule, so this keeps every behaviour the rule
        // can tell apart ("too early" vs "waited"), while letting equal states merge.
        if !self.full {
            self.block += 1;
        }
        match item {
            Item::Pay { inv } => {
                let before = self.status(inv);
                let accepted = match pay_accepted {
                    Some(a) => {
                        if a {
                            let (t, c) = self.run_pay_unchecked(inv);
                            self.pending.push(t);
                            self.pending.push(c);
                        }
                        a
                    }
                    None => {
                        let saved = self.storage.clone();
                        // Only the guard's own call is inside catch_unwind (review L1):
                        // a panic here is the guard refusing. Decoding the receipts is
                        // outside it, so a decoder failure is an error, not a refusal.
                        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.call_pay(inv)));
                        match r {
                            Ok((receipts, storage)) => {
                                let (t, c) = self.accept_pay(inv, &receipts, storage);
                                self.pending.push(t);
                                self.pending.push(c);
                                true
                            }
                            Err(_) => {
                                // Refused: NEAR rolls the call back. Keep the old storage.
                                self.storage = saved;
                                false
                            }
                        }
                    }
                };
                self.trace.push(if accepted {
                    Event::PayAccepted { inv, status_before: before }
                } else {
                    Event::PayRefused { inv, status_before: before }
                });
                // Lockstep: the model must accept/refuse the same pay, and name the
                // same amount as the ft_transfer receipt the real guard created.
                let m = self.model.pay(inv, self.block);
                if m.is_ok() != accepted {
                    self.mismatches.push(format!("pay({}) real accepted={accepted} model={m:?}", INVOICES[inv].0));
                }
                if let (Ok(m_amount), true) = (m, accepted) {
                    let real_amount = self.pending.iter().rev().find_map(|i| match i {
                        Item::Transfer { amount, .. } => Some(*amount),
                        _ => None,
                    });
                    if real_amount != Some(m_amount) {
                        self.mismatches.push(format!("pay({}) receipt amount real={real_amount:?} model={m_amount}", INVOICES[inv].0));
                    }
                }
                self.compare_with_model();
            }
            Item::Transfer { inv, tag, receiver, amount } => {
                assert_eq!(receiver, INVOICES[inv].1, "guard sent to an unexpected receiver");
                // The token refuses a transfer the guard cannot cover (full world tracks it).
                let transfer_ok = transfer_ok && (!self.full || self.guard_balance >= amount);
                if transfer_ok && self.full {
                    self.guard_balance -= amount;
                }
                if transfer_ok {
                    self.sent[inv] += amount;
                    self.trace.push(Event::TransferOk { inv, amount });
                } else {
                    self.trace.push(Event::TransferFailed { inv });
                }
                // Its callback becomes runnable now, carrying the outcome.
                for it in self.pending.iter_mut() {
                    if let Item::Callback { tag: t, outcome, .. } = it {
                        if *t == tag {
                            *outcome = Some(transfer_ok);
                        }
                    }
                }
            }
            Item::Callback { inv, outcome, .. } if c.dies && self.deaths_left > 0 => {
                // Out of gas, or a panic: every write is rolled back. Nothing changes.
                let _ = outcome.expect("callback ran before its transfer");
                self.deaths_left -= 1;
                self.touched[inv] = true;
                self.trace.push(Event::CallbackDied { inv });
                self.compare_with_model();
            }
            Item::Callback { inv, outcome, .. } => {
                let ok = outcome.expect("callback ran before its transfer");
                let results = vec![if ok { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed }];
                install(self.storage.clone(), GUARD, self.block, results);
                with_guard(|g| g.on_transfer(INVOICES[inv].0.to_string()));
                self.storage = take_storage();
                let after = self.status(inv);
                self.trace.push(Event::CallbackRan { inv, ok, status_after: after });
                self.model.on_transfer(inv, ok);
                self.compare_with_model();
            }
            Item::Reconcile => {
                let inv = c.inv;
                if c.wait {
                    self.block += WAIT_BLOCKS;
                }
                let id = INVOICES[inv].0.to_string();
                let (r, receipts) = self.call_guard(OWNER, vec![], |g| drop(g.reconcile(id)));
                let accepted = r.is_some();
                if accepted {
                    let epoch = decode_reconcile_receipts(inv, &receipts);
                    self.pending.push(Item::BalanceRead { inv, epoch });
                }
                self.trace.push(Event::ReconcileSent { inv, accepted, waited: c.wait });
                let m = self.model.reconcile(inv, self.block);
                if m.is_ok() != accepted {
                    self.mismatches.push(format!("reconcile({}) real accepted={accepted} model={m:?}", INVOICES[inv].0));
                }
                self.compare_with_model();
            }
            Item::BalanceRead { inv, epoch } => {
                let balance = self.guard_balance;
                self.trace.push(Event::BalanceRead { inv, balance });
                self.pending.push(Item::OnReconcile { inv, epoch, balance });
            }
            Item::OnReconcile { inv, epoch, balance } => {
                let id = INVOICES[inv].0.to_string();
                let (r, _) = self.call_guard(GUARD, vec![], |g| g.on_reconcile(id, epoch, Ok(U128(balance))));
                let accepted = r.is_some();
                let after = self.status(inv);
                if accepted {
                    self.touched[inv] = true;
                }
                self.trace.push(Event::OnReconcile { inv, accepted, status_after: after });
                let m = self.model.on_reconcile(inv, epoch, Some(balance));
                match (m, r) {
                    (Ok(ms), Some(rs)) if ms == mstatus(rs) => {}
                    (Err(_), None) => {}
                    (m, r) => self.mismatches.push(format!("on_reconcile({}) real={r:?} model={m:?}", INVOICES[inv].0)),
                }
                self.compare_with_model();
            }
            Item::Resolve => {
                let inv = c.inv;
                if c.wait {
                    self.block += WAIT_BLOCKS;
                }
                let id = INVOICES[inv].0.to_string();
                let sent = c.sent;
                let (r, _) = self.call_guard(OWNER, vec![], |g| g.resolve_stuck(id, sent));
                let accepted = r.is_some();
                if accepted {
                    self.touched[inv] = true;
                }
                let after = self.status(inv);
                self.trace.push(Event::Resolve { inv, sent, waited: c.wait, accepted, status_after: after });
                let m = self.model.resolve_stuck(inv, sent, self.block);
                match (m, r) {
                    (Ok(ms), Some(rs)) if ms == mstatus(rs) => {}
                    (Err(_), None) => {}
                    (m, r) => self.mismatches.push(format!("resolve_stuck({}) real={r:?} model={m:?}", INVOICES[inv].0)),
                }
                self.compare_with_model();
            }
            Item::Outside => {
                self.guard_balance += DONATION;
                self.trace.push(Event::Outside { balance_after: self.guard_balance });
            }
        }
    }
}

pub fn mstatus(s: Status) -> MStatus {
    match s {
        Status::Approved => MStatus::Approved,
        Status::Pending => MStatus::Pending,
        Status::Paid => MStatus::Paid,
        Status::Failed => MStatus::Failed,
    }
}

/// `reconcile` must create exactly: ft_balance_of(guard) on the token, then
/// on_reconcile(id, epoch_at_start) on the guard. Returns that epoch. A malformed receipt
/// stops the run loudly (outside catch_unwind).
fn decode_reconcile_receipts(inv: usize, receipts: &[near_sdk::mock::Receipt]) -> u64 {
    let mut read = false;
    let mut epoch = None;
    for r in receipts {
        for a in &r.actions {
            if let MockAction::FunctionCallWeight { method_name, args, .. } = a {
                let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).expect("json args");
                match (r.receiver_id.as_str(), method_name.as_slice()) {
                    (TOKEN, b"ft_balance_of") => {
                        assert_eq!(v["account_id"].as_str(), Some(GUARD), "balance read of another account");
                        read = true;
                    }
                    (GUARD, b"on_reconcile") => {
                        assert_eq!(v["id"].as_str(), Some(INVOICES[inv].0), "on_reconcile for another invoice");
                        epoch = Some(v["epoch_at_start"].as_u64().expect("epoch_at_start"));
                    }
                    other => panic!("unexpected receipt from reconcile {other:?}"),
                }
            }
        }
    }
    assert!(read, "reconcile created no ft_balance_of");
    epoch.expect("reconcile created no on_reconcile")
}


/// Turn the two receipts `pay` created into a transfer item and a callback item.
/// When the guard's `pay` accepts, per its own source (`contracts/guard/src/lib.rs`):
/// both modes refuse `Paid` (line "invoice already paid"); `fixed` also refuses
/// `Pending` ("payment already in flight"). The Kani driver trusts this; the
/// exhaustive driver checks it against the real `pay` on every schedule.
pub fn pay_would_be_accepted(mode: Mode, status: Status) -> bool {
    match mode {
        Mode::VulnerableFixture => status != Status::Paid,
        Mode::Fixed => status == Status::Approved,
    }
}

fn decode_receipts(inv: usize, tag: usize, receipts: &[near_sdk::mock::Receipt]) -> (Item, Item) {
    let mut transfer = None;
    let mut callback = None;
    for r in receipts {
        for a in &r.actions {
            if let MockAction::FunctionCallWeight { method_name, args, .. } = a {
                let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).expect("json args");
                match (r.receiver_id.as_str(), method_name.as_slice()) {
                    (TOKEN, b"ft_transfer") => {
                        let receiver = v["receiver_id"].as_str().expect("receiver_id").to_string();
                        let amount: u128 = v["amount"].as_str().expect("amount").parse().expect("u128");
                        transfer = Some(Item::Transfer { inv, tag, receiver, amount });
                    }
                    (GUARD, b"on_transfer") => {
                        assert_eq!(v["id"].as_str(), Some(INVOICES[inv].0), "callback for another invoice");
                        callback = Some(Item::Callback { inv, tag, outcome: None });
                    }
                    other => panic!("unexpected receipt {other:?}"),
                }
            }
        }
    }
    (transfer.expect("pay created no ft_transfer"), callback.expect("pay created no callback"))
}

/// Feasibility probe (kept as a record: Kani 0.68.0 hit an internal compiler error
/// compiling this crate, see evidence/proofs-2026-11-10/kani-feasibility-probe.log).
/// Feasibility probe: can Kani run the real guard on near-sdk's mocked chain at all?
/// One setup, one pay, one transfer outcome, one callback.
#[cfg(kani)]
mod kani_probe {
    use super::*;
    #[kani::proof]
    #[kani::unwind(4)]
    fn probe_one_pay() {
        let mut w = World::new(Mode::Fixed, &[0]);
        let ok: bool = kani::any();
        w.step(0, true, Some(true));
        w.step(0, ok, None.or(Some(true)));
        w.step(0, true, Some(true));
        assert!(w.sent[0] <= INVOICES[0].2);
    }
}
