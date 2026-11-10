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
//! Two drivers use this world:
//! - `tests/exhaustive.rs` (plain Rust): tries every schedule, really calls `pay` every
//!   time and catches the panic of a refused one.
//! - `src/kani_harness.rs` (Kani): the scheduler choices are `kani::any()`. Kani cannot
//!   catch a panic, so a `pay` is only run when [`pay_would_be_accepted`] says so, and
//!   the exhaustive run checks that rule against the real `pay` on every schedule.

#[cfg(not(feature = "mutant"))]
pub use guard::{Guard, Mode, Status};
#[cfg(feature = "mutant")]
pub use guard_mutant::{Guard, Mode, Status};
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
}

/// What happened in one step (for readable traces).
#[derive(Clone, Debug)]
pub enum Event {
    PayAccepted { inv: usize, status_before: Status },
    PayRefused { inv: usize, status_before: Status },
    TransferOk { inv: usize, amount: u128 },
    TransferFailed { inv: usize },
    CallbackRan { inv: usize, ok: bool, status_after: Status },
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
}

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
        let storage = take_storage();
        World {
            mode,
            storage,
            pending: pays.iter().map(|&inv| Item::Pay { inv }).collect(),
            sent: [0; NINV],
            block: 3,
            trace: Vec::new(),
            next_tag: 0,
            model: Model::new(
                if mode == Mode::Fixed { MMode::Fixed } else { MMode::VulnerableFixture },
                [INVOICES[0].2, INVOICES[1].2],
                // LOCKSTEP_SELFTEST=1 gives the model the OPPOSITE mutant flag from the
                // real build, so the lockstep check must report mismatches (it has teeth).
                cfg!(feature = "mutant") ^ std::env::var_os("LOCKSTEP_SELFTEST").is_some(),
            ),
            mismatches: Vec::new(),
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
    pub fn key(&self) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<(u8, usize, String, u128, u8)>, [u128; NINV], Model<NINV>) {
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
            })
            .collect();
        pend.sort();
        (st, pend, self.sent, self.model)
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
            let rs = match r.status {
                Status::Approved => MStatus::Approved,
                Status::Pending => MStatus::Pending,
                Status::Paid => MStatus::Paid,
            };
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
        if ledger.expected_balance.is_some() {
            diffs.push("ledger: expected_balance set, the model assumes None".into());
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

    /// Run a `pay` that is expected to be accepted. Returns the receipts it created,
    /// turned into waiting items. Panics (inside the guard) if the guard refuses.
    fn run_pay_unchecked(&mut self, inv: usize) -> (Item, Item) {
        install(self.storage.clone(), AGENT, self.block, vec![]);
        let promise = with_guard(|g| g.pay(INVOICES[inv].0.to_string()));
        drop(promise); // the Promise schedules its receipts when dropped
        let receipts = near_sdk::mock::with_mocked_blockchain(|b| b.created_receipts());
        let storage = take_storage();
        self.storage = storage;
        let tag = self.next_tag;
        self.next_tag += 1;
        decode_receipts(inv, tag, &receipts)
    }

    /// Execute pending item `idx`. For a transfer, `transfer_ok` picks its outcome.
    /// `pay_accepted`: Some(answer) means "trust this answer about whether the guard
    /// accepts this pay" (the Kani driver); None means "really call pay and catch a
    /// refusal" (the exhaustive driver, which then also checks the answer).
    pub fn step(&mut self, idx: usize, transfer_ok: bool, pay_accepted: Option<bool>) {
        let item = self.pending.remove(idx);
        self.block += 1;
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
                        let mut probe = self.clone();
                        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| probe.run_pay_unchecked(inv)));
                        match r {
                            Ok((t, c)) => {
                                self.storage = probe.storage;
                                self.next_tag = probe.next_tag;
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
        }
    }
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
