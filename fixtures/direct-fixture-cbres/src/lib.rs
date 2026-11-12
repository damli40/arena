//! VARIANT of fixtures/direct-fixture (one change: the callback reads the transfer result through #[callback_result], without #[private]).
//! Used by the direct self-tests to check that a forged callback copies the guard's own call.
//! direct-fixture: a TEST FIXTURE for Arena's direct-payment path. Not a guard anyone should use.
//!
//! It has the same methods and argument shapes as the direct-pay guard Arena tests ("Guard G"):
//! the agent calls `spend(receiver, amount, memo)`, the guard checks an allowlist, a per-payment
//! limit, a UTC-day limit and an approval threshold, then sends plain NEAR and settles in a
//! callback. The `mode` given at init switches on ONE deliberate defect (or none, "correct"),
//! so Arena can check that every defect gives the result its self-tests demand
//! (docs/GUARD-CAPABILITIES.md section 5). Modes:
//!
//! correct            the negative control: enforces every rule
//! noop               spend succeeds and moves nothing
//! constant           always pays 50 milliNEAR to allowlist[0], whatever it is asked
//! wrong_receiver     pays the right amount to the agent itself instead of the receiver
//! double             pays twice the amount asked
//! hold_all           holds every request for approval
//! refuse_all         refuses every request
//! pay_once           pays the first request, refuses every later one
//! ignore_allowlist   never checks the allowlist
//! swap_approve       `approve` rejects and `reject` approves
//! noop_update_policy `update_policy` changes what `get_policy` shows, not what is enforced
//! cap_race           charges the day's total only in the callback (concurrent spends all pass)
//! public_callback    the callback is public, keeps settled records, and a call with no
//!                    transfer result counts as a failed transfer (so it gives budget back)
//! budget_burn        a failed transfer keeps its charge against the day's total
//! refund_twice       a failed transfer gives back twice its amount
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, serde_json, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseResult};
use std::collections::BTreeMap;

const DAY_NS: u64 = 86_400_000_000_000;
const MILLI: u128 = 1_000_000_000_000_000_000_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
#[near(serializers = [borsh])]
pub struct Policy {
    pub per_tx_max: U128,
    pub daily_max: U128,
    pub allowlist: Vec<AccountId>,
    pub approval_threshold: U128,
    pub paused: bool,
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct Agent {
    enforced: Policy,
    shown: Policy,
    day: u64,
    spent: u128,
}

#[derive(Serialize, Clone)]
#[serde(crate = "near_sdk::serde")]
#[near(serializers = [borsh])]
pub struct Request {
    pub id: U64,
    pub agent: AccountId,
    pub receiver: AccountId,
    pub amount: U128,
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct Transfer {
    agent: AccountId,
    amount: u128,
    day: u64,
    settled: bool,
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde", tag = "status", rename_all = "snake_case")]
pub enum SpendResult {
    Transferring { transfer_id: U64 },
    Pending { request_id: U64 },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Fixture {
    owner: AccountId,
    mode: String,
    agents: BTreeMap<AccountId, Agent>,
    pending: BTreeMap<u64, Request>,
    transfers: BTreeMap<u64, Transfer>,
    next_id: u64,
    paid_once: bool,
}

const MODES: [&str; 15] = [
    "correct", "noop", "constant", "wrong_receiver", "double", "hold_all", "refuse_all", "pay_once",
    "ignore_allowlist", "swap_approve", "noop_update_policy", "cap_race", "public_callback", "budget_burn",
    "refund_twice",
];

#[near]
impl Fixture {
    #[init]
    #[private]
    pub fn new(owner: AccountId, mode: String) -> Self {
        assert!(MODES.contains(&mode.as_str()), "E_MODE");
        Self { owner, mode, agents: BTreeMap::new(), pending: BTreeMap::new(), transfers: BTreeMap::new(), next_id: 0, paid_once: false }
    }

    pub fn add_agent(&mut self, agent: AccountId, policy: Policy) {
        self.assert_owner();
        Self::validate_policy(&policy);
        assert!(!self.agents.contains_key(&agent), "E_AGENT_EXISTS");
        self.agents.insert(agent, Agent { enforced: policy.clone(), shown: policy, day: Self::day(), spent: 0 });
    }

    pub fn update_policy(&mut self, agent: AccountId, policy: Policy) {
        self.assert_owner();
        Self::validate_policy(&policy);
        let noop = self.is("noop_update_policy");
        let a = self.agents.get_mut(&agent).expect("E_NOT_AGENT");
        a.shown = policy.clone();
        if !noop {
            a.enforced = policy;
        }
    }

    pub fn spend(&mut self, receiver: AccountId, amount: U128, memo: String) -> SpendResult {
        let _ = memo;
        let agent = env::predecessor_account_id();
        assert_eq!(agent, env::signer_account_id(), "E_NOT_AGENT");
        if self.is("refuse_all") {
            env::panic_str("E_REFUSED");
        }
        if self.is("pay_once") && self.paid_once {
            env::panic_str("E_REFUSED");
        }
        let id = self.alloc();
        if self.is("noop") {
            return SpendResult::Transferring { transfer_id: U64(id) };
        }
        self.validate(&agent, &receiver, amount.0, false);
        let a = self.agents.get(&agent).unwrap().clone();
        let hold = self.is("hold_all") || amount.0 > a.enforced.approval_threshold.0;
        if !self.is("cap_race") {
            self.charge(&agent, amount.0);
        }
        if hold {
            self.pending.insert(id, Request { id: U64(id), agent, receiver, amount });
            return SpendResult::Pending { request_id: U64(id) };
        }
        self.paid_once = true;
        let (to, amt) = match self.mode.as_str() {
            "constant" => (a.enforced.allowlist[0].clone(), 50 * MILLI),
            "wrong_receiver" => (agent.clone(), amount.0),
            "double" => (receiver, amount.0 * 2),
            _ => (receiver, amount.0),
        };
        self.send(id, agent, to, amt, amount.0);
        SpendResult::Transferring { transfer_id: U64(id) }
    }

    pub fn approve(&mut self, request_id: U64) -> U64 {
        self.assert_owner();
        if self.is("swap_approve") {
            self.do_reject(request_id.0);
        } else {
            self.do_approve(request_id.0);
        }
        request_id
    }

    pub fn reject(&mut self, request_id: U64) {
        self.assert_owner();
        if self.is("swap_approve") {
            self.do_approve(request_id.0);
        } else {
            self.do_reject(request_id.0);
        }
    }

    pub fn on_transfer(&mut self, transfer_id: U64, #[callback_result] res: Result<(), near_sdk::PromiseError>) -> bool {
        let public = self.is("public_callback");
        if !public {
            assert_eq!(env::predecessor_account_id(), env::current_account_id(), "E_PRIVATE");
        }
        let ok = res.is_ok();
        let t = self.transfers.get(&transfer_id.0).cloned().expect("E_TRANSFER");
        if public {
            // Defect: a settled record is kept and can be "settled" again by anyone.
            self.transfers.insert(transfer_id.0, Transfer { settled: true, ..t.clone() });
        } else {
            assert!(!t.settled, "E_SETTLED");
            self.transfers.remove(&transfer_id.0);
        }
        if self.is("cap_race") && ok {
            self.charge(&t.agent, t.amount);
        }
        if !ok && !self.is("cap_race") && !self.is("budget_burn") {
            let back = if self.is("refund_twice") { t.amount * 2 } else { t.amount };
            if let Some(a) = self.agents.get_mut(&t.agent) {
                if a.day == t.day {
                    a.spent = a.spent.saturating_sub(back);
                }
            }
        }
        ok
    }

    pub fn get_policy(&self, agent: AccountId) -> Option<Policy> {
        self.agents.get(&agent).map(|a| a.shown.clone())
    }
    pub fn get_spent_today(&self, agent: AccountId) -> U128 {
        U128(self.agents.get(&agent).filter(|a| a.day == Self::day()).map_or(0, |a| a.spent))
    }
    pub fn list_pending(&self) -> Vec<Request> {
        self.pending.values().cloned().collect()
    }
    pub fn get_mode(&self) -> String {
        self.mode.clone()
    }
}

impl Fixture {
    fn is(&self, m: &str) -> bool {
        self.mode == m
    }
    fn day() -> u64 {
        env::block_timestamp() / DAY_NS
    }
    fn alloc(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    fn assert_owner(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "E_OWNER");
    }
    fn validate_policy(p: &Policy) {
        assert!(p.per_tx_max.0 > 0 && p.per_tx_max.0 <= p.daily_max.0, "E_POLICY");
        assert!(p.approval_threshold.0 <= p.per_tx_max.0, "E_POLICY");
    }
    fn validate(&self, agent: &AccountId, receiver: &AccountId, amount: u128, reserved: bool) {
        let a = self.agents.get(agent).expect("E_NOT_AGENT");
        let p = &a.enforced;
        assert!(!p.paused, "E_PAUSED");
        assert!(amount > 0, "E_AMOUNT");
        if !self.is("ignore_allowlist") {
            assert!(p.allowlist.contains(receiver), "E_NOT_ALLOWLISTED");
        }
        assert!(amount <= p.per_tx_max.0, "E_PER_TX");
        let spent = if a.day == Self::day() { a.spent } else { 0 };
        let total = if reserved { spent } else { spent + amount };
        assert!(total <= p.daily_max.0, "E_DAILY");
    }
    fn charge(&mut self, agent: &AccountId, amount: u128) {
        let day = Self::day();
        let a = self.agents.get_mut(agent).unwrap();
        if a.day != day {
            a.day = day;
            a.spent = 0;
        }
        a.spent += amount;
    }
    fn send(&mut self, id: u64, agent: AccountId, to: AccountId, amount: u128, charged: u128) {
        self.transfers.insert(id, Transfer { agent, amount: charged, day: Self::day(), settled: false });
        Promise::new(to).transfer(NearToken::from_yoctonear(amount)).then(
            Promise::new(env::current_account_id()).function_call(
                "on_transfer",
                serde_json::to_vec(&serde_json::json!({ "transfer_id": U64(id) })).unwrap(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(30),
            ),
        );
    }
    fn do_approve(&mut self, id: u64) {
        let r = self.pending.get(&id).cloned().expect("E_REQUEST");
        self.validate(&r.agent, &r.receiver, r.amount.0, true);
        self.pending.remove(&id);
        self.send(id, r.agent, r.receiver, r.amount.0, r.amount.0);
    }
    fn do_reject(&mut self, id: u64) {
        let r = self.pending.remove(&id).expect("E_REQUEST");
        if let Some(a) = self.agents.get_mut(&r.agent) {
            a.spent = a.spent.saturating_sub(r.amount.0);
        }
    }
}
