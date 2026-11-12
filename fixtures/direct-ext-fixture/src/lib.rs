//! direct-ext-fixture: a TEST FIXTURE for Arena's extended direct mode. Not a guard anyone should use.
//!
//! One guard whose interface can be switched, at init, between the shapes other teams' guards use,
//! so Arena's self-tests can prove each new config capability by behaviour, both ways: the right
//! mapping must validate, a wrong one must be refused (docs/CHECK-YOUR-GUARD.md, "Extended direct
//! mode"). The options (all in `new(owner, agent, opts)`):
//!
//! signer   "account"   the agent is its own account (`predecessor == agent`)
//!          "guard_key" the agent is a key on THIS account: `predecessor == current account` and
//!                      `signer_account_pk` must be the key the owner registered with
//!                      `add_agent_key(public_key)`. If `installs_key` is true that call also adds
//!                      the key to this account, limited to `pay`; otherwise Arena must add it.
//! payees   "in_policy" the allowlist is part of `set_limits`
//!          "per_call"  the allowlist is filled one account per `add_payee` call (`remove_payee`)
//! window   {"kind": "utc_day" | "rolling" | "anchored" | "lifetime", "secs": N}
//!          utc_day: the total restarts at 00:00 UTC; rolling: payments older than N seconds no
//!          longer count; anchored: the total restarts every N seconds counted from init;
//!          lifetime: the total never restarts.
//! one_yocto owner methods require exactly 1 yoctoNEAR attached
//! sig_pk   if set, every `pay` must carry `nonce` (used once) and `signature` (base64 ed25519 by
//!          this key over "arena-fixture:v1|<this account>|<receiver>|<amount>|<nonce>")
//! versioned every `set_limits` must carry a `version` greater than the last one (a policy cannot be
//!          edited, only replaced under a fresh id), and every `pay` must name the current version
//! defect   one deliberate defect for negative self-tests, or "none":
//!          "skip_signature"  accepts any signature
//!          "any_key"         (guard_key) accepts any key on this account, registered or not
//!          "cap_race"        a payment paid at once is charged to the window only when its
//!                            transfer settles (in the callback), so payments sent together all
//!                            pass the window check before any of them is counted
use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, serde_json, AccountId, Allowance, Gas, NearToken, PanicOnDefault, Promise, PromiseResult, PublicKey};
use std::collections::{BTreeMap, BTreeSet};

const DAY_NS: u64 = 86_400_000_000_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
#[near(serializers = [borsh])]
pub struct Window {
    pub kind: String,
    pub secs: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
#[near(serializers = [borsh])]
pub struct Opts {
    pub signer: String,
    #[serde(default)]
    pub installs_key: bool,
    pub payees: String,
    pub window: Window,
    #[serde(default)]
    pub one_yocto: bool,
    #[serde(default)]
    pub sig_pk: Option<PublicKey>,
    #[serde(default)]
    pub versioned: bool,
    #[serde(default = "none")]
    pub defect: String,
}

fn none() -> String {
    "none".into()
}

#[near(serializers = [borsh])]
#[derive(Clone)]
pub struct Req {
    receiver: AccountId,
    amount: u128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Fixture {
    owner: AccountId,
    agent: AccountId,
    opts: Opts,
    agent_key: Option<PublicKey>,
    per_payment: u128,
    window_limit: u128,
    approval_above: u128,
    allowlist: BTreeSet<AccountId>,
    /// (block ns, amount) of every charge still counted
    charges: Vec<(u64, u128)>,
    /// utc_day / anchored: the current period number and its total
    period: u64,
    period_total: u128,
    anchor: u64,
    pending: BTreeMap<u64, Req>,
    used_nonces: BTreeSet<u64>,
    next_id: u64,
    version: Option<u64>,
}

#[near]
impl Fixture {
    #[init]
    #[private]
    pub fn new(owner: AccountId, agent: AccountId, opts: Opts) -> Self {
        assert!(["account", "guard_key"].contains(&opts.signer.as_str()), "E_OPT_SIGNER");
        assert!(["in_policy", "per_call"].contains(&opts.payees.as_str()), "E_OPT_PAYEES");
        assert!(["utc_day", "rolling", "anchored", "lifetime"].contains(&opts.window.kind.as_str()), "E_OPT_WINDOW");
        assert!(["none", "skip_signature", "any_key", "cap_race"].contains(&opts.defect.as_str()), "E_OPT_DEFECT");
        let now = env::block_timestamp();
        Self {
            owner, agent, opts, agent_key: None, per_payment: 0, window_limit: 0, approval_above: 0,
            allowlist: BTreeSet::new(), charges: Vec::new(), period: 0, period_total: 0, anchor: now,
            pending: BTreeMap::new(), used_nonces: BTreeSet::new(), next_id: 1, version: None,
        }
    }

    #[payable]
    pub fn add_agent_key(&mut self, public_key: PublicKey) {
        self.owner_only();
        assert_eq!(self.opts.signer, "guard_key", "E_NOT_KEY_MODE");
        self.agent_key = Some(public_key.clone());
        if self.opts.installs_key {
            Promise::new(env::current_account_id()).add_access_key_allowance(
                public_key,
                Allowance::limited(NearToken::from_near(5)).unwrap(),
                env::current_account_id(),
                "pay".to_string(),
            );
        }
    }

    #[payable]
    pub fn set_limits(&mut self, per_payment: U128, window_limit: U128, approval_above: U128, allowlist: Option<Vec<AccountId>>, version: Option<u64>) {
        self.owner_only();
        if self.opts.versioned {
            let v = version.expect("E_VERSION_REQUIRED");
            assert!(self.version.map_or(true, |old| v > old), "E_VERSION_EXISTS");
            self.version = Some(v);
        }
        self.per_payment = per_payment.0;
        self.window_limit = window_limit.0;
        self.approval_above = approval_above.0;
        if self.opts.payees == "in_policy" {
            self.allowlist = allowlist.expect("E_ALLOWLIST_REQUIRED").into_iter().collect();
        }
    }

    #[payable]
    pub fn add_payee(&mut self, account: AccountId) {
        self.owner_only();
        assert_eq!(self.opts.payees, "per_call", "E_NOT_PER_CALL");
        self.allowlist.insert(account);
    }

    #[payable]
    pub fn remove_payee(&mut self, account: AccountId) {
        self.owner_only();
        assert_eq!(self.opts.payees, "per_call", "E_NOT_PER_CALL");
        self.allowlist.remove(&account);
    }

    pub fn pay(&mut self, receiver: AccountId, amount: U128, memo: Option<String>, nonce: Option<U64>, signature: Option<Base64VecU8>, version: Option<u64>) -> serde_json::Value {
        let _ = memo;
        self.agent_only();
        if self.opts.versioned {
            assert_eq!(version, self.version, "E_STALE_VERSION");
        }
        if let Some(pk) = self.opts.sig_pk.clone() {
            let n = nonce.expect("E_NONCE_REQUIRED").0;
            assert!(!self.used_nonces.contains(&n), "E_NONCE_USED");
            if self.opts.defect != "skip_signature" {
                let sig: [u8; 64] = signature.expect("E_SIGNATURE_REQUIRED").0.try_into().expect("E_SIGNATURE_LEN");
                let msg = format!("arena-fixture:v1|{}|{}|{}|{}", env::current_account_id(), receiver, amount.0, n);
                let key: [u8; 32] = pk.as_bytes()[1..].try_into().expect("E_KEY");
                assert!(env::ed25519_verify(&sig, msg.as_bytes(), &key), "E_BAD_SIGNATURE");
            }
            self.used_nonces.insert(n);
        }
        assert!(amount.0 > 0, "E_AMOUNT");
        assert!(self.allowlist.contains(&receiver), "E_NOT_ALLOWLISTED");
        assert!(amount.0 <= self.per_payment, "E_PER_PAYMENT");
        assert!(self.counted() + amount.0 <= self.window_limit, "E_WINDOW");
        let id = self.next_id;
        self.next_id += 1;
        if amount.0 > self.approval_above {
            self.charge(amount.0);
            self.pending.insert(id, Req { receiver, amount: amount.0 });
            return serde_json::json!({"status": "pending", "id": U64(id)});
        }
        let late = self.opts.defect == "cap_race";
        if !late {
            self.charge(amount.0);
        }
        self.send_settle(receiver, amount.0, late);
        serde_json::json!({"status": "paid", "id": U64(id)})
    }

    #[payable]
    pub fn approve(&mut self, id: U64) {
        self.owner_only();
        let r = self.pending.remove(&id.0).expect("E_REQUEST");
        self.send_settle(r.receiver, r.amount, false);
    }

    #[payable]
    pub fn reject(&mut self, id: U64) {
        self.owner_only();
        let r = self.pending.remove(&id.0).expect("E_REQUEST");
        self.uncharge(r.amount);
    }

    #[private]
    pub fn on_transfer(&mut self, amount: U128, charge_now: Option<bool>) -> bool {
        let ok = env::promise_results_count() == 1 && matches!(env::promise_result(0), PromiseResult::Successful(_));
        if charge_now == Some(true) {
            if ok {
                self.charge(amount.0);
            }
        } else if !ok {
            self.uncharge(amount.0);
        }
        ok
    }

    pub fn get_counted(&self) -> U128 {
        U128(self.counted())
    }
}

impl Fixture {
    fn owner_only(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "E_OWNER");
        if self.opts.one_yocto {
            assert_eq!(env::attached_deposit(), NearToken::from_yoctonear(1), "E_ONE_YOCTO");
        } else {
            assert_eq!(env::attached_deposit(), NearToken::from_yoctonear(0), "E_NO_DEPOSIT");
        }
    }
    fn agent_only(&self) {
        assert_eq!(env::attached_deposit(), NearToken::from_yoctonear(0), "E_NO_DEPOSIT");
        if self.opts.signer == "account" {
            assert_eq!(env::predecessor_account_id(), self.agent, "E_NOT_AGENT");
        } else {
            assert_eq!(env::predecessor_account_id(), env::current_account_id(), "E_NOT_AGENT_KEY");
            if self.opts.defect != "any_key" {
                assert_eq!(Some(env::signer_account_pk()), self.agent_key, "E_UNKNOWN_KEY");
            }
        }
    }
    fn period_of(&self, now: u64) -> u64 {
        match self.opts.window.kind.as_str() {
            "utc_day" => now / DAY_NS,
            "anchored" => (now - self.anchor) / (self.opts.window.secs * 1_000_000_000),
            _ => 0,
        }
    }
    fn counted(&self) -> u128 {
        let now = env::block_timestamp();
        match self.opts.window.kind.as_str() {
            "rolling" => {
                let from = now.saturating_sub(self.opts.window.secs * 1_000_000_000);
                self.charges.iter().filter(|(t, _)| *t > from).map(|(_, a)| a).sum()
            }
            "lifetime" => self.period_total,
            _ => if self.period_of(now) == self.period { self.period_total } else { 0 },
        }
    }
    fn charge(&mut self, amount: u128) {
        let now = env::block_timestamp();
        match self.opts.window.kind.as_str() {
            "rolling" => self.charges.push((now, amount)),
            "lifetime" => self.period_total += amount,
            _ => {
                let p = self.period_of(now);
                if p != self.period {
                    self.period = p;
                    self.period_total = 0;
                }
                self.period_total += amount;
            }
        }
    }
    fn uncharge(&mut self, amount: u128) {
        match self.opts.window.kind.as_str() {
            "rolling" => {
                if let Some(i) = self.charges.iter().rposition(|(_, a)| *a == amount) {
                    self.charges.remove(i);
                }
            }
            _ => self.period_total = self.period_total.saturating_sub(amount),
        }
    }
    fn send_settle(&mut self, to: AccountId, amount: u128, charge_now: bool) {
        Promise::new(to).transfer(NearToken::from_yoctonear(amount)).then(
            Promise::new(env::current_account_id()).function_call(
                "on_transfer",
                serde_json::to_vec(&serde_json::json!({ "amount": U128(amount), "charge_now": charge_now })).unwrap(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(20),
            ),
        );
    }
}
