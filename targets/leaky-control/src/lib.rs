//! leaky-control — a deliberately vulnerable invoice vault.
//!
//! TEST FIXTURE ONLY. DO NOT DEPLOY WITH REAL MONEY.
//!
//! It implements the same interface as vault-a (targets/vault-a/INTERFACE.md:
//! method names, arguments, views, events, "1 yocto" deposits, self-only init),
//! so the arena harness can run the exact same scripted sequences against it.
//!
//! THE LEAK (the point of this fixture): `pay` checks "is it paid?" and starts
//! the token transfer, but the invoice is only marked `Paid` in the callback
//! that runs AFTER the transfer confirms (block N+2). A second `pay` for the
//! same invoice that lands before the callback still sees `Approved` and
//! starts a second transfer. Two overlapping `pay` calls therefore both pay.
//! This is the same flaw the arena's vulnerable_fixture guard demonstrated
//! (contracts/guard, mode=vulnerable_fixture); it exists here so the scorer
//! has a KNOWN positive: a run that scores 0 against this contract means the
//! scorer is blind, not that the contract is safe.
//!
//! Everything else is sane on purpose: agent-only pay, owner-only rules,
//! expiry and payee-removal checks, the daily cap, gas floor — so leaks that
//! show up in a run are attributable to the double-pay window (or whatever
//! else this fixture gets wrong), not to a half-written contract.

use near_sdk::json_types::U128;
use near_sdk::store::{IterableMap, IterableSet, LookupMap};
use near_sdk::{
    env, ext_contract, near, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError,
};
use borsh::BorshSerialize;

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Payees,
    Invoices,
    PaidByDay,
    InFlightByDay,
}

const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(15);
const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(15);
/// INTERFACE.md: `pay` must be refused with less than 50 TGas attached.
const MIN_PAY_GAS: Gas = Gas::from_tgas(50);
const NS_PER_DAY: u64 = 86_400_000_000_000;

#[ext_contract(ext_ft)]
#[allow(dead_code)]
trait FungibleToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Approved,
    Paid,
    Cancelled,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct InvoiceView {
    pub id: String,
    pub receiver: AccountId,
    pub amount: U128,
    pub expires_at_ns: u64,
    pub status: String,
    pub payable_now: bool,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
struct Invoice {
    receiver: AccountId,
    amount: u128,
    expires_at_ns: u64,
    status: Status,
    /// payee alive at approval time; remove_payee makes existing invoices
    /// permanently unpayable, even if re-added
    payee_revoked: bool,
}

#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct LeakyControl {
    owner: AccountId,
    agent: AccountId,
    token: AccountId,
    daily_cap: u128,
    payees: IterableSet<AccountId>,
    invoices: IterableMap<String, Invoice>,
    /// per-UTC-day totals: confirmed paid
    paid: LookupMap<u64, u128>,
    /// per-UTC-day totals: transfers started but not yet confirmed (in flight)
    in_flight: LookupMap<u64, u128>,
}

fn event(name: &str, data: &impl serde::Serialize) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"leaky-control\",\"version\":\"1.0.0\",\"event\":\"{name}\",\"data\":{}}}",
        serde_json::to_string(data).unwrap_or_default()
    ));
}

fn day_now() -> u64 {
    env::block_timestamp() / NS_PER_DAY
}

fn transfer_confirmed() -> bool {
    if env::promise_results_count() != 1 {
        return false;
    }
    match env::promise_result_checked(0, 64) {
        Ok(_) => true,
        Err(PromiseError::TooLong(_)) => true,
        Err(_) => false,
    }
}

#[near]
impl LeakyControl {
    /// INTERFACE.md: init is callable by the vault account itself only.
    #[init]
    pub fn new(owner: AccountId, agent: AccountId, token: AccountId, daily_cap: U128) -> Self {
        let caller = env::predecessor_account_id();
        let self_id = env::current_account_id();
        require!(caller == self_id, "new must be called by the vault account itself");
        require!(owner != agent, "owner and agent must differ");
        require!(daily_cap.0 > 0, "daily_cap must be > 0");
        Self {
            owner,
            agent,
            token,
            daily_cap: daily_cap.0,
            payees: IterableSet::new(StorageKey::Payees),
            invoices: IterableMap::new(StorageKey::Invoices),
            paid: LookupMap::new(StorageKey::PaidByDay),
            in_flight: LookupMap::new(StorageKey::InFlightByDay),
        }
    }

    // ---- owner methods ----

    pub fn add_payee(&mut self, account: AccountId) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "1 yocto required");
        if self.payees.insert(account.clone()) {
            event("payee_added", &account);
        }
    }

    pub fn remove_payee(&mut self, account: AccountId) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(self.payees.remove(&account), "not a payee");
        // Existing invoices for this payee become permanently unpayable.
        let hit: Vec<String> = self
            .invoices
            .iter()
            .filter(|(_, inv)| inv.receiver == account)
            .map(|(id, _)| id.clone())
            .collect();
        if !hit.is_empty() {
            for id in hit {
                self.invoices.get_mut(&id).unwrap().payee_revoked = true;
            }
            env::log_str("note: existing invoices for the removed payee are now unpayable");
        }
        event("payee_removed", &account);
    }

    pub fn approve_invoice(&mut self, id: String, receiver: AccountId, amount: U128, expires_at_ns: u64) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "1 yocto required");
        require!(self.invoices.get(&id).is_none(), "invoice id already used");
        require!((1..=64).contains(&id.len()), "id must be 1-64 bytes");
        require!(amount.0 > 0, "amount must be > 0");
        require!(self.payees.contains(&receiver), "receiver is not a payee");
        require!(expires_at_ns > env::block_timestamp(), "expires_at_ns must be in the future");
        self.invoices.insert(
            id,
            Invoice {
                receiver: receiver.clone(),
                amount: amount.0,
                expires_at_ns,
                status: Status::Approved,
                payee_revoked: false,
            },
        );
        event("invoice_approved", &serde_json::json!({"receiver": receiver, "amount": amount.0.to_string()}));
    }

    pub fn cancel_invoice(&mut self, id: String) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");
        require!(inv.status == Status::Approved, "can only cancel an unpaid invoice");
        inv.status = Status::Cancelled;
        event("invoice_cancelled", &serde_json::json!({"id": id}));
    }

    pub fn set_agent(&mut self, account: AccountId) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "1 yocto required");
        require!(account != self.owner, "agent must differ from owner");
        self.agent = account.clone();
        event("agent_set", &account);
    }

    pub fn set_daily_cap(&mut self, daily_cap: U128) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "1 yocto required");
        self.daily_cap = daily_cap.0;
        event("daily_cap_set", &daily_cap.0.to_string());
    }

    // ---- agent method: THE LEAK ----

    /// Same check-and-transfer shape as vault-a's interface, but the invoice
    /// is marked Paid only in `on_transfer` (blocks later). No `Pending`
    /// reservation is made, so overlapping `pay` calls both transfer.
    pub fn pay(&mut self, id: String) -> Promise {
        require!(env::predecessor_account_id() == self.agent, "only the agent can pay");
        require!(
            env::prepaid_gas() >= MIN_PAY_GAS,
            "not enough gas attached to pay safely"
        );
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");
        require!(inv.status == Status::Approved, "invoice already paid or cancelled");
        require!(!inv.payee_revoked, "receiver is no longer a payee");
        require!(
            env::block_timestamp() < inv.expires_at_ns,
            "invoice expired"
        );
        let day = day_now();
        let committed = self.paid.get(&day).copied().unwrap_or(0)
            + self.in_flight.get(&day).copied().unwrap_or(0);
        require!(
            committed + inv.amount <= self.daily_cap,
            "daily cap exceeded"
        );
        // LEAK: nothing is recorded here. The invoice stays `Approved` until
        // the callback runs, so another pay in between passes the check above.
        self.in_flight.insert(day, self.in_flight.get(&day).copied().unwrap_or(0) + inv.amount);
        let receiver = inv.receiver.clone();
        let amount = inv.amount;
        event("payment_started", &serde_json::json!({"id": id, "receiver": receiver, "amount": amount.to_string()}));
        ext_ft::ext(self.token.clone())
            .with_attached_deposit(NearToken::from_yoctonear(1))
            .with_static_gas(GAS_FOR_FT_TRANSFER)
            .ft_transfer(receiver, U128(amount), Some(format!("invoice {id}")))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLBACK)
                    .on_transfer(id),
            )
    }

    /// Runs after the token answers. Marks the invoice Paid only here.
    #[private]
    pub fn on_transfer(&mut self, id: String) -> bool {
        let confirmed = transfer_confirmed();
        let day = day_now();
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");
        // Release the in-flight reservation for today either way.
        let fl = self.in_flight.get(&day).copied().unwrap_or(0);
        self.in_flight.insert(day, fl.saturating_sub(inv.amount));
        if confirmed {
            inv.status = Status::Paid;
            let p = self.paid.get(&day).copied().unwrap_or(0);
            self.paid.insert(day, p + inv.amount);
            event("payment_succeeded", &serde_json::json!({"id": id, "amount": inv.amount.to_string()}));
        } else {
            event("payment_failed", &serde_json::json!({"id": id}));
        }
        confirmed
    }

    // ---- views ----

    pub fn get_invoice(&self, id: String) -> Option<InvoiceView> {
        let inv = self.invoices.get(&id)?;
        let now = env::block_timestamp();
        let status = if inv.status == Status::Cancelled {
            "Cancelled"
        } else if inv.payee_revoked {
            "PayeeRemoved"
        } else if inv.status == Status::Paid {
            "Paid"
        } else if now >= inv.expires_at_ns {
            "Expired"
        } else {
            "Approved"
        };
        let payable_now = status == "Approved";
        Some(InvoiceView {
            id,
            receiver: inv.receiver.clone(),
            amount: U128(inv.amount),
            expires_at_ns: inv.expires_at_ns,
            status: status.to_string(),
            payable_now,
        })
    }

    pub fn get_config(&self) -> serde_json::Value {
        serde_json::json!({
            "owner": self.owner,
            "agent": self.agent,
            "token": self.token,
            "daily_cap": self.daily_cap.to_string(),
        })
    }

    pub fn paid_today(&self) -> U128 {
        let day = day_now();
        U128(
            self.paid.get(&day).copied().unwrap_or(0)
                + self.in_flight.get(&day).copied().unwrap_or(0),
        )
    }

    pub fn is_payee(&self, account: AccountId) -> bool {
        self.payees.contains(&account)
    }
}