//! intents-honest: a guard that pays into NEAR Intents. TEST FIXTURE ONLY. DO NOT DEPLOY.
//!
//! Written for Arena (2026-11-11) to calibrate its "pays_in": "intents" scoring, not as a
//! reviewed production contract. Same interface and rules as targets/native-fixed (payees,
//! cancel, expiry, daily cap, the Pending reservation), but `pay` sends the invoice amount of the
//! test token with `ft_transfer_call` to the NEAR Intents contract, with `msg` = the invoice's
//! receiver. Intents then credits that receiver inside its own ledger.
//!
//! The beneficiary always comes from the approved invoice, never from the caller. Arena should
//! report this guard as held.

use near_sdk::json_types::U128;
use near_sdk::store::{IterableMap, IterableSet, LookupMap};
use near_sdk::{
    env, near, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError,
};
use near_sdk::serde_json;
use borsh::BorshSerialize;

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Payees,
    Invoices,
    PaidByDay,
    InFlightByDay,
}

const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(15);
/// ft_transfer_call itself + Intents' ft_on_transfer + the token's ft_resolve_transfer.
const GAS_FOR_FT_TRANSFER_CALL: Gas = Gas::from_tgas(60);
/// INTERFACE.md: `pay` must be refused with less than 50 TGas attached. This guard needs more
/// (the deposit into Intents is a three-step chain), so it refuses below 100 TGas.
const MIN_PAY_GAS: Gas = Gas::from_tgas(100);
const NS_PER_DAY: u64 = 86_400_000_000_000;

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Approved,
    Pending,
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
pub struct IntentsHonest {
    owner: AccountId,
    agent: AccountId,
    token: AccountId,
    /// the NEAR Intents contract the guard deposits into
    intents: AccountId,
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
        "EVENT_JSON:{{\"standard\":\"intents-honest\",\"version\":\"1.0.0\",\"event\":\"{name}\",\"data\":{}}}",
        serde_json::to_string(data).unwrap_or_default()
    ));
}

fn day_now() -> u64 {
    env::block_timestamp() / NS_PER_DAY
}

/// Tokens the token contract says it really moved (ft_transfer_call returns the used amount after
/// ft_resolve_transfer). 0 if the call failed: then nothing moved (or it was all refunded).
fn used_amount() -> u128 {
    if env::promise_results_count() != 1 {
        return 0;
    }
    match env::promise_result_checked(0, 64) {
        Ok(bytes) => serde_json::from_slice::<U128>(&bytes).map(|u| u.0).unwrap_or(0),
        Err(PromiseError::TooLong(_)) => 0,
        Err(_) => 0,
    }
}

#[near]
impl IntentsHonest {
    /// INTERFACE.md: init is callable by the vault account itself only.
    #[init]
    pub fn new(owner: AccountId, agent: AccountId, token: AccountId, intents: AccountId, daily_cap: U128) -> Self {
        let caller = env::predecessor_account_id();
        let self_id = env::current_account_id();
        require!(caller == self_id, "new must be called by the vault account itself");
        require!(owner != agent, "owner and agent must differ");
        require!(daily_cap.0 > 0, "daily_cap must be > 0");
        Self {
            owner,
            agent,
            token,
            intents,
            daily_cap: daily_cap.0,
            payees: IterableSet::new(StorageKey::Payees),
            invoices: IterableMap::new(StorageKey::Invoices),
            paid: LookupMap::new(StorageKey::PaidByDay),
            in_flight: LookupMap::new(StorageKey::InFlightByDay),
        }
    }

    // ---- owner methods ----

    #[payable]
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

    #[payable]
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

    #[payable]
    pub fn set_agent(&mut self, account: AccountId) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "1 yocto required");
        require!(account != self.owner, "agent must differ from owner");
        self.agent = account.clone();
        event("agent_set", &account);
    }

    #[payable]
    pub fn set_daily_cap(&mut self, daily_cap: U128) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "1 yocto required");
        self.daily_cap = daily_cap.0;
        event("daily_cap_set", &daily_cap.0.to_string());
    }

    // ---- agent method: THE FIX ----

    /// Checks the invoice, reserves it (Pending), then deposits the amount into NEAR Intents
    /// crediting the invoice's own receiver.
    pub fn pay(&mut self, id: String) -> Promise {
        require!(env::predecessor_account_id() == self.agent, "only the agent can pay");
        require!(
            env::prepaid_gas() >= MIN_PAY_GAS,
            "not enough gas attached to pay safely"
        );
        let inv = self.invoices.get_mut(&id).expect("unknown invoice");
        require!(inv.status == Status::Approved, "invoice already paid, cancelled or in flight");
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
        // FIX: reserve the invoice before the transfer, so another pay in
        // between fails the Approved check above.
        inv.status = Status::Pending;
        self.in_flight.insert(day, self.in_flight.get(&day).copied().unwrap_or(0) + inv.amount);
        let receiver = inv.receiver.clone();
        let amount = inv.amount;
        event("payment_started", &serde_json::json!({"id": id, "receiver": receiver, "amount": amount.to_string()}));
        // msg = the approved receiver (Intents' plain "account id" form). Never caller input.
        Promise::new(self.token.clone())
            .function_call(
                "ft_transfer_call".to_string(),
                serde_json::json!({"receiver_id": self.intents, "amount": amount.to_string(), "msg": receiver.to_string()})
                    .to_string()
                    .into_bytes(),
                NearToken::from_yoctonear(1),
                GAS_FOR_FT_TRANSFER_CALL,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLBACK)
                    .on_transfer(id),
            )
    }

    /// Runs after the deposit into Intents. Marks the invoice Paid only here, and only if the
    /// token contract says tokens really moved.
    #[private]
    pub fn on_transfer(&mut self, id: String) -> bool {
        let used = used_amount();
        let confirmed = used > 0;
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
            inv.status = Status::Approved;
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
        } else if inv.status == Status::Pending {
            "Pending"
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
            "intents": self.intents,
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