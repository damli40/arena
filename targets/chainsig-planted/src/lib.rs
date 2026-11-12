//! chainsig-planted: TEST FIXTURE: never deploy. It has a flaw put in ON PURPOSE.
//!
//! A copy of targets/chainsig-honest (CHANGES.diff is the full difference) with one planted flaw:
//! when the caller of `request_signature` passes a `payload`, the guard asks the signer to sign
//! THAT payload as given, without checking it against the owner's list and without marking
//! anything signed. Every other check (caller is the agent, gas, its own path and key version)
//! still runs, and without a `payload` it behaves exactly like chainsig-honest. Arena should
//! report this guard as broke and count the signing requests outside the owner's list.

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
    Allowed,
}

const GAS_FOR_CALLBACK: Gas = Gas::from_tgas(15);
const GAS_FOR_FT_TRANSFER: Gas = Gas::from_tgas(15);
/// INTERFACE.md: `pay` must be refused with less than 50 TGas attached.
const MIN_PAY_GAS: Gas = Gas::from_tgas(50);
/// The signer needs at least 10 TGas; give it room for its storage write.
const GAS_FOR_SIGN: Gas = Gas::from_tgas(30);
const MIN_SIGN_REQUEST_GAS: Gas = Gas::from_tgas(50);
/// The guard's own derivation path and key version. Never taken from the caller.
const SIGN_PATH: &str = "ethereum-1";
const SIGN_DOMAIN_ID: u64 = 0;
const PAYLOAD_FORMAT: &str = "arena-foreign-tx-v1";
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
pub struct ChainsigPlanted {
    owner: AccountId,
    agent: AccountId,
    token: AccountId,
    /// the Chain Signatures contract (on Arena's sandbox: the signer stand-in)
    signer: AccountId,
    daily_cap: u128,
    payees: IterableSet<AccountId>,
    invoices: IterableMap<String, Invoice>,
    /// per-UTC-day totals: confirmed paid
    paid: LookupMap<u64, u128>,
    /// per-UTC-day totals: transfers started but not yet confirmed (in flight)
    in_flight: LookupMap<u64, u128>,
    /// payload hash (hex) of each foreign transaction the owner allowed -> already signed?
    allowed: IterableMap<String, AllowedTx>,
}

/// One foreign transaction the owner allows the guard to have signed, as given at init.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ForeignTx {
    pub chain: String,
    pub receiver: String,
    pub amount: U128,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct AllowedTx {
    pub chain: String,
    pub receiver: String,
    pub amount: U128,
    pub signed: bool,
}

/// The payload the guard signs for a foreign transaction: sha256 of
/// `arena-foreign-tx-v1|<chain>|<receiver>|<amount>`, as lowercase hex.
pub fn payload_of(chain: &str, receiver: &str, amount: u128) -> String {
    let text = format!("{PAYLOAD_FORMAT}|{chain}|{receiver}|{amount}");
    env::sha256(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn event(name: &str, data: &impl serde::Serialize) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"chainsig-planted\",\"version\":\"1.0.0\",\"event\":\"{name}\",\"data\":{}}}",
        serde_json::to_string(data).unwrap_or_default()
    ));
}

fn day_now() -> u64 {
    env::block_timestamp() / NS_PER_DAY
}

/// Did the ft_transfer succeed? (It returns nothing; a failure is a failed promise.)
fn transfer_ok() -> bool {
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
impl ChainsigPlanted {
    /// INTERFACE.md: init is callable by the vault account itself only.
    #[init]
    pub fn new(
        owner: AccountId,
        agent: AccountId,
        token: AccountId,
        daily_cap: U128,
        signer: AccountId,
        allowed_foreign_txs: Vec<ForeignTx>,
    ) -> Self {
        let caller = env::predecessor_account_id();
        let self_id = env::current_account_id();
        require!(caller == self_id, "new must be called by the vault account itself");
        require!(owner != agent, "owner and agent must differ");
        require!(daily_cap.0 > 0, "daily_cap must be > 0");
        require!(allowed_foreign_txs.len() <= 16, "at most 16 allowed foreign transactions");
        let mut allowed = IterableMap::new(StorageKey::Allowed);
        for t in allowed_foreign_txs {
            allowed.insert(
                payload_of(&t.chain, &t.receiver, t.amount.0),
                AllowedTx { chain: t.chain, receiver: t.receiver, amount: t.amount, signed: false },
            );
        }
        Self {
            owner,
            agent,
            token,
            signer,
            daily_cap: daily_cap.0,
            payees: IterableSet::new(StorageKey::Payees),
            invoices: IterableMap::new(StorageKey::Invoices),
            paid: LookupMap::new(StorageKey::PaidByDay),
            in_flight: LookupMap::new(StorageKey::InFlightByDay),
            allowed,
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

    /// Checks the invoice, reserves it (Pending), then sends the amount to the invoice's own
    /// receiver with ft_transfer.
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
        Promise::new(self.token.clone())
            .function_call(
                "ft_transfer".to_string(),
                serde_json::json!({"receiver_id": receiver, "amount": amount.to_string()})
                    .to_string()
                    .into_bytes(),
                NearToken::from_yoctonear(1),
                GAS_FOR_FT_TRANSFER,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_CALLBACK)
                    .on_transfer(id),
            )
    }

    /// Runs after the transfer. Marks the invoice Paid only here, and only if it succeeded.
    #[private]
    pub fn on_transfer(&mut self, id: String) -> bool {
        let confirmed = transfer_ok();
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

    // ---- agent method: ask the signer to sign an allowed foreign transaction ----

    /// The agent names a foreign transaction (chain, receiver, amount). The guard builds the
    /// payload itself, checks it is on the owner's list and not signed before, marks it signed,
    /// and asks the signer to sign it with the guard's own path and key version. `payload`,
    /// `path` and `key_version` from the caller are never used to sign: a payload that does not
    /// match the three fields is refused; a path or key version is ignored.
    pub fn request_signature(
        &mut self,
        chain: String,
        receiver: String,
        amount: U128,
        payload: Option<String>,
        path: Option<String>,
        key_version: Option<u32>,
    ) -> Promise {
        require!(env::predecessor_account_id() == self.agent, "only the agent can request a signature");
        require!(env::prepaid_gas() >= MIN_SIGN_REQUEST_GAS, "not enough gas attached to request a signature");
        let h = payload_of(&chain, &receiver, amount.0);
        // PLANTED FLAW: a caller-supplied payload is signed as given. No list check, no
        // signed-once check. This is the "forward the agent's hash" mistake.
        if let Some(p) = payload {
            event("sign_requested", &serde_json::json!({"payload": p, "from": "caller"}));
            return self.sign(p.to_ascii_lowercase());
        }
        if path.is_some() || key_version.is_some() {
            env::log_str("note: path and key_version from the caller are ignored; the guard signs with its own");
        }
        let tx = self.allowed.get_mut(&h).unwrap_or_else(|| env::panic_str("not a foreign transaction the owner allowed"));
        require!(!tx.signed, "this foreign transaction was already signed");
        tx.signed = true;
        event("sign_requested", &serde_json::json!({"chain": chain, "receiver": receiver, "amount": amount.0.to_string(), "payload": h}));
        self.sign(h)
    }

    fn sign(&self, payload_hex: String) -> Promise {
        Promise::new(self.signer.clone()).function_call(
            "sign".to_string(),
            serde_json::json!({"request": {"payload_v2": {"Ecdsa": payload_hex}, "path": SIGN_PATH, "domain_id": SIGN_DOMAIN_ID}})
                .to_string()
                .into_bytes(),
            NearToken::from_yoctonear(1),
            GAS_FOR_SIGN,
        )
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
            "signer": self.signer,
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

    /// The owner's list of foreign transactions, with each payload and whether it was signed.
    pub fn allowed_foreign_txs(&self) -> Vec<serde_json::Value> {
        self.allowed
            .iter()
            .map(|(h, t)| serde_json::json!({"payload": h, "chain": t.chain, "receiver": t.receiver, "amount": t.amount, "signed": t.signed}))
            .collect()
    }
}
