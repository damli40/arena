//! vault-a: an invoice vault for an AI agent on NEAR.
//!
//! The vault holds one NEP-141 token. The owner approves invoices
//! (receiver + amount + expiry). The agent triggers payment of an approved
//! invoice. Each invoice can move its amount to its receiver exactly once.
//! See DESIGN.md for the state machine and the reasoning behind each check.

use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    assert_one_yocto, env, log, near, require, serde_json, AccountId, BorshStorageKey, Gas,
    NearToken, PanicOnDefault, Promise, PromiseError,
};

/// Nanoseconds in one UTC day. NEAR block timestamps are Unix-epoch ns,
/// so `timestamp / NS_PER_DAY` is the UTC day number.
const NS_PER_DAY: u64 = 86_400 * 1_000_000_000;

/// Gas handed to the token's `ft_transfer`.
const GAS_FT_TRANSFER: Gas = Gas::from_tgas(20);
/// Gas reserved for our own callback. The callback must never run out of gas,
/// otherwise the invoice would be stuck in `Pending`.
const GAS_CALLBACK: Gas = Gas::from_tgas(15);
/// Gas we need left for the rest of `pay` itself after scheduling.
const GAS_PAY_OVERHEAD: Gas = Gas::from_tgas(10);

const MAX_ID_LEN: usize = 64;

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Payees,
    Invoices,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoiceStatus {
    /// Approved by the owner; can be paid if unexpired and receiver still a payee.
    Approved,
    /// A transfer is in flight; waiting for the callback.
    Pending,
    /// Transfer succeeded. Terminal.
    Paid,
    /// Cancelled by the owner. Terminal.
    Cancelled,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug)]
pub struct Invoice {
    pub receiver: AccountId,
    pub amount: u128,
    pub expires_at_ns: u64,
    pub status: InvoiceStatus,
    /// Payee "generation" the receiver had when the invoice was approved.
    /// Removing a payee and adding it back gives it a new generation, so
    /// invoices approved before the removal stay dead.
    pub payee_generation: u64,
    /// UTC day the in-flight amount was counted against (only while Pending).
    pub pending_day: Option<u64>,
}

#[near(serializers = [json])]
pub struct InvoiceView {
    pub id: String,
    pub receiver: AccountId,
    pub amount: U128,
    pub expires_at_ns: u64,
    /// One of "Approved", "Pending", "Paid", "Cancelled", "Expired", "PayeeRemoved".
    /// "Expired" and "PayeeRemoved" are derived: the stored status is Approved
    /// but the invoice can no longer be paid.
    pub status: String,
    pub payable_now: bool,
}

#[near(serializers = [json])]
pub struct ConfigView {
    pub owner: AccountId,
    pub agent: AccountId,
    pub token: AccountId,
    pub daily_cap: U128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct VaultA {
    owner: AccountId,
    agent: AccountId,
    token: AccountId,
    daily_cap: u128,
    /// payee -> generation number.
    payees: LookupMap<AccountId, u64>,
    next_payee_generation: u64,
    invoices: LookupMap<String, Invoice>,
    /// UTC day number that `spent_amount` refers to.
    spent_day: u64,
    /// Amount paid or in flight during `spent_day`.
    spent_amount: u128,
}

fn current_day() -> u64 {
    env::block_timestamp() / NS_PER_DAY
}

fn emit(event: &str, data: serde_json::Value) {
    log!(
        "EVENT_JSON:{}",
        serde_json::json!({"standard": "vault-a", "version": "1.0.0", "event": event, "data": [data]})
    );
}

#[near]
impl VaultA {
    /// Only the vault account itself may initialise (deploy + init in one
    /// transaction), so nobody can front-run initialisation with their own owner.
    #[init]
    #[private]
    pub fn new(owner: AccountId, agent: AccountId, token: AccountId, daily_cap: U128) -> Self {
        require!(owner != agent, "owner and agent must be different accounts");
        require!(
            agent != env::current_account_id() && owner != env::current_account_id(),
            "owner/agent cannot be the vault itself"
        );
        require!(token != env::current_account_id(), "token cannot be the vault itself");
        Self {
            owner,
            agent,
            token,
            daily_cap: daily_cap.0,
            payees: LookupMap::new(StorageKey::Payees),
            next_payee_generation: 1,
            invoices: LookupMap::new(StorageKey::Invoices),
            spent_day: current_day(),
            spent_amount: 0,
        }
    }

    // ------------------------------------------------------------------
    // Owner methods
    // ------------------------------------------------------------------

    /// Add a payee. Requires exactly 1 yoctoNEAR (full-access key).
    /// Re-adding an existing payee is a no-op (keeps its generation).
    #[payable]
    pub fn add_payee(&mut self, account: AccountId) {
        assert_one_yocto();
        self.assert_owner();
        require!(account != env::current_account_id(), "vault cannot be a payee");
        if self.payees.contains_key(&account) {
            return;
        }
        let generation = self.next_payee_generation;
        self.next_payee_generation += 1;
        self.payees.insert(account.clone(), generation);
        emit("payee_added", serde_json::json!({"account": account}));
    }

    /// Remove a payee. All invoices approved for this payee become permanently
    /// unpayable, even if the payee is added again later. No deposit needed
    /// (restricting is always safe, so it should be easy in an emergency).
    pub fn remove_payee(&mut self, account: AccountId) {
        self.assert_owner();
        if self.payees.remove(&account).is_some() {
            emit("payee_removed", serde_json::json!({"account": account}));
        }
    }

    /// Approve a new invoice. Requires exactly 1 yoctoNEAR.
    #[payable]
    pub fn approve_invoice(
        &mut self,
        id: String,
        receiver: AccountId,
        amount: U128,
        expires_at_ns: u64,
    ) {
        assert_one_yocto();
        self.assert_owner();
        require!(!id.is_empty() && id.len() <= MAX_ID_LEN, "invoice id must be 1..=64 bytes");
        require!(!self.invoices.contains_key(&id), "invoice id already used");
        require!(amount.0 > 0, "amount must be positive");
        require!(expires_at_ns > env::block_timestamp(), "expiry must be in the future");
        let generation = match self.payees.get(&receiver) {
            Some(g) => *g,
            None => env::panic_str("receiver is not a payee"),
        };
        self.invoices.insert(
            id.clone(),
            Invoice {
                receiver: receiver.clone(),
                amount: amount.0,
                expires_at_ns,
                status: InvoiceStatus::Approved,
                payee_generation: generation,
                pending_day: None,
            },
        );
        emit(
            "invoice_approved",
            serde_json::json!({"id": id, "receiver": receiver, "amount": amount, "expires_at_ns": expires_at_ns.to_string()}),
        );
    }

    /// Cancel an approved invoice. Fails if the invoice is already paid,
    /// already cancelled, or has a transfer in flight (an in-flight transfer
    /// cannot be recalled; wait for its outcome and cancel if it failed).
    pub fn cancel_invoice(&mut self, id: String) {
        self.assert_owner();
        let inv = match self.invoices.get_mut(&id) {
            Some(inv) => inv,
            None => env::panic_str("invoice not found"),
        };
        match inv.status {
            InvoiceStatus::Approved => inv.status = InvoiceStatus::Cancelled,
            InvoiceStatus::Pending => env::panic_str("transfer in flight; cannot cancel now"),
            InvoiceStatus::Paid => env::panic_str("invoice already paid"),
            InvoiceStatus::Cancelled => env::panic_str("invoice already cancelled"),
        }
        emit("invoice_cancelled", serde_json::json!({"id": id}));
    }

    /// Replace the agent. Requires exactly 1 yoctoNEAR.
    #[payable]
    pub fn set_agent(&mut self, account: AccountId) {
        assert_one_yocto();
        self.assert_owner();
        require!(account != self.owner, "owner and agent must be different accounts");
        require!(account != env::current_account_id(), "agent cannot be the vault itself");
        self.agent = account.clone();
        emit("agent_set", serde_json::json!({"agent": account}));
    }

    /// Change the daily cap. Takes effect immediately, including for today:
    /// if today's spend already exceeds the new cap, no more payments today.
    /// Requires exactly 1 yoctoNEAR.
    #[payable]
    pub fn set_daily_cap(&mut self, daily_cap: U128) {
        assert_one_yocto();
        self.assert_owner();
        self.daily_cap = daily_cap.0;
        emit("daily_cap_set", serde_json::json!({"daily_cap": daily_cap}));
    }

    // ------------------------------------------------------------------
    // Agent method
    // ------------------------------------------------------------------

    /// Pay an approved invoice. Agent only. Attach at least ~50 TGas
    /// (100 TGas recommended). No deposit.
    pub fn pay(&mut self, id: String) -> Promise {
        require!(env::predecessor_account_id() == self.agent, "only the agent can pay");

        // The callback must be guaranteed enough gas, or the invoice could be
        // left stuck in Pending. Check before touching state.
        let needed = GAS_FT_TRANSFER
            .saturating_add(GAS_CALLBACK)
            .saturating_add(GAS_PAY_OVERHEAD);
        let remaining = env::prepaid_gas().saturating_sub(env::used_gas());
        require!(remaining >= needed, "not enough gas attached to pay safely");

        let now = env::block_timestamp();
        let today = now / NS_PER_DAY;

        let (receiver, amount) = {
            let inv = match self.invoices.get(&id) {
                Some(inv) => inv,
                None => env::panic_str("invoice not found"),
            };
            match inv.status {
                InvoiceStatus::Approved => {}
                InvoiceStatus::Pending => env::panic_str("payment already in flight"),
                InvoiceStatus::Paid => env::panic_str("invoice already paid"),
                InvoiceStatus::Cancelled => env::panic_str("invoice cancelled"),
            }
            require!(now < inv.expires_at_ns, "invoice expired");
            match self.payees.get(&inv.receiver) {
                Some(g) if *g == inv.payee_generation => {}
                _ => env::panic_str("receiver is no longer a payee"),
            }
            (inv.receiver.clone(), inv.amount)
        };

        // Daily cap: roll the window if the UTC day changed, then reserve.
        self.roll_day(today);
        let new_spent = match self.spent_amount.checked_add(amount) {
            Some(v) => v,
            None => env::panic_str("daily cap exceeded"),
        };
        require!(amount <= self.daily_cap, "daily cap exceeded"); // MUTANT M3: per payment
        self.spent_amount = new_spent;

        // Mark in flight BEFORE scheduling the transfer, so a second `pay`
        // in a later block cannot start another transfer for the same invoice.
        {
            let inv = self.invoices.get_mut(&id).expect("checked above");
            inv.status = InvoiceStatus::Pending;
            inv.pending_day = Some(today);
        }

        emit(
            "payment_started",
            serde_json::json!({"id": id, "receiver": receiver, "amount": U128(amount)}),
        );

        let args = serde_json::json!({
            "receiver_id": receiver,
            "amount": U128(amount),
            "memo": format!("vault-a invoice {}", id),
        });

        Promise::new(self.token.clone())
            .function_call(
                "ft_transfer".to_string(),
                serde_json::to_vec(&args).expect("serialize args"),
                NearToken::from_yoctonear(1),
                GAS_FT_TRANSFER,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_CALLBACK)
                    .on_transfer_complete(id),
            )
    }

    /// Callback after `ft_transfer`. Only callable by the vault itself.
    /// Returns true if the invoice is now Paid. Written so it does not panic:
    /// a panic here would leave the invoice stuck in Pending.
    #[private]
    pub fn on_transfer_complete(&mut self, id: String) -> bool {
        // NEP-141 ft_transfer returns nothing and panics on any failure, so
        // "the receipt succeeded" is the outcome. We read at most 0 bytes of
        // the return value; a non-empty return (TooLong) still means success.
        let succeeded = env::promise_results_count() == 1
            && match env::promise_result_checked(0, 0) {
                Ok(_) => true,
                Err(PromiseError::TooLong(_)) => true,
                Err(_) => false,
            };

        let (amount, pending_day) = match self.invoices.get_mut(&id) {
            Some(inv) if inv.status == InvoiceStatus::Pending => {
                let day = inv.pending_day.take();
                if succeeded {
                    inv.status = InvoiceStatus::Paid;
                } else {
                    inv.status = InvoiceStatus::Approved;
                }
                (inv.amount, day)
            }
            _ => {
                // Should be unreachable: only `pay` schedules this callback and
                // it always sets Pending first. Log and do nothing.
                log!("vault-a: callback for invoice {} not in Pending state; ignored", id);
                return false;
            }
        };

        if succeeded {
            emit("payment_succeeded", serde_json::json!({"id": id, "amount": U128(amount)}));
            true
        } else {
            // Release the reservation, but only from the day it was counted
            // against. If the window has since rolled to a new day, the old
            // day's counter no longer exists and there is nothing to release.
            if pending_day == Some(self.spent_day) {
                self.spent_amount = self.spent_amount.saturating_sub(amount);
            }
            emit("payment_failed", serde_json::json!({"id": id, "amount": U128(amount)}));
            false
        }
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    pub fn get_invoice(&self, id: String) -> Option<InvoiceView> {
        let inv = self.invoices.get(&id)?;
        let now = env::block_timestamp();
        let payee_ok = matches!(self.payees.get(&inv.receiver), Some(g) if *g == inv.payee_generation);
        let (status, payable_now) = match inv.status {
            InvoiceStatus::Approved if now >= inv.expires_at_ns => ("Expired", false),
            InvoiceStatus::Approved if !payee_ok => ("PayeeRemoved", false),
            InvoiceStatus::Approved => ("Approved", true),
            InvoiceStatus::Pending => ("Pending", false),
            InvoiceStatus::Paid => ("Paid", false),
            InvoiceStatus::Cancelled => ("Cancelled", false),
        };
        Some(InvoiceView {
            id,
            receiver: inv.receiver.clone(),
            amount: U128(inv.amount),
            expires_at_ns: inv.expires_at_ns,
            status: status.to_string(),
            payable_now,
        })
    }

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            owner: self.owner.clone(),
            agent: self.agent.clone(),
            token: self.token.clone(),
            daily_cap: U128(self.daily_cap),
        }
    }

    /// Amount paid plus amount in flight during the current UTC day.
    pub fn paid_today(&self) -> U128 {
        if self.spent_day == current_day() {
            U128(self.spent_amount)
        } else {
            U128(0)
        }
    }

    pub fn is_payee(&self, account: AccountId) -> bool {
        self.payees.contains_key(&account)
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "only the owner can do this");
    }

    fn roll_day(&mut self, today: u64) {
        if today != self.spent_day {
            self.spent_day = today;
            self.spent_amount = 0;
        }
    }
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{get_logs, VMContextBuilder};
    use near_sdk::{testing_env, PromiseResult};

    const DAY: u64 = NS_PER_DAY;
    const T0: u64 = 20_000 * DAY + 1_000; // some UTC day, just after midnight

    fn acc(s: &str) -> AccountId {
        s.parse().unwrap()
    }

    fn ctx(pred: &str, ts: u64, deposit: u128) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id(acc("vault.near"))
            .predecessor_account_id(acc(pred))
            .block_timestamp(ts)
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .prepaid_gas(Gas::from_tgas(100));
        b
    }

    fn setup(cap: u128) -> VaultA {
        testing_env!(ctx("vault.near", T0, 0).build());
        let mut v = VaultA::new(acc("owner.near"), acc("agent.near"), acc("token.near"), U128(cap));
        testing_env!(ctx("owner.near", T0, 1).build());
        v.add_payee(acc("bob.near"));
        v
    }

    fn approve(v: &mut VaultA, id: &str, amount: u128, exp: u64) {
        testing_env!(ctx("owner.near", T0, 1).build());
        v.approve_invoice(id.into(), acc("bob.near"), U128(amount), exp);
    }

    fn callback(v: &mut VaultA, id: &str, ts: u64, ok: bool) -> bool {
        let r = if ok { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed };
        testing_env!(
            ctx("vault.near", ts, 0).build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![r]
        );
        v.on_transfer_complete(id.into())
    }

    fn status(v: &VaultA, id: &str) -> String {
        v.get_invoice(id.into()).unwrap().status
    }

    #[test]
    fn pay_success_once() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("agent.near", T0 + 10, 0).build());
        v.pay("a".into());
        assert_eq!(status(&v, "a"), "Pending");
        assert_eq!(v.paid_today().0, 100);
        assert!(callback(&mut v, "a", T0 + 20, true));
        assert_eq!(status(&v, "a"), "Paid");
        assert!(get_logs().iter().any(|l| l.contains("payment_succeeded")));
    }

    #[test]
    #[should_panic(expected = "invoice already paid")]
    fn no_double_pay() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        callback(&mut v, "a", T0, true);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
    }

    #[test]
    #[should_panic(expected = "payment already in flight")]
    fn no_pay_while_pending() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        v.pay("a".into());
    }

    #[test]
    fn failed_transfer_is_payable_again_and_releases_cap() {
        let mut v = setup(100);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        assert!(!callback(&mut v, "a", T0, false));
        assert_eq!(status(&v, "a"), "Approved");
        assert_eq!(v.paid_today().0, 0);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        assert!(callback(&mut v, "a", T0, true));
        assert_eq!(v.paid_today().0, 100);
    }

    #[test]
    fn failure_after_midnight_does_not_touch_new_day() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + 3 * DAY);
        approve(&mut v, "b", 50, T0 + 3 * DAY);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        // next day: pay b, then a's failure arrives
        testing_env!(ctx("agent.near", T0 + DAY, 0).build());
        v.pay("b".into());
        callback(&mut v, "a", T0 + DAY, false);
        testing_env!(ctx("agent.near", T0 + DAY, 0).build());
        assert_eq!(v.paid_today().0, 50);
    }

    #[test]
    #[should_panic(expected = "daily cap exceeded")]
    fn cap_enforced_including_in_flight() {
        let mut v = setup(150);
        approve(&mut v, "a", 100, T0 + DAY);
        approve(&mut v, "b", 100, T0 + DAY);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        v.pay("b".into());
    }

    #[test]
    fn cap_resets_next_utc_day() {
        let mut v = setup(100);
        approve(&mut v, "a", 100, T0 + 3 * DAY);
        approve(&mut v, "b", 100, T0 + 3 * DAY);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        callback(&mut v, "a", T0, true);
        testing_env!(ctx("agent.near", T0 + DAY, 0).build());
        assert_eq!(v.paid_today().0, 0);
        v.pay("b".into());
    }

    #[test]
    #[should_panic(expected = "invoice expired")]
    fn expired_not_payable() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + 100);
        testing_env!(ctx("agent.near", T0 + 100, 0).build());
        v.pay("a".into());
    }

    #[test]
    #[should_panic(expected = "invoice cancelled")]
    fn cancelled_not_payable() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("owner.near", T0, 0).build());
        v.cancel_invoice("a".into());
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
    }

    #[test]
    #[should_panic(expected = "receiver is no longer a payee")]
    fn removed_then_readded_payee_old_invoice_dead() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("owner.near", T0, 0).build());
        v.remove_payee(acc("bob.near"));
        testing_env!(ctx("owner.near", T0, 1).build());
        v.add_payee(acc("bob.near"));
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
    }

    #[test]
    #[should_panic(expected = "only the agent can pay")]
    fn owner_cannot_pay() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("owner.near", T0, 0).build());
        v.pay("a".into());
    }

    #[test]
    #[should_panic(expected = "only the owner can do this")]
    fn agent_cannot_approve() {
        let mut v = setup(1_000);
        testing_env!(ctx("agent.near", T0, 1).build());
        v.approve_invoice("x".into(), acc("bob.near"), U128(1), T0 + DAY);
    }

    #[test]
    #[should_panic(expected = "receiver is not a payee")]
    fn approve_requires_payee() {
        let mut v = setup(1_000);
        testing_env!(ctx("owner.near", T0, 1).build());
        v.approve_invoice("x".into(), acc("eve.near"), U128(1), T0 + DAY);
    }

    #[test]
    #[should_panic(expected = "invoice id already used")]
    fn id_reuse_rejected() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        approve(&mut v, "a", 100, T0 + DAY);
    }

    #[test]
    #[should_panic(expected = "transfer in flight")]
    fn cannot_cancel_pending() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        testing_env!(ctx("agent.near", T0, 0).build());
        v.pay("a".into());
        testing_env!(ctx("owner.near", T0, 0).build());
        v.cancel_invoice("a".into());
    }

    #[test]
    #[should_panic(expected = "not enough gas")]
    fn low_gas_rejected() {
        let mut v = setup(1_000);
        approve(&mut v, "a", 100, T0 + DAY);
        let mut c = ctx("agent.near", T0, 0);
        c.prepaid_gas(Gas::from_tgas(30));
        testing_env!(c.build());
        v.pay("a".into());
    }

    #[test]
    #[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
    fn owner_set_requires_one_yocto() {
        let mut v = setup(1_000);
        testing_env!(ctx("owner.near", T0, 0).build());
        v.set_daily_cap(U128(5));
    }
}
