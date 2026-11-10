//! arena-receipts: Arena publishes each guard's measured score under the guard's code
//! fingerprint (sha256 of its wasm). Anyone can then ask `passes(...)` before trusting a guard.
//!
//! A receipt proves WHO published a score (the owner account) and WHEN (block timestamp),
//! and points to the evidence by hash. It does NOT prove the bench ran unmodified, or that
//! the tests were good.
use near_sdk::json_types::{U128, U64};
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

/// What the publisher sends. `published_at` is added by the contract.
#[near(serializers = [json])]
pub struct ReceiptInput {
    pub guard_code_hash: String,
    pub guard_label: String,
    pub suite: String,
    pub beyond_policy: U128,
    pub against_intent: Option<U128>,
    pub tests_run: u32,
    pub tests_held: u32,
    pub harness_commit: String,
    pub evidence_sha256: String,
    pub evidence_path: String,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Receipt {
    pub guard_code_hash: String,
    pub guard_label: String,
    pub suite: String,
    pub beyond_policy: U128,
    pub against_intent: Option<U128>,
    pub tests_run: u32,
    pub tests_held: u32,
    pub harness_commit: String,
    pub evidence_sha256: String,
    pub evidence_path: String,
    /// Block timestamp, nanoseconds since the Unix epoch.
    pub published_at: U64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Receipts {
    owner: AccountId,
    /// guard_code_hash -> every receipt for it, oldest first. Never edited or deleted.
    by_hash: LookupMap<String, Vec<Receipt>>,
}

fn require_hex64(name: &str, s: &str) {
    let ok = s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    require!(ok, format!("{name} must be 64 lowercase hex characters"));
}

#[near]
impl Receipts {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self { owner, by_hash: LookupMap::new(b"r") }
    }

    /// Owner only. The caller attaches NEAR for the storage it adds; the rest is refunded.
    #[payable]
    pub fn publish(&mut self, receipt: ReceiptInput) -> Receipt {
        require!(env::predecessor_account_id() == self.owner, "only the owner can publish");
        require_hex64("guard_code_hash", &receipt.guard_code_hash);
        require_hex64("evidence_sha256", &receipt.evidence_sha256);
        require!(receipt.tests_held <= receipt.tests_run, "tests_held > tests_run");
        let before = env::storage_usage();
        let r = Receipt {
            guard_code_hash: receipt.guard_code_hash,
            guard_label: receipt.guard_label,
            suite: receipt.suite,
            beyond_policy: receipt.beyond_policy,
            against_intent: receipt.against_intent,
            tests_run: receipt.tests_run,
            tests_held: receipt.tests_held,
            harness_commit: receipt.harness_commit,
            evidence_sha256: receipt.evidence_sha256,
            evidence_path: receipt.evidence_path,
            published_at: U64(env::block_timestamp()),
        };
        self.by_hash.entry(r.guard_code_hash.clone()).or_default().push(r.clone());
        self.by_hash.flush();
        let added = env::storage_usage().saturating_sub(before) as u128;
        let cost = env::storage_byte_cost().saturating_mul(added);
        let paid = env::attached_deposit();
        require!(paid >= cost, format!("attach at least {cost} for storage"));
        let refund = paid.saturating_sub(cost);
        if refund > NearToken::from_yoctonear(0) {
            Promise::new(env::predecessor_account_id()).transfer(refund).detach();
        }
        env::log_str(&format!(
            "EVENT_JSON:{}",
            near_sdk::serde_json::json!({"standard": "arena-receipts", "version": "1.0.0",
                "event": "publish", "data": [&r]})
        ));
        r
    }

    pub fn receipts_for(&self, guard_code_hash: String) -> Vec<Receipt> {
        self.by_hash.get(&guard_code_hash).cloned().unwrap_or_default()
    }

    /// The most recently published receipt for this guard and suite.
    pub fn latest(&self, guard_code_hash: String, suite: String) -> Option<Receipt> {
        self.by_hash.get(&guard_code_hash)?.iter().rev().find(|r| r.suite == suite).cloned()
    }

    /// True only if the latest receipt exists, is at most `max_age_ns` old, and is within
    /// both limits. With `max_against_intent` set, a receipt that never measured intent fails.
    pub fn passes(
        &self,
        guard_code_hash: String,
        suite: String,
        max_beyond_policy: U128,
        max_against_intent: Option<U128>,
        max_age_ns: U64,
    ) -> bool {
        let Some(r) = self.latest(guard_code_hash, suite) else { return false };
        let age = env::block_timestamp().saturating_sub(r.published_at.0);
        let intent_ok = match (max_against_intent, r.against_intent) {
            (None, _) => true,
            (Some(max), Some(got)) => got.0 <= max.0,
            (Some(_), None) => false,
        };
        age <= max_age_ns.0 && r.beyond_policy.0 <= max_beyond_policy.0 && intent_ok
    }
}
