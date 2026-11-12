//! The SLOW token (branch race-ordering, RACE-ORDERING-DESIGN section 4.3): the local test token
//! (contracts/test-token, same methods, same `new`), plus one switch. With holding OFF it behaves
//! exactly like the test token. With holding ON, `ft_transfer` moves the money at once, then PARKS
//! its answer (NEAR yield/resume): the caller's callback cannot run until the token account calls
//! `release`. NEAR wakes a parked answer by itself after about 200 blocks; then `on_release` logs
//! `HOLD-TIMEOUT seq=<n>` (the harness marks that run not-produced) and still answers success,
//! because the money did move.
//!
//! `set_hold` and `release` may be called only by the token account itself (the harness signs as
//! the token contract, as at setup); testers (`agent`, `outsider`) never can. Local sandbox only.

use near_contract_standards::fungible_token::metadata::{
    FungibleTokenMetadata, FungibleTokenMetadataProvider, FT_METADATA_SPEC,
};
use near_contract_standards::fungible_token::{
    FungibleToken, FungibleTokenCore, FungibleTokenResolver,
};
use near_contract_standards::storage_management::{
    StorageBalance, StorageBalanceBounds, StorageManagement,
};
use near_sdk::json_types::U128;
use near_sdk::{env, log, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, PromiseOrValue};

/// Gas reserved for `on_release` when an answer is parked (the same for any delay).
const GAS_ON_RELEASE: Gas = Gas::from_tgas(5);

#[near(serializers = [borsh])]
pub struct Held {
    seq: u64,
    receiver_id: AccountId,
    amount: U128,
    since_block: u64,
    data_id: Vec<u8>,
}

#[near(serializers = [json])]
pub struct HeldView {
    pub seq: u64,
    pub receiver_id: AccountId,
    pub amount: U128,
    pub since_block: u64,
}

#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct Contract {
    token: FungibleToken,
    hold: bool,
    next_seq: u64,
    held: Vec<Held>,
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId, total_supply: U128) -> Self {
        let mut token = FungibleToken::new(b"t".to_vec());
        token.internal_register_account(&owner_id);
        token.internal_deposit(&owner_id, total_supply.into());
        Self { token, hold: false, next_seq: 1, held: Vec::new() }
    }

    fn assert_self(&self) {
        require!(env::predecessor_account_id() == env::current_account_id(), "only the token account");
    }

    /// Turn holding on or off. Token account only.
    pub fn set_hold(&mut self, on: bool) {
        self.assert_self();
        self.hold = on;
        log!("SET-HOLD {}", on);
    }

    /// Wake the oldest `count` parked answers (all if absent). Token account only. Returns how many.
    pub fn release(&mut self, count: Option<u32>) -> u32 {
        self.assert_self();
        let n = count.map(|c| c as usize).unwrap_or(self.held.len()).min(self.held.len());
        let woken: Vec<Held> = self.held.drain(..n).collect();
        for h in &woken {
            let id: [u8; 32] = h.data_id.clone().try_into().expect("32-byte yield id");
            let ok = env::promise_yield_resume(&id, b"\"released\"");
            log!("RELEASE seq={} resumed={}", h.seq, ok);
        }
        n as u32
    }

    /// Parked answers, oldest first.
    pub fn held(&self) -> Vec<HeldView> {
        self.held
            .iter()
            .map(|h| HeldView { seq: h.seq, receiver_id: h.receiver_id.clone(), amount: h.amount, since_block: h.since_block })
            .collect()
    }

    pub fn is_holding(&self) -> bool {
        self.hold
    }

    /// Runs when a parked answer is woken: by `release`, or by NEAR after its timeout.
    #[private]
    pub fn on_release(&mut self, seq: u64) {
        match env::promise_result_checked(0, 64) {
            Ok(_) => log!("RELEASED seq={}", seq),
            Err(_) => {
                // Timeout: nobody released it. The money moved at ft_transfer time, so answer
                // success anyway, and say so loudly (the harness marks the run not-produced).
                self.held.retain(|h| h.seq != seq);
                log!("HOLD-TIMEOUT seq={}", seq);
            }
        }
    }
}

#[near]
impl FungibleTokenCore for Contract {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.token.ft_transfer(receiver_id.clone(), amount, memo);
        if self.hold {
            let seq = self.next_seq;
            self.next_seq += 1;
            let args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({ "seq": seq })).expect("args");
            let idx = env::promise_yield_create("on_release", &args, GAS_ON_RELEASE, GasWeight(0), 0);
            let data_id = env::read_register(0).expect("yield id");
            self.held.push(Held { seq, receiver_id, amount, since_block: env::block_height(), data_id });
            log!("HOLD seq={}", seq);
            env::promise_return(idx);
        }
    }

    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }

    fn ft_total_supply(&self) -> U128 {
        self.token.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.token.ft_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenResolver for Contract {
    #[private]
    fn ft_resolve_transfer(
        &mut self,
        sender_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    ) -> U128 {
        let (used, _burned) =
            self.token
                .internal_ft_resolve_transfer(&sender_id, receiver_id, amount);
        used.into()
    }
}

#[near]
impl StorageManagement for Contract {
    #[payable]
    fn storage_deposit(
        &mut self,
        account_id: Option<AccountId>,
        registration_only: Option<bool>,
    ) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
        self.token.storage_withdraw(amount)
    }

    #[payable]
    fn storage_unregister(&mut self, force: Option<bool>) -> bool {
        #[allow(unused_variables)]
        if let Some((account_id, balance)) = self.token.internal_storage_unregister(force) {
            env::log_str(&format!("closed {account_id} with balance {balance}"));
            true
        } else {
            false
        }
    }

    fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.token.storage_balance_bounds()
    }

    fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenMetadataProvider for Contract {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        FungibleTokenMetadata {
            spec: FT_METADATA_SPEC.to_string(),
            name: "Arena Slow Test Token".to_string(),
            symbol: "ARENA".to_string(),
            icon: None,
            reference: None,
            reference_hash: None,
            decimals: 0,
        }
    }
}
