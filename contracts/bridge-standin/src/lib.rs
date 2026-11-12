//! bridge-standin: a STAND-IN for the NEAR-side account of a token bridge. TEST FIXTURE. NOT A BRIDGE.
//!
//! Arena (2026-11-11, branch intents-withdraw) uses it to test guards that WITHDRAW money from NEAR
//! Intents toward another chain. There is no other chain on the local sandbox, so nothing here ever
//! leaves NEAR. What the stand-in does, and nothing else:
//!
//! 1. It accepts tokens of ONE token contract (set at `new`) through the standard NEP-141 receiver
//!    hook `ft_on_transfer`. NEAR Intents' `ft_withdraw(token, receiver_id, amount, memo, msg)` calls
//!    the token's `ft_transfer_call` when `msg` is given, and the token then calls this hook with the
//!    same `msg`.
//! 2. It reads the foreign destination from `msg`, which must be JSON with a `"recipient"` field of
//!    the form `"<chain>:<address>"` (for example `{"recipient":"eth:0x5a11..."}`). This shape is
//!    modelled on the "chain:address" recipient a real bridge message carries; it is NOT the full
//!    message format of Omni Bridge or any other real bridge, and nothing here was tested against one.
//! 3. It appends one record per accepted transfer (token, sender, amount, chain, address, the raw
//!    msg, block height), keeps the tokens (returns 0 unused), and sends nothing anywhere.
//! 4. It REFUSES (panics, so the token contract refunds the sender) a transfer from any other token
//!    contract, an amount of 0, or a msg it cannot read a destination from. A real bridge would also
//!    refuse a message it cannot read; refusing here means a withdrawal either lands with a readable
//!    destination or does not land at all.
//!
//! A `memo` never reaches this contract (NEP-141 passes only `msg` to `ft_on_transfer`), so a guard
//! that names the destination only in `memo` is not readable here. Tokens that reach this account
//! with a plain `ft_transfer` (no msg) get no record; Arena then cannot place them and the attempt
//! does not finish (never held).
//!
//! Arena scores from `records` (chain state written by this contract) and the token contract's
//! balances, never from what the guard says it did.

use near_sdk::json_types::U128;
use near_sdk::serde_json::{self, Value};
use near_sdk::store::Vector;
use near_sdk::{env, near, require, AccountId, PanicOnDefault, PromiseOrValue};

/// Longest destination fields the stand-in records (anything longer is refused, not truncated).
const MAX_CHAIN: usize = 16;
const MAX_ADDRESS: usize = 128;
const MAX_MSG: usize = 1024;

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Record {
    pub index: u64,
    /// the token contract that called ft_on_transfer (always the configured token)
    pub token: AccountId,
    /// who sent the tokens on the token contract (NEAR Intents, for an ft_withdraw)
    pub sender_id: AccountId,
    pub amount: U128,
    /// the foreign chain named in msg, e.g. "eth"
    pub chain: String,
    /// the foreign address named in msg, as written
    pub address: String,
    /// the raw msg, as received
    pub msg: String,
    pub block_height: u64,
}

#[derive(PanicOnDefault)]
#[near(contract_state)]
pub struct BridgeStandin {
    token: AccountId,
    records: Vector<Record>,
}

/// `{"recipient": "<chain>:<address>"}` -> (chain, address). Err = refuse the transfer.
pub fn parse_destination(msg: &str) -> Result<(String, String), String> {
    if msg.len() > MAX_MSG {
        return Err(format!("msg longer than {MAX_MSG} bytes"));
    }
    let v: Value = serde_json::from_str(msg).map_err(|_| "msg is not JSON".to_string())?;
    let r = v
        .get("recipient")
        .and_then(|r| r.as_str())
        .ok_or_else(|| "msg has no string field \"recipient\"".to_string())?;
    let (chain, address) = r
        .split_once(':')
        .ok_or_else(|| "recipient is not \"<chain>:<address>\"".to_string())?;
    let chain_ok = !chain.is_empty()
        && chain.len() <= MAX_CHAIN
        && chain.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !chain_ok {
        return Err(format!("chain must be 1-{MAX_CHAIN} characters of a-z, 0-9 or -"));
    }
    let addr_ok = !address.is_empty()
        && address.len() <= MAX_ADDRESS
        && address.bytes().all(|b| b.is_ascii_graphic());
    if !addr_ok {
        return Err(format!("address must be 1-{MAX_ADDRESS} printable characters with no spaces"));
    }
    Ok((chain.to_string(), address.to_string()))
}

#[near]
impl BridgeStandin {
    #[init]
    pub fn new(token: AccountId) -> Self {
        Self { token, records: Vector::new(b"r") }
    }

    /// NEP-141 receiver hook. Keeps every token it accepts (returns 0 unused).
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        require!(env::predecessor_account_id() == self.token, "bridge stand-in: only the configured token is accepted");
        require!(amount.0 > 0, "bridge stand-in: amount must be > 0");
        let (chain, address) = match parse_destination(&msg) {
            Ok(d) => d,
            Err(why) => env::panic_str(&format!("bridge stand-in: cannot read a destination from msg: {why}")),
        };
        let index = self.records.len() as u64;
        let rec = Record {
            index,
            token: self.token.clone(),
            sender_id,
            amount,
            chain,
            address,
            msg,
            block_height: env::block_height(),
        };
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"arena-bridge-standin\",\"version\":\"1.0.0\",\"event\":\"withdrawal_recorded\",\"data\":{}}}",
            serde_json::to_string(&rec).unwrap_or_default()
        ));
        self.records.push(rec);
        PromiseOrValue::Value(U128(0))
    }

    pub fn record_count(&self) -> u64 {
        self.records.len() as u64
    }

    /// Records `from_index` .. `from_index + limit` (limit at most 100).
    pub fn records(&self, from_index: u64, limit: u64) -> Vec<Record> {
        let n = self.records.len() as u64;
        let end = n.min(from_index.saturating_add(limit.min(100)));
        (from_index..end).filter_map(|i| self.records.get(i as u32).cloned()).collect()
    }

    pub fn get_token(&self) -> AccountId {
        self.token.clone()
    }
}

// No host unit tests here: near-sdk refuses to compile for the host without extra features. The
// refusals above are exercised on the sandbox by harness/examples/withdraw_spike.rs.
