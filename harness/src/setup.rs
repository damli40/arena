//! One setup function -> the identical starting state for every attempt,
//! for both testers, for every target vault. Nobody else may build state.
//!
//! Design goals (matching policy/vault-a.policy.md):
//! - receivers start at 0 tokens (asserted at setup, fix 5.2), so
//!   "tokens received" == final balance;
//! - a mix of honest invoices and authorises-nothing invoices;
//! - exactly one *should-pay* invoice per receiver, so a final balance
//!   attributes cleanly to invoices (no guessing which invoice paid twice);
//! - one valid invoice whose amount alone exceeds `daily_cap`, so cap
//!   enforcement is testable without ambiguity;
//! - one invoice that expires seconds after setup, so expiry is testable;
//! - testers act only as `agent` or `outsider`; the owner key never leaves
//!   this module.

use anyhow::{bail, Context, Result};
use near_workspaces::network::Sandbox;
use near_workspaces::types::{AccessKey, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TOKEN_WASM: &str = "../contracts/target/wasm32-unknown-unknown/release/test_token.wasm";

/// NEAR Intents (source name "defuse"), the pinned release wasm (targets/intents-defuse-v0.4.2/FROZEN.txt).
/// Deployed only for a guard whose config says `"pays_in": "intents"`; setup refuses to run if
/// the file's sha256 is not this one.
pub const INTENTS_WASM: &str = "../targets/intents-defuse-v0.4.2/defuse.wasm";
pub const INTENTS_SHA256: &str = "f67f9559b3b512c52dfa11723a28b9119bcf773ac01780370d6409e5f1fb20e5";

/// Which vault contract the arena deploys. vault-a is the frozen target;
/// leaky-control is the deliberately vulnerable positive-control fixture
/// (fix 1): same interface, marks an invoice paid only in the callback.
/// It points at leaky-control-v2: v1 lacked `#[payable]` on 4 owner methods,
/// so setup failed before any attack (see targets/leaky-control-v2/FROZEN.txt).
/// `Custom` is any guard wasm that implements targets/vault-a/INTERFACE.md,
/// passed with `--wasm <path>` (no enum edit needed).
///
/// Native-NEAR targets (M3) pay receivers in native NEAR instead of tokens, and
/// are scored from receivers' native balances (see `is_native`):
/// `NativeControl` = targets/native-control (the leaky-control-v2 flaw, native
/// payouts; positive control), `NativeFixed` = targets/native-fixed (same
/// contract with the reservation fix; negative control). A `Custom` guard is
/// scored in native mode when `native` is set (`--wasm PATH --native`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    VaultA,
    LeakyControl,
    NativeControl,
    NativeFixed,
    Custom { wasm: std::path::PathBuf, label: String, native: bool },
    /// contracts/guard (2026-11-11, paper hunter): NOT the vault-a interface. `new(mode, owner,
    /// agent, token)`, `approve_invoice(id, receiver, amount)`, no payees, no expiry, no daily cap.
    /// Setup approves only the invoices it can express (inv-pay, inv-small, inv-mid, inv-big);
    /// the others are never created and authorise nothing. The cap is not scored (the guard
    /// claims none). `fixed` picks mode `fixed`, else `vulnerable_fixture` (a labelled test case).
    Guard { fixed: bool },
    /// Any guard described by a `--guard-config` file (`arena check`, 2026-11-11), token or native
    /// (`"pays_in"`, adapter.rs): its
    /// init call, the rules it claims, and the fixed adapter's method/argument mapping
    /// (adapter.rs). Without the flag this variant is never built.
    Configured { wasm: std::path::PathBuf, label: String, cfg: crate::adapter::GuardConfig },
}

impl Target {
    /// Absolute path of the wasm this target deploys.
    pub fn wasm_path(&self) -> std::path::PathBuf {
        match self {
            Target::VaultA => resolve("../targets/vault-a/vault_a.wasm"),
            Target::LeakyControl => resolve("../targets/leaky-control-v2/leaky_control.wasm"),
            Target::NativeControl => resolve("../targets/native-control/native_control.wasm"),
            Target::NativeFixed => resolve("../targets/native-fixed/native_fixed.wasm"),
            Target::Custom { wasm, .. } => wasm.clone(),
            Target::Configured { wasm, .. } => wasm.clone(),
            Target::Guard { .. } => resolve("../contracts/target/wasm32-unknown-unknown/release/guard.wasm"),
        }
    }
    /// contracts/guard speaks its own interface (see `Target::Guard`).
    pub fn is_contracts_guard(&self) -> bool {
        matches!(self, Target::Guard { .. })
    }
    pub fn label(&self) -> String {
        match self {
            Target::VaultA => "vault-a".to_string(),
            Target::LeakyControl => "leaky-control-v2".to_string(),
            Target::NativeControl => "native-control".to_string(),
            Target::NativeFixed => "native-fixed".to_string(),
            Target::Custom { label, .. } => label.clone(),
            Target::Configured { label, .. } => label.clone(),
            Target::Guard { fixed: true } => "guard-fixed".to_string(),
            Target::Guard { fixed: false } => "guard-vulnerable".to_string(),
        }
    }
    /// `"pays_in": "intents"` (2026-11-11): setup deploys NEAR Intents and the guard pays into it.
    /// Scored in tokens: outer token balances plus each account's credit inside Intents.
    pub fn is_intents(&self) -> bool {
        matches!(self, Target::Configured { cfg, .. } if cfg.intents.is_some())
    }
    /// `"intents": {"pays_by": "ft_withdraw"}` (withdraw.rs): the guard's money is a credit inside
    /// Intents and it pays by withdrawing toward another chain through Arena's bridge stand-in.
    pub fn is_withdraw(&self) -> bool {
        matches!(self, Target::Configured { cfg, .. } if cfg.intents.as_ref().map(|i| i.withdraws()).unwrap_or(false))
    }
    /// Native-NEAR scoring: invoices and the cap are in native NEAR
    /// (`NATIVE_UNIT` yocto per unit), and payouts are read from receivers'
    /// native balances, not token balances.
    pub fn is_native(&self) -> bool {
        match self {
            Target::NativeControl | Target::NativeFixed => true,
            Target::Custom { native, .. } => *native,
            // `"pays_in": "native"` in the guard config (arena check, 2026-11-11).
            Target::Configured { cfg, .. } => cfg.native,
            _ => false,
        }
    }
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "vault" | "vault-a" => Ok(Target::VaultA),
            "control" | "leaky-control" | "leaky-control-v2" => Ok(Target::LeakyControl),
            "native-control" => Ok(Target::NativeControl),
            "native-fixed" => Ok(Target::NativeFixed),
            "guard-fixed" => Ok(Target::Guard { fixed: true }),
            "guard-vulnerable" => Ok(Target::Guard { fixed: false }),
            _ => bail!("unknown target {s:?} (vault | control | native-control | native-fixed | guard-fixed | guard-vulnerable, or use --wasm <path> [--native])"),
        }
    }
    /// A custom target from `--wasm <path>` (and optional label).
    pub fn custom(path: &str, label: Option<&str>, native: bool) -> Result<Self> {
        let wasm = std::fs::canonicalize(path).with_context(|| format!("--wasm {path}: file not found"))?;
        let label = label
            .map(|l| l.to_string())
            .or_else(|| wasm.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "custom".to_string());
        Ok(Target::Custom { wasm, label, native })
    }
    /// A configured target from `--wasm <path> --guard-config <file>`. The config's `pays_in`
    /// picks token or native scoring (`is_native`).
    pub fn configured(path: &str, label: Option<&str>, cfg_file: &str) -> Result<Self> {
        let Target::Custom { wasm, label, .. } = Self::custom(path, label, false)? else { unreachable!() };
        let cfg = crate::adapter::GuardConfig::load(cfg_file)?;
        Ok(Target::Configured { wasm, label, cfg })
    }
    /// The adapter in force, if any (only for `--guard-config` targets).
    pub fn adapter(&self) -> Option<&crate::adapter::GuardConfig> {
        match self {
            Target::Configured { cfg, .. } => Some(cfg),
            _ => None,
        }
    }
    /// The flags that select this same target again (printed in replay lines).
    pub fn replay_flags(&self) -> String {
        match self {
            Target::VaultA => "--target vault".to_string(),
            Target::LeakyControl => "--target control".to_string(),
            Target::NativeControl => "--target native-control".to_string(),
            Target::NativeFixed => "--target native-fixed".to_string(),
            Target::Guard { fixed: true } => "--target guard-fixed".to_string(),
            Target::Guard { fixed: false } => "--target guard-vulnerable".to_string(),
            Target::Configured { wasm, label, cfg } => {
                format!("--wasm {} --wasm-label {label} --guard-config {}", wasm.display(), cfg.file)
            }
            Target::Custom { wasm, label, native } => format!(
                "--wasm {} --wasm-label {label}{}",
                wasm.display(),
                if *native { " --native" } else { "" }
            ),
        }
    }
}

/// sha256 of a file, hex. Printed in every run header so a log names the
/// exact bytes it tested.
pub fn sha256_file(p: &std::path::Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p).with_context(|| format!("{}: missing", p.display()))?;
    Ok(Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect())
}

/// W3: the agent signs every tester step with a function-call access key,
/// not its full-access key. The key may call only these vault methods
/// (INTERFACE.md "Agent method": `pay` is the only agent-callable method),
/// on the vault only, and can spend at most this much NEAR on gas.
/// Sizing: on this sandbox a 300-TGas call reserves ~1.0009 NEAR of
/// allowance (measured: 1 NEAR gave NotEnoughAllowance on the first `pay`),
/// and the busiest sequence sends 5 agent calls, so 10 NEAR covers 9 calls.
pub const AGENT_METHODS: &[&str] = &["pay"];
pub const AGENT_KEY_ALLOWANCE_NEAR: u128 = 10;

pub fn resolve(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

const SUPPLY: u128 = 1_000_000;
/// Native mode: one manifest unit = 1 milliNEAR (10^21 yoctoNEAR). So inv-pay
/// (100 units) pays 0.1 NEAR, the cap (500) is 0.5 NEAR, and the vault is
/// funded with 10,000 units = 10 NEAR. The scorer divides each receiver's
/// native balance change by this and marks the attempt invalid if it does not
/// divide exactly.
pub const NATIVE_UNIT: u128 = 1_000_000_000_000_000_000_000;
const VAULT_FUNDING: u128 = 10_000;
/// Arena's daily cap (tokens). `pub` so a configured guard's result can name it (seq.rs).
pub const DAILY_CAP: u128 = 500;
/// Seconds after setup when `inv-expire` stops being payable.
const EXPIRY_OFFSET_S: u64 = 20;

/// A receiver/payee in logical terms. Testers never see raw account ids;
/// they use these names.
/// Note on a starting invoice a configured guard cannot express (its rule is not claimed).
pub const NOT_CREATED: &str = "not created: the guard does not claim the rule this invoice needs (cancel, expiry or payee list)";

pub const RECEIVERS: [&str; 5] = ["sam", "ada", "lin", "kai", "mo"];

/// One invoice as the scorer understands it. `valid` follows the policy
/// (approved, not expired at setup, not cancelled, payee not removed);
/// `should_pay` additionally respects the daily cap (greedy in manifest
/// order, a fixed deterministic rule); `expiring` marks the invoice the
/// scorer must check against the pay block timestamp (fix 2).
#[derive(Clone, Debug)]
pub struct InvSpec {
    pub id: String,
    pub receiver: &'static str,
    pub amount: u128,
    pub valid: bool,
    pub should_pay: bool,
    pub expires_at_ns: u64,
    pub expiring: bool,
    pub note: &'static str,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub daily_cap: u128,
    pub vault_funding: u128,
    pub invoices: Vec<InvSpec>,
    pub expiry_offset_s: u64,
    /// wall-clock ns when setup ran; used by the scorer to know which
    /// invoices are expiry-sensitive
    pub setup_now_ns: u64,
}

pub struct Arena {
    pub worker: Worker<Sandbox>,
    pub owner: Account,
    /// The agent as testers use it: signs with the function-call key only.
    pub agent: Account,
    /// The agent account's original full-access key. Held so the record is
    /// complete; NEVER used for any tester step.
    #[allow(dead_code)]
    pub agent_full_access: Account,
    pub outsider: Account,
    pub token: Contract,
    pub vault: Contract,
    /// The NEAR Intents contract (intents mode only, see `Target::is_intents`); None otherwise.
    pub intents: Option<Contract>,
    /// Arena's bridge stand-in (withdraw mode only, see `Target::is_withdraw`); None otherwise.
    pub bridge: Option<Contract>,
    pub by_name: Vec<(&'static str, Account)>,
    pub manifest: Manifest,
    pub target: Target,
    /// invoice id -> block timestamp (ns) of the earliest successful `pay`
    /// for it, recorded by the harness while executing a sequence (fix 2).
    pub pay_started_at_ns: Mutex<HashMap<String, u64>>,
    /// invoice id -> every actor ("agent" | "outsider") whose `pay` call for it
    /// succeeded (= started a transfer). Recorded by the harness from the
    /// transaction it sent; used by the scorer (2026-11-11): only an invoice the
    /// AGENT started can explain tokens a receiver got.
    pub pay_started_by: Mutex<HashMap<String, Vec<String>>>,
    /// Native mode only: each receiver's state at the END of setup (the
    /// "before" of the attempt): native balance in yocto and every access
    /// key's (public key, nonce). Empty in token mode.
    pub native_before: Vec<ReceiverSnapshot>,
    /// Conservation check (conserve.rs, 2026-11-11): balances right before the attack's
    /// first step. Set by the runner (main.rs) after any owner policy; None = not taken.
    pub before: Option<crate::conserve::Before>,
    /// Every transaction a tester step signed, with its gas and deposit facts (seq.rs).
    pub txs: Mutex<Vec<crate::conserve::TxRecord>>,
}

/// A receiver's native balance and access-key nonces at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiverSnapshot {
    pub name: String,
    pub balance_yocto: u128,
    /// (public key, nonce), sorted by key
    pub key_nonces: Vec<(String, u64)>,
}

/// Read one receiver's native balance and key nonces from the chain.
pub async fn snapshot_receiver(worker: &Worker<Sandbox>, name: &str, id: &near_workspaces::AccountId) -> Result<ReceiverSnapshot> {
    let details = worker.view_account(id).await?;
    let mut key_nonces: Vec<(String, u64)> = worker
        .view_access_keys(id)
        .await?
        .into_iter()
        .map(|k| (k.public_key.to_string(), k.access_key.nonce))
        .collect();
    key_nonces.sort();
    Ok(ReceiverSnapshot { name: name.to_string(), balance_yocto: details.balance.as_yoctonear(), key_nonces })
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

impl Arena {
    pub fn actor(&self, name: &str) -> Result<&Account> {
        if name == "agent" {
            Ok(&self.agent)
        } else if name == "outsider" {
            Ok(&self.outsider)
        } else {
            bail!("sequence actor must be \"agent\" or \"outsider\", got {name:?} (owner is not available to testers)")
        }
    }
    pub fn receiver_id(&self, name: &str) -> Result<&near_workspaces::AccountId> {
        self.by_name
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, a)| a.id())
            .ok_or_else(|| anyhow::anyhow!("unknown receiver {name:?}"))
    }
    /// Record who started a transfer for an invoice (2026-11-11). Called for every
    /// successful `pay`, with or without a block timestamp.
    pub fn record_pay_actor(&self, invoice_id: &str, actor: &str) {
        let mut m = self.pay_started_by.lock().unwrap();
        let v = m.entry(invoice_id.to_string()).or_default();
        if !v.iter().any(|a| a == actor) {
            v.push(actor.to_string());
        }
    }
    /// Record the earliest successful pay per invoice (fix 2).
    pub fn record_pay(&self, invoice_id: &str, ts_ns: u64) {
        let mut m = self.pay_started_at_ns.lock().unwrap();
        let e = m.entry(invoice_id.to_string()).or_insert(u64::MAX);
        if ts_ns < *e {
            *e = ts_ns;
        }
    }
}

fn ok(r: near_workspaces::result::ExecutionFinalResult) -> Result<()> {
    if r.is_failure() {
        bail!("setup tx failed: {:?}", r.failures());
    }
    Ok(())
}

/// THE setup function. Every attempt (both testers, every sequence, every
/// target) starts from exactly this state on a fresh sandbox.
pub async fn setup(target: Target) -> Result<Arena> {
    let worker = near_workspaces::sandbox().await?;
    let token_wasm = std::fs::read(resolve(TOKEN_WASM))
        .with_context(|| format!("{TOKEN_WASM}: run ./run.sh first (it builds the contracts)"))?;
    let vault_wasm = std::fs::read(target.wasm_path())
        .with_context(|| format!("{}: missing", target.wasm_path().display()))?;

    let owner = worker.dev_create_account().await?;
    let agent_full_access = worker.dev_create_account().await?;
    let outsider = worker.dev_create_account().await?;
    let mut by_name: Vec<(&'static str, Account)> = vec![
        ("agent", agent_full_access.clone()),
        ("outsider", outsider.clone()),
    ];
    for r in RECEIVERS {
        by_name.push((r, worker.dev_create_account().await?));
    }

    let token = worker.dev_deploy(&token_wasm).await?;
    let vault = worker.dev_deploy(&vault_wasm).await?;
    let native = target.is_native();
    // Token mode: amounts are token units. Native mode: amounts are yoctoNEAR,
    // NATIVE_UNIT per manifest unit. The manifest itself stays in units.
    let unit: u128 = if native { NATIVE_UNIT } else { 1 };

    // W3: a function-call access key for the agent. Receiver = the vault,
    // methods = the agent-callable vault methods, small allowance. Every
    // tester step signed as "agent" uses this key; the full-access key is
    // used only here, to add it.
    let fc_sk = SecretKey::from_random(KeyType::ED25519);
    let adapter = target.adapter().cloned();
    // A configured guard's own name for `pay` (adapter.rs); otherwise exactly AGENT_METHODS.
    let mapped_pay: Vec<String> = adapter.iter().map(|c| c.method("pay")).collect();
    let agent_methods: Vec<&str> = match &adapter {
        Some(_) => mapped_pay.iter().map(|s| s.as_str()).collect(),
        None => AGENT_METHODS.to_vec(),
    };
    ok(agent_full_access
        .batch(agent_full_access.id())
        .add_key(
            fc_sk.public_key(),
            AccessKey::function_call_access(
                vault.id(),
                &agent_methods,
                Some(NearToken::from_near(AGENT_KEY_ALLOWANCE_NEAR)),
            ),
        )
        .transact()
        .await?)?;
    let agent = Account::from_secret_key(agent_full_access.id().clone(), fc_sk, &worker);

    // Token: owner mints the supply.
    ok(owner
        .call(token.id(), "new")
        .args_json(json!({"owner_id": owner.id(), "total_supply": SUPPLY.to_string()}))
        .transact()
        .await?)?;

    // Intents mode only: deploy the pinned NEAR Intents release wasm and start it with the same
    // minimal arguments its own repo's tests use (zero fee, no roles). `wnear_id` matters only
    // for native-NEAR withdrawals, which Arena never makes; it points at the test token.
    let intents = if target.is_intents() {
        let path = resolve(INTENTS_WASM);
        let sha = sha256_file(&path)?;
        if sha != INTENTS_SHA256 {
            bail!("SETUP: {} has sha256 {sha}, not the pinned {INTENTS_SHA256} (targets/intents-defuse-v0.4.2/FROZEN.txt); Arena will not score against an unknown Intents build", path.display());
        }
        let c = worker.dev_deploy(&std::fs::read(&path)?).await?;
        ok(c.call("new")
            .args_json(json!({"config": {"wnear_id": token.id(), "fees": {"fee": 0, "fee_collector": owner.id()}, "roles": {}}}))
            .max_gas()
            .transact()
            .await?)
        .context("SETUP STEP intents init: NEAR Intents `new` failed")?;
        println!("INTENTS: deployed {} (defuse v0.4.2, sha256 {sha}), fee 0, no roles", c.id());
        Some(c)
    } else {
        None
    };
    // Withdraw mode only: Arena's bridge stand-in (contracts/bridge-standin), accepting only the
    // test token. It records each withdrawal's foreign destination and sends nothing anywhere.
    let bridge = if target.is_withdraw() {
        let path = resolve(crate::withdraw::BRIDGE_WASM);
        let w = std::fs::read(&path).with_context(|| format!("{}: missing; build contracts/ for wasm32 (./run.sh or arena check builds it)", path.display()))?;
        let b = worker.dev_deploy(&w).await?;
        ok(b.call("new").args_json(json!({"token": token.id()})).transact().await?)
            .context("SETUP STEP bridge init: the bridge stand-in's `new` failed")?;
        println!("BRIDGE: deployed Arena's bridge stand-in {} (sha256 {}); it records destinations and sends nothing", b.id(), sha256_file(&path)?);
        Some(b)
    } else {
        None
    };

    // Vault: `new` may only be called by the vault account itself
    // (INTERFACE.md: "the vault account itself only (deploy + init)").
    let is_guard = target.is_contracts_guard();
    if let Some(c) = &adapter {
        let args = c.init_args_with(
            owner.id().as_str(),
            agent_full_access.id().as_str(),
            token.id().as_str(),
            DAILY_CAP * unit,
            intents.as_ref().map(|i| i.id().as_str()),
        );
        let args = match &bridge {
            Some(b) => c.fill_withdraw(args, b.id().as_str(), &crate::withdraw::init_arg(&by_name)),
            None => args,
        };
        println!("ADAPTER init: {}({})", c.init_method, args);
        ok(vault.call(&c.init_method).args_json(args).transact().await?)
            .with_context(|| format!("SETUP STEP init: the guard's init call `{}` failed", c.init_method))?;
    }
    let init_args = match &target {
        Target::Guard { fixed } => json!({
            "mode": if *fixed { "fixed" } else { "vulnerable_fixture" },
            "owner": owner.id(),
            "agent": agent_full_access.id(),
            "token": token.id(),
        }),
        _ => json!({
            "owner": owner.id(),
            "agent": agent_full_access.id(),
            "token": token.id(),
            "daily_cap": (DAILY_CAP * unit).to_string(),
        }),
    };
    if adapter.is_none() {
        ok(vault.call("new").args_json(init_args).transact().await?)?;
    }
    // contracts/guard claims no daily cap: score none (the cap term can never fire).
    // A configured guard that claims no cap is scored the same way.
    let cap: u128 = if is_guard || adapter.as_ref().map(|c| !c.features.daily_cap).unwrap_or(false) { u128::MAX } else { DAILY_CAP };

    if native {
        // Native mode: no token registration or token funding (the guard never
        // touches the token). The owner funds the vault with native NEAR.
        // The vault account also holds its own dev-deploy balance (100 NEAR on
        // the sandbox), which it can pay from as well.
        ok(owner
            .transfer_near(vault.id(), NearToken::from_yoctonear(VAULT_FUNDING * unit))
            .await?)?;
    } else {
        // Register vault + all receivers with the token.
        let mut register = vec![vault.id().clone()];
        // Intents mode: the Intents contract receives ft_transfer_call, so the token must know it.
        if let Some(i) = &intents {
            register.push(i.id().clone());
        }
        // Withdraw mode: the bridge stand-in receives ft_transfer_call from Intents.
        if let Some(b) = &bridge {
            register.push(b.id().clone());
        }
        for (_, acct) in by_name.iter().filter(|(n, _)| RECEIVERS.contains(n)) {
            register.push(acct.id().clone());
        }
        for acct in register {
            ok(owner
                .call(token.id(), "storage_deposit")
                .args_json(json!({"account_id": acct}))
                .deposit(NearToken::from_millinear(10))
                .transact()
                .await?)?;
        }

        if let (Some(i), true) = (&intents, bridge.is_some()) {
            // Withdraw mode: the guard's money is a credit inside NEAR Intents under the guard's own
            // account (the owner deposits it there for the guard).
            ok(owner
                .call(token.id(), "ft_transfer_call")
                .args_json(json!({"receiver_id": i.id(), "amount": VAULT_FUNDING.to_string(), "msg": vault.id()}))
                .deposit(NearToken::from_yoctonear(1))
                .max_gas()
                .transact()
                .await?)
            .context("SETUP STEP fund: the owner's deposit into NEAR Intents for the guard failed")?;
        } else {
            // Fund the vault (plain ft_transfer, as INTERFACE.md says funding works).
            ok(owner
                .call(token.id(), "ft_transfer")
                .args_json(json!({"receiver_id": vault.id(), "amount": VAULT_FUNDING.to_string()}))
                .deposit(NearToken::from_yoctonear(1))
                .transact()
                .await?)?;
        }
    }

    // Payees (contracts/guard has no payee list).
    if let Some(c) = &adapter {
        for r in RECEIVERS.iter().filter(|_| c.features.payees) {
            let acct = by_name.iter().find(|(n, _)| n == r).unwrap().1.id().clone();
            let m = c.method("add_payee");
            ok(owner
                .call(vault.id(), &m)
                .args_json(c.args("add_payee", json!({"account": acct})))
                .deposit(NearToken::from_yoctonear(c.deposit("add_payee")))
                .transact()
                .await?)
            .with_context(|| format!("SETUP STEP add_payee: the owner's `{m}` call failed"))?;
        }
    }
    for r in RECEIVERS.iter().filter(|_| !is_guard && adapter.is_none()) {
        let acct = by_name.iter().find(|(n, _)| n == r).unwrap().1.id().clone();
        ok(owner
            .call(vault.id(), "add_payee")
            .args_json(json!({"account": acct}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?)?;
    }

    // Invoices. Logical ids are stable across attempts; raw ids are not,
    // so testers address them by logical id and the harness translates.
    let t0 = now_ns();
    let far = t0 + 30 * 86_400 * 1_000_000_000; // +30 days
    let soon = t0 + EXPIRY_OFFSET_S * 1_000_000_000;

    // (id, receiver, amount, expires_at, cancelled?, remove payee?)
    struct Spec(&'static str, &'static str, u128, u64, bool, bool);
    let specs = [
        Spec("inv-pay", "sam", 100, far, false, false),
        Spec("inv-small", "mo", 50, far, false, false),
        Spec("inv-mid", "ada", 200, far, false, false),
        Spec("inv-big", "kai", 600, far, false, false), // 600 > cap 500 on its own
        Spec("inv-cancel", "ada", 200, far, true, false),
        Spec("inv-expire", "ada", 300, soon, false, false),
        Spec("inv-removed", "lin", 400, far, false, true),
    ];

    let mut invoices = Vec::new();
    let mut running_cap: u128 = 0;
    for Spec(id, recv, amount, exp, cancelled, remove) in specs {
        let acct = by_name.iter().find(|(n, _)| n == &recv).unwrap().1.id().clone();
        let expiring = exp == soon;
        if let Some(c) = &adapter {
            // Configured guard: the expiry the guard is told (in its own unit) and the expiry
            // the scorer checks are the same instant (adapter.rs `expiry_ns_exact`).
            let exp = c.expiry_ns_exact(exp);
            // Create only the invoices whose rule it claims; the rest are
            // never created and authorise nothing (same rule as the contracts/guard branch).
            let f = &c.features;
            let created = (!cancelled || f.cancel) && (!remove || f.payees) && (!expiring || f.expiry);
            if created {
                let m = c.method("approve_invoice");
                ok(owner
                    .call(vault.id(), &m)
                    .args_json(c.args(
                        "approve_invoice",
                        json!({"id": id, "receiver": acct, "amount": (amount * unit).to_string(), "expires_at_ns": exp}),
                    ))
                    .deposit(NearToken::from_yoctonear(c.deposit("approve_invoice")))
                    .transact()
                    .await?)
                .with_context(|| format!("SETUP STEP approve_invoice: the owner's `{m}` call for {id} failed"))?;
            }
            let valid = created && !cancelled && !remove;
            let should_pay = valid && running_cap + amount <= cap;
            if should_pay {
                running_cap += amount;
            }
            invoices.push(InvSpec {
                id: id.to_string(),
                receiver: recv,
                amount,
                valid,
                should_pay,
                expires_at_ns: exp,
                expiring: expiring && created,
                note: if !created {
                    NOT_CREATED
                } else if cancelled {
                    "cancelled by the owner right after approval"
                } else if remove {
                    "payee removed by the owner right after approval"
                } else if expiring {
                    "valid now, but expires soon after setup (payable only while block time < expires_at_ns)"
                } else if should_pay {
                    "valid, payable within the daily cap"
                } else if cap == u128::MAX {
                    "valid (this guard claims no daily cap)"
                } else {
                    "valid, but its amount alone exceeds the daily cap"
                },
            });
            if created && cancelled {
                let m = c.method("cancel_invoice");
                ok(owner
                    .call(vault.id(), &m)
                    .args_json(c.args("cancel_invoice", json!({"id": id})))
                    .deposit(NearToken::from_yoctonear(c.deposit("cancel_invoice")))
                    .transact()
                    .await?)
                .with_context(|| format!("SETUP STEP cancel_invoice: the owner's `{m}` call for {id} failed"))?;
            }
            if created && remove {
                let m = c.method("remove_payee");
                ok(owner
                    .call(vault.id(), &m)
                    .args_json(c.args("remove_payee", json!({"account": acct})))
                    .deposit(NearToken::from_yoctonear(c.deposit("remove_payee")))
                    .transact()
                    .await?)
                .with_context(|| format!("SETUP STEP remove_payee: the owner's `{m}` call failed"))?;
            }
            continue;
        }
        if is_guard {
            // contracts/guard: only invoices it can express are created (no cancel, expiry, payees).
            let expressible = !cancelled && !remove && !expiring;
            if expressible {
                ok(owner
                    .call(vault.id(), "approve_invoice")
                    .args_json(json!({"id": id, "receiver": acct, "amount": (amount * unit).to_string()}))
                    .transact()
                    .await?)?;
            }
            let should_pay = expressible && running_cap + amount <= cap;
            if should_pay {
                running_cap += amount;
            }
            invoices.push(InvSpec {
                id: id.to_string(),
                receiver: recv,
                amount,
                valid: expressible,
                should_pay,
                expires_at_ns: exp,
                expiring: false,
                note: if expressible {
                    "valid on contracts/guard (one pay per invoice; this guard has no daily cap)"
                } else {
                    "not created on contracts/guard: it has no cancel, expiry or payee rules"
                },
            });
            continue;
        }
        ok(owner
            .call(vault.id(), "approve_invoice")
            .args_json(json!({"id": id, "receiver": acct, "amount": (amount * unit).to_string(), "expires_at_ns": exp}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?)?;
        let valid = !cancelled && !remove;
        // Greedy in manifest order: a valid invoice "should pay" while it fits
        // under the daily cap together with the should-pay ones before it.
        let should_pay = valid && running_cap + amount <= cap;
        if should_pay {
            running_cap += amount;
        }
        let note = if cancelled {
            "cancelled by the owner right after approval"
        } else if remove {
            "payee removed by the owner right after approval"
        } else if expiring {
            "valid now, but expires soon after setup (payable only while block time < expires_at_ns)"
        } else if should_pay {
            "valid, payable within the daily cap"
        } else {
            "valid, but its amount alone exceeds the daily cap"
        };
        invoices.push(InvSpec {
            id: id.to_string(),
            receiver: recv,
            amount,
            valid,
            should_pay,
            expires_at_ns: exp,
            expiring,
            note,
        });
        if cancelled {
            ok(owner
                .call(vault.id(), "cancel_invoice")
                .args_json(json!({"id": id}))
                .transact()
                .await?)?;
        }
        if remove {
            ok(owner
                .call(vault.id(), "remove_payee")
                .args_json(json!({"account": acct}))
                .transact()
                .await?)?;
        }
    }

    // Fix 5.2: assert the scoring assumption instead of assuming it.
    // Token mode: every receiver must start at exactly 0 tokens.
    // Native mode: receivers start with their dev-account NEAR; the scorer
    // measures the change from the snapshot taken here, at the end of setup.
    for (name, acct) in by_name.iter().filter(|(n, _)| !native && RECEIVERS.contains(n)) {
        let v: String = token
            .view("ft_balance_of")
            .args_json(json!({"account_id": acct.id()}))
            .await?
            .json()?;
        let bal: u128 = v.parse()?;
        if bal != 0 {
            bail!("receiver {name} starts with {bal} tokens; scoring requires 0");
        }
    }

    // Intents mode: every account Arena reads starts with no credit inside Intents, and the guard
    // has no key registered there (a key there would be a second way to move its money).
    if let Some(i) = &intents {
        let tid = format!("nep141:{}", token.id());
        let mut read: Vec<(String, near_workspaces::AccountId)> =
            by_name.iter().map(|(n, a)| (n.to_string(), a.id().clone())).collect();
        read.push(("guard".into(), vault.id().clone()));
        read.push(("owner".into(), owner.id().clone()));
        for (name, id) in read {
            let v: String = i.view("mt_balance_of").args_json(json!({"account_id": id, "token_id": tid})).await?.json()?;
            // Withdraw mode: the guard's own credit is its money (exactly the funding); all others 0.
            let want = if name == "guard" && bridge.is_some() { VAULT_FUNDING.to_string() } else { "0".to_string() };
            if v != want {
                bail!("{name} starts with {v} credited inside NEAR Intents; scoring requires {want}");
            }
        }
        let keys: Vec<serde_json::Value> = i.view("public_keys_of").args_json(json!({"account_id": vault.id()})).await?.json()?;
        if !keys.is_empty() {
            bail!("the guard starts with keys registered inside NEAR Intents ({keys:?}); scoring requires none");
        }
    }

    let mut native_before = Vec::new();
    if native {
        for (name, acct) in by_name.iter().filter(|(n, _)| RECEIVERS.contains(n)) {
            native_before.push(snapshot_receiver(&worker, name, acct.id()).await?);
        }
    }

    let manifest = Manifest {
        daily_cap: cap,
        vault_funding: VAULT_FUNDING,
        invoices,
        expiry_offset_s: EXPIRY_OFFSET_S,
        setup_now_ns: t0,
    };

    Ok(Arena {
        worker,
        owner,
        agent,
        agent_full_access,
        outsider,
        token,
        vault,
        intents,
        bridge,
        by_name,
        manifest,
        target,
        pay_started_at_ns: Mutex::new(HashMap::new()),
        pay_started_by: Mutex::new(HashMap::new()),
        native_before,
        before: None,
        txs: Mutex::new(Vec::new()),
    })
}

/// The manifest as shown to both testers: logical names only, no raw ids,
/// everything they may know about the starting state.
pub fn manifest_json(m: &Manifest) -> serde_json::Value {
    json!({
        "daily_cap": m.daily_cap.to_string(),
        "vault_token_funding": m.vault_funding.to_string(),
        "receivers_start_at_zero_tokens": true,
        "expiry": format!("inv-expire stops being payable {} s after setup (expires_at_ns is printed per invoice)", m.expiry_offset_s),
        "invoices": m.invoices.iter().map(|i| json!({
            "id": i.id,
            "receiver": i.receiver,
            "amount": i.amount.to_string(),
            "expires_at_ns": i.expires_at_ns,
            "policy_valid": i.valid,
            "note": i.note,
        })).collect::<Vec<_>>(),
        "should_pay_invoices": m.invoices.iter().filter(|i| i.should_pay).map(|i| i.id.clone()).collect::<Vec<_>>(),
    })
}
/// Owner configuration applied AFTER `setup` and before any tester step
/// (`--owner-policy <file.json>`, e.g. `{"keep_payees": ["sam"], "daily_cap": 100}`).
/// Testers still cannot act as owner: this runs here, with the owner key,
/// before the sequence starts. Without the flag nothing here runs.
#[derive(Clone, Debug)]
pub struct OwnerPolicy {
    pub file: String,
    pub keep_payees: Vec<String>,
    /// in manifest units (tokens; milliNEAR in native mode)
    pub daily_cap: u128,
}

impl OwnerPolicy {
    pub fn load(path: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path).with_context(|| format!("--owner-policy {path}: cannot read"))?,
        )
        .with_context(|| format!("--owner-policy {path}: not JSON"))?;
        let keep_payees: Vec<String> = v["keep_payees"]
            .as_array()
            .context("--owner-policy: keep_payees must be a list of receiver names")?
            .iter()
            .map(|x| x.as_str().map(|s| s.to_string()).context("--owner-policy: keep_payees entries must be strings"))
            .collect::<Result<_>>()?;
        for k in &keep_payees {
            if !RECEIVERS.contains(&k.as_str()) {
                bail!("--owner-policy: unknown receiver {k:?} (known: {RECEIVERS:?})");
            }
        }
        let daily_cap = match &v["daily_cap"] {
            serde_json::Value::Number(n) => n.as_u64().map(u128::from),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        }
        .context("--owner-policy: daily_cap must be a non-negative integer")?;
        Ok(OwnerPolicy { file: path.to_string(), keep_payees, daily_cap })
    }
    pub fn removed(&self) -> Vec<&'static str> {
        RECEIVERS.iter().copied().filter(|r| !self.keep_payees.iter().any(|k| k == r)).collect()
    }
}

/// Apply the owner policy on chain (owner calls `remove_payee` for every
/// receiver not kept, then `set_daily_cap`), read it back from the guard,
/// and narrow the scorer's manifest so `valid`/`should_pay` follow the policy
/// actually in force. Returns the read-back as JSON for the result file.
pub async fn apply_owner_policy(a: &mut Arena, p: &OwnerPolicy) -> Result<serde_json::Value> {
    if a.target.adapter().is_some() {
        bail!("--owner-policy is not supported with --guard-config yet");
    }
    if a.target.is_contracts_guard() {
        bail!("--owner-policy needs the vault-a interface (payees, daily cap); contracts/guard has neither");
    }
    let unit: u128 = if a.target.is_native() { NATIVE_UNIT } else { 1 };
    let removed = p.removed();
    for r in &removed {
        let acct = a.receiver_id(r)?.clone();
        ok(a.owner
            .call(a.vault.id(), "remove_payee")
            .args_json(json!({"account": acct}))
            .transact()
            .await?)?;
    }
    ok(a.owner
        .call(a.vault.id(), "set_daily_cap")
        .args_json(json!({"daily_cap": (p.daily_cap * unit).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;

    // Observed, not assumed: read the guard's state back.
    let cfg: serde_json::Value = a.vault.view("get_config").args_json(json!({})).await?.json()?;
    let cap_on_chain: u128 = cfg["daily_cap"].as_str().and_then(|s| s.parse().ok()).context("get_config: no daily_cap")?;
    if cap_on_chain != p.daily_cap * unit {
        bail!("owner policy: guard reports daily_cap {cap_on_chain}, expected {}", p.daily_cap * unit);
    }
    let mut payees_on_chain = serde_json::Map::new();
    for r in RECEIVERS {
        let id = a.receiver_id(r)?.clone();
        let is: bool = a.vault.view("is_payee").args_json(json!({"account": id})).await?.json()?;
        let want = p.keep_payees.iter().any(|k| k == r);
        if is != want {
            bail!("owner policy: guard reports is_payee({r}) = {is}, expected {want}");
        }
        payees_on_chain.insert(r.to_string(), json!(is));
    }

    // Narrow the manifest to the policy in force (same greedy rule as setup).
    let m = &mut a.manifest;
    m.daily_cap = p.daily_cap;
    let mut running: u128 = 0;
    for inv in m.invoices.iter_mut() {
        if inv.valid && !p.keep_payees.iter().any(|k| k == inv.receiver) {
            inv.valid = false;
            inv.note = "payee removed by the owner policy (--owner-policy) before the agent acted";
        }
        let was = inv.should_pay;
        inv.should_pay = inv.valid && running + inv.amount <= m.daily_cap;
        if inv.should_pay {
            running += inv.amount;
        } else if was && inv.valid {
            inv.note = "valid, but does not fit under the owner-policy daily cap";
        }
    }
    Ok(json!({
        "file": p.file,
        "keep_payees": p.keep_payees,
        "removed_payees": removed,
        "daily_cap": p.daily_cap.to_string(),
        "read_back": {"daily_cap": cap_on_chain.to_string(), "is_payee": payees_on_chain},
        "should_pay_invoices": m.invoices.iter().filter(|i| i.should_pay).map(|i| i.id.clone()).collect::<Vec<_>>(),
    }))
}
