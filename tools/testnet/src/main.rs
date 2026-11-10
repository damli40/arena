//! Testnet replay of the local race test (tests/tests/race.rs, t1 and t2).
//!
//! Question it answers: "is the local 200-paid-on-a-100-invoice result just a
//! sandbox quirk?" It runs the same experiment on NEAR testnet with our own guard.
//!
//! NEAR TESTNET ONLY. Never mainnet. No real funds: every account is a fresh
//! testnet dev account funded by the testnet helper (faucet).
//!
//! Per trial (fresh accounts every trial):
//!   1. create owner, agent, receiver (sam); deploy test token + guard (mode = arg);
//!   2. owner funds the guard with 1,000 test tokens and approves ONE 100-token invoice;
//!   3. the agent submits two `pay` calls for that invoice without waiting for either;
//!   4. record tx hashes, the block height of every step, the receiver's final balance,
//!      the guard's own record, and the agent key nonce (proves exactly 2 pays were sent).
//!
//! Keys: every key is random and saved outside the repo in ~/.near-credentials/testnet
//! (mode 600, never printed). Since Nov 11 the funder is loaded from that file too; the
//! Nov 9 funder's key was derived from its own id (`SecretKey::from_seed`), so anyone
//! could rebuild it. That key is now used only by `consolidate`, to empty old dev accounts.
//!
//! Cost (Nov 11): after each trial its five accounts are deleted with the funder as
//! beneficiary, so their NEAR comes back. The LAST trial of each mode is kept alive so
//! the live contracts can be opened. Transactions stay in chain history either way.
//!
//! Usage:
//!   cargo run --release -- newfunder <prefix>          # ONE faucet account <prefix>.testnet, random key
//!   cargo run --release -- run <trials> <out.json> <funder-id> <tag> [modes...]

use near_workspaces::network::Testnet;
use near_workspaces::result::{ExecutionFinalResult, ExecutionOutcome};
use near_workspaces::types::{AccessKey, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const TOKEN_WASM: &str = "../../contracts/target/wasm32-unknown-unknown/release/test_token.wasm";
const GUARD_WASM: &str = "../../contracts/target/wasm32-unknown-unknown/release/guard.wasm";

const SUPPLY: u128 = 1_000_000;
const GUARD_FUNDING: u128 = 1_000;
const INVOICE_AMOUNT: u128 = 100;
const RULE: &str = "an invoice may pay at most its amount (100 test tokens)";

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

/// Polls a sent tx until it has a final result. Tolerates RPC errors/timeouts while
/// polling (up to ~3 min), and never re-sends: the tx was signed and broadcast once.
async fn wait_tx(st: near_workspaces::operations::TransactionStatus) -> anyhow::Result<ExecutionFinalResult> {
    let mut errors = 0;
    let started = Instant::now();
    loop {
        if started.elapsed().as_secs() > 120 {
            anyhow::bail!("tx {} not resolved within 120 s (the library may have re-signed it after a broadcast error; check the signer's key nonce)", st.hash());
        }
        match st.status().await {
            Ok(std::task::Poll::Ready(r)) => return Ok(r),
            Ok(std::task::Poll::Pending) => {}
            Err(e) => {
                errors += 1;
                if errors > 60 {
                    anyhow::bail!("tx {} still unresolved after {errors} RPC errors: {e}", st.hash());
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
}

fn ok_deploy(label: &str, r: near_workspaces::result::Execution<Contract>) -> anyhow::Result<Contract> {
    Ok(r.into_result().map_err(|e| anyhow::anyhow!("{label}: {e:?}"))?)
}

fn ok(label: &str, r: ExecutionFinalResult) -> anyhow::Result<ExecutionFinalResult> {
    if r.is_failure() {
        anyhow::bail!("setup step '{label}' failed: {:?}", r.failures());
    }
    Ok(r)
}

/// Retries a fallible async step a few times (the testnet helper and public RPC are flaky).
/// Only used for SETUP steps; the two `pay` calls are never retried.
macro_rules! retry {
    ($label:expr, $e:expr) => {{
        let mut last = None;
        let mut out = None;
        for attempt in 0..6u64 {
            match $e.await {
                Ok(v) => {
                    out = Some(v);
                    break;
                }
                Err(err) => {
                    eprintln!("  retry {}: attempt {} failed: {err}", $label, attempt + 1);
                    last = Some(err);
                    tokio::time::sleep(std::time::Duration::from_secs(30 * (attempt + 1))).await;
                }
            }
        }
        match out {
            Some(v) => v,
            None => return Err(anyhow::anyhow!("{} failed after retries: {:?}", $label, last)),
        }
    }};
}

async fn height(worker: &Worker<Testnet>, o: &ExecutionOutcome) -> anyhow::Result<u64> {
    let mut last = None;
    for _ in 0..4 {
        match worker.view_block().block_hash(o.block_hash).await {
            Ok(b) => return Ok(b.height()),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
    Err(anyhow::anyhow!("view_block failed: {:?}", last))
}

/// One row per execution step of a tx: role, executor, height, ok, logs.
async fn steps(worker: &Worker<Testnet>, r: &ExecutionFinalResult, guard: &str, token: &str) -> anyhow::Result<Vec<Value>> {
    let mut out = Vec::new();
    let mut seen_pay = false;
    let mut seen_transfer = false;
    for (i, o) in r.outcomes().into_iter().enumerate() {
        let ex = o.executor_id.as_str().to_string();
        let role = if i == 0 {
            "tx_to_receipt (agent signs)".to_string()
        } else if ex == guard && !seen_pay {
            seen_pay = true;
            "pay (guard: check + start transfer)".to_string()
        } else if ex == token && !seen_transfer {
            seen_transfer = true;
            "ft_transfer (token moves)".to_string()
        } else if ex == guard && seen_transfer {
            "on_transfer (guard callback: writes result)".to_string()
        } else {
            format!("other receipt on {ex} (e.g. gas refund)")
        };
        let h = height(worker, o).await?;
        out.push(json!({
            "role": role,
            "executor": ex,
            "block_height": h,
            "ok": o.is_success(),
            "logs": o.logs,
            "failure": if o.is_failure() { format!("{:?}", o.clone().into_result().err()) } else { String::new() },
        }));
    }
    Ok(out)
}

fn first_height(steps: &[Value], prefix: &str) -> Option<u64> {
    steps
        .iter()
        .find(|s| s["role"].as_str().unwrap_or("").starts_with(prefix))
        .and_then(|s| s["block_height"].as_u64())
}

fn failure_text(r: &ExecutionFinalResult) -> String {
    r.failures()
        .iter()
        .map(|f| format!("{:?}", (*f).clone().into_result().err()))
        .collect::<Vec<_>>()
        .join(" | ")
}

async fn ft_balance(token: &Contract, who: &near_workspaces::AccountId) -> anyhow::Result<u128> {
    let v: String = token
        .view("ft_balance_of")
        .args_json(json!({"account_id": who}))
        .await?
        .json()?;
    Ok(v.parse()?)
}

async fn agent_nonce(agent: &Account, agent2: &Account) -> anyhow::Result<u64> {
    let n1 = agent.view_access_key(&agent.secret_key().public_key()).await?.nonce;
    let n2 = agent2.view_access_key(&agent2.secret_key().public_key()).await?.nonce;
    Ok(n1 + n2)
}

/// Up-front NEAR one trial hands out (owner + agent + sam + token + guard), in milliNEAR.
fn agent_millinear() -> u128 {
    // 2.3 NEAR: enough for two 1,000-TGas pays reserved at once (1.0009 NEAR each, measured
    // Nov 9). 0.25 (run 6) and 1.5 (run 7) were too little; 2.3 worked in run 9.
    std::env::var("AGENT_MILLINEAR").ok().and_then(|v| v.parse().ok()).unwrap_or(2300)
}
const OWNER_MILLI: u128 = 250;
const SAM_MILLI: u128 = 50;
const CONTRACT_MILLI: u128 = 1950; // token and guard: ~187 KB of code each = ~1.88 NEAR of storage (2.0 until Nov 10)
fn trial_upfront_milli() -> u128 {
    OWNER_MILLI + agent_millinear() + SAM_MILLI + 2 * CONTRACT_MILLI
}

async fn balance(worker: &Worker<Testnet>, id: &near_workspaces::AccountId) -> anyhow::Result<u128> {
    Ok(worker.view_account(id).await?.balance.as_yoctonear())
}

/// Deletes one trial account, NEAR to the funder. Returns a JSON row (never fails the trial).
async fn delete_to(acct: Account, funder: &near_workspaces::AccountId) -> Value {
    let id = acct.id().to_string();
    for attempt in 0..3u64 {
        match acct.clone().delete_account(funder).await {
            Ok(r) => return json!({"account": id, "ok": r.is_success(), "tx": r.outcome().transaction_hash.to_string(),
                                   "failure": if r.is_failure() { failure_text(&r) } else { String::new() }}),
            Err(e) => {
                eprintln!("  delete {id}: attempt {} failed: {e}", attempt + 1);
                tokio::time::sleep(std::time::Duration::from_secs(10 * (attempt + 1))).await;
            }
        }
    }
    json!({"account": id, "ok": false, "tx": null, "failure": "delete failed after 3 attempts; key saved, use `reclaim`"})
}

#[allow(clippy::too_many_arguments)]
async fn trial(worker: &Worker<Testnet>, funder: &Account, tag: &str, mode: &str, n: usize, keep: bool, token_wasm: &[u8], guard_wasm: &[u8]) -> anyhow::Result<Value> {
    let t0 = Instant::now();
    eprintln!("== mode={mode} trial={n}: creating fresh accounts");
    // The five trial accounts are fresh subaccounts of one funder account, each with
    // a new random key. (The testnet faucet returned HTTP 429 after 6 accounts in run 1
    // and kept refusing for 10+ minutes, so trial accounts no longer come from the faucet.)
    let short = if mode == "fixed" { "fx" } else { "vf" };
    let sub = |name: &'static str, near_milli: u128| {
        let f = funder.clone();
        let full = format!("{tag}{short}{n}-{name}");
        async move {
            let sk = SecretKey::from_random(KeyType::ED25519);
            save_cred(&format!("{full}.{}", f.id()), &sk)?;
            let r = f
                .create_subaccount(&full)
                .initial_balance(NearToken::from_millinear(near_milli))
                .keys(sk)
                .transact()
                .await?;
            r.into_result().map_err(anyhow::Error::from)
        }
    };
    use anyhow::Context;
    let owner = sub("owner", OWNER_MILLI).await.context("create owner")?;
    // The agent needs >2 NEAR: `max_gas()` attaches 1,000 TGas, and NEAR checks the signer
    // can pay for it at a pessimistic gas price. With 0.25 NEAR both pays (run 6), and with 1.5 NEAR the second pay (run 7), were silently
    // dropped by the RPC (run 6 trial 0).
    let agent = sub("agent", agent_millinear()).await.context("create agent")?;
    let receiver = sub("sam", SAM_MILLI).await.context("create sam")?;
    let token_acct = sub("token", CONTRACT_MILLI).await.context("create token acct")?;
    let guard_acct = sub("guard", CONTRACT_MILLI).await.context("create guard acct")?;
    let token = ok_deploy("deploy token", token_acct.deploy(token_wasm).await.context("deploy token")?)?;
    let guard = ok_deploy("deploy guard", guard_acct.deploy(guard_wasm).await.context("deploy guard")?)?;

    // Second full-access key on the agent, so each `pay` is signed by its own key.
    // Then both can be broadcast at the same moment without nonce conflicts
    // (one key's nonces must arrive in order; two keys are independent).
    let sk2 = SecretKey::from_random(KeyType::ED25519);
    save_cred(&format!("{}#key2", agent.id()), &sk2)?;
    let r = agent
        .batch(agent.id())
        .add_key(sk2.public_key(), AccessKey::full_access())
        .transact_async()
        .await?;
    let r = wait_tx(r).await?;
    ok("agent add_key", r)?;
    let agent2 = Account::from_secret_key(agent.id().clone(), sk2, worker);
    eprintln!(
        "   owner={} agent={} receiver={} token={} guard={}",
        owner.id(), agent.id(), receiver.id(), token.id(), guard.id()
    );

    let mut setup_txs = Vec::new();
    let r = ok("token.new", wait_tx(owner.call(token.id(), "new")
        .args_json(json!({"owner_id": owner.id(), "total_supply": SUPPLY.to_string()}))
        .transact_async().await?).await?)?;
    setup_txs.push(json!({"step": "token.new", "tx": r.outcome().transaction_hash.to_string()}));
    let r = ok("guard.new", wait_tx(owner.call(guard.id(), "new")
        .args_json(json!({"mode": mode, "funder": funder.id(), "owner": owner.id(), "agent": agent.id(), "token": token.id()}))
        .transact_async().await?).await?)?;
    setup_txs.push(json!({"step": "guard.new", "tx": r.outcome().transaction_hash.to_string()}));
    for acct in [guard.id().clone(), receiver.id().clone()] {
        let r = ok("storage_deposit", wait_tx(owner.call(token.id(), "storage_deposit")
            .args_json(json!({"account_id": acct}))
            .deposit(NearToken::from_millinear(10))
            .transact_async().await?).await?)?;
        setup_txs.push(json!({"step": format!("storage_deposit {acct}"), "tx": r.outcome().transaction_hash.to_string()}));
    }
    let r = ok("fund guard", wait_tx(owner.call(token.id(), "ft_transfer")
        .args_json(json!({"receiver_id": guard.id(), "amount": GUARD_FUNDING.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact_async().await?).await?)?;
    setup_txs.push(json!({"step": "fund guard 1000", "tx": r.outcome().transaction_hash.to_string()}));
    let id = format!("inv-{mode}-{n}");
    let r = ok("approve_invoice", wait_tx(owner.call(guard.id(), "approve_invoice")
        .args_json(json!({"id": id, "receiver": receiver.id(), "amount": INVOICE_AMOUNT.to_string()}))
        .transact_async().await?).await?)?;
    setup_txs.push(json!({"step": "approve_invoice 100", "tx": r.outcome().transaction_hash.to_string()}));
    let mode_onchain: Value = guard.view("get_mode").await?.json()?;

    let recv_before = ft_balance(&token, receiver.id()).await?;
    let guard_before = ft_balance(&token, guard.id()).await?;
    let nonce_before = agent_nonce(&agent, &agent2).await?;

    // ---- the race: two pays, neither waits for the other. Never retried by us. ----
    // Both broadcasts start at the same moment (tokio::join!), one per key.
    let id_a = id.clone();
    let id_b = id.clone();
    let send_a = async {
        let t = now_ms();
        let s = agent.call(guard.id(), "pay").args_json(json!({"id": id_a})).max_gas().transact_async().await;
        (t, now_ms(), s)
    };
    let send_b = async {
        let t = now_ms();
        let s = agent2.call(guard.id(), "pay").args_json(json!({"id": id_b})).max_gas().transact_async().await;
        (t, now_ms(), s)
    };
    let ((sent_a, acked_a, a), (sent_b, acked_b, b)) = tokio::join!(send_a, send_b);
    let (a, b) = (a?, b?);
    let hash_a = a.hash().to_string();
    let hash_b = b.hash().to_string();
    // If a result cannot be fetched, keep going: the final balances, invoice record and
    // key nonces below still say what happened. The trial is flagged, not dropped.
    let (ra, rb) = tokio::join!(wait_tx(a), wait_tx(b));
    let wait_err_a = ra.as_ref().err().map(|e| format!("{e:#}"));
    let wait_err_b = rb.as_ref().err().map(|e| format!("{e:#}"));

    let recv_after = ft_balance(&token, receiver.id()).await?;
    let guard_after = ft_balance(&token, guard.id()).await?;
    let nonce_after = agent_nonce(&agent, &agent2).await?;
    let inv: Value = guard.view("get_invoice").args_json(json!({"id": id})).await?.json()?;

    let g = guard.id().as_str();
    let tk = token.id().as_str();
    let sa = match &ra { Ok(r) => steps(worker, r, g, tk).await?, Err(_) => vec![] };
    let sb = match &rb { Ok(r) => steps(worker, r, g, tk).await?, Err(_) => vec![] };

    let received = recv_after - recv_before;
    let pays_sent = nonce_after - nonce_before;

    // Overlap: did the later `pay` check run at or before the earlier pay's callback?
    let pay_a = first_height(&sa, "pay ");
    let pay_b = first_height(&sb, "pay ");
    let cb_a = first_height(&sa, "on_transfer");
    let cb_b = first_height(&sb, "on_transfer");
    // "Earlier" = the pay whose check ran first (A on a tie). Its callback is where it
    // writes the result; the later check only sees "not paid" if it ran before that.
    let (first_cb, second_pay) = match (pay_a, pay_b) {
        (Some(x), Some(y)) if x <= y => (cb_a, Some(y)),
        (Some(x), Some(_)) => (cb_b, Some(x)),
        _ => (None, None),
    };
    let overlap = match (first_cb, second_pay) {
        (Some(c), Some(p)) => Some(p <= c),
        _ => None,
    };

    // Kept trial: return spare NEAR from the signer accounts (keeps 0.05 + storage), so the
    // live contracts stay open for judges. Other trials: delete all five accounts, funder
    // as beneficiary, so all their NEAR comes back (chain history keeps every tx).
    let mut deleted = Vec::new();
    if !keep {
        for acct in [token.as_account().clone(), guard.as_account().clone(), receiver.clone(), owner.clone(), agent.clone()] {
            deleted.push(delete_to(acct, funder.id()).await);
        }
    }
    for acct in [&agent, &owner].into_iter().filter(|_| keep) {
        if let Ok(v) = acct.view_account().await {
            let locked = (v.storage_usage as u128) * 10u128.pow(19) + 50 * 10u128.pow(21);
            let free = v.balance.as_yoctonear().saturating_sub(locked);
            if free > 0 {
                let _ = acct.transfer_near(funder.id(), NearToken::from_yoctonear(free)).await;
            }
        }
    }

    let link = |h: &str| format!("https://testnet.nearblocks.io/txns/{h}");
    let out = json!({
        "mode": mode,
        "mode_onchain": mode_onchain,
        "trial": n,
        "rule": RULE,
        "invoice_id": id,
        "invoice_amount": INVOICE_AMOUNT.to_string(),
        "accounts": {
            "funder": funder.id(), "owner": owner.id(), "agent": agent.id(), "receiver": receiver.id(),
            "token": token.id(), "guard": guard.id(),
        },
        "setup_txs": setup_txs,
        "pay_a": {"tx": hash_a, "link": link(&hash_a), "sent_unix_ms": sent_a.to_string(), "broadcast_returned_unix_ms": acked_a.to_string(),
                  "success": ra.as_ref().ok().map(|r| r.is_success()), "failure": ra.as_ref().map(failure_text).unwrap_or_default(), "outcome_fetch_error": wait_err_a, "steps": sa},
        "pay_b": {"tx": hash_b, "link": link(&hash_b), "sent_unix_ms": sent_b.to_string(), "broadcast_returned_unix_ms": acked_b.to_string(),
                  "success": rb.as_ref().ok().map(|r| r.is_success()), "failure": rb.as_ref().map(failure_text).unwrap_or_default(), "outcome_fetch_error": wait_err_b, "steps": sb},
        "receiver_balance_before": recv_before.to_string(),
        "receiver_balance_after": recv_after.to_string(),
        "receiver_received": received.to_string(),
        "guard_paid_out": (guard_before - guard_after).to_string(),
        "invoice_record_after": inv,
        "agent_txs_sent_during_race": pays_sent,
        "later_pay_check_height": second_pay,
        "earlier_pay_callback_height": first_cb,
        "overlapped": overlap,
        "rule_held": received <= INVOICE_AMOUNT,
        "kept_alive": keep,
        "deleted_accounts": deleted,
        "elapsed_s": t0.elapsed().as_secs(),
    });
    eprintln!(
        "   RESULT mode={mode} trial={n}: receiver +{received} | pays sent={pays_sent} | pay heights A={pay_a:?} B={pay_b:?} | callbacks A={cb_a:?} B={cb_b:?} | overlap={overlap:?}"
    );
    Ok(out)
}

/// Saves a trial account key OUTSIDE the repo, near-cli style, mode 600, so leftover
/// testnet NEAR can be recovered. Never printed.
fn save_cred(name: &str, sk: &SecretKey) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::PathBuf::from(std::env::var("HOME")?).join(".near-credentials/testnet");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{name}.json"));
    let body = json!({"account_id": name.split('#').next().unwrap(), "public_key": sk.public_key().to_string(), "private_key": sk.to_string()});
    std::fs::write(&path, body.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// The funder, loaded from its saved random key (~/.near-credentials/testnet/<id>.json).
fn load_account(worker: &Worker<Testnet>, id: &near_workspaces::AccountId) -> anyhow::Result<Account> {
    let path = std::path::PathBuf::from(std::env::var("HOME")?).join(format!(".near-credentials/testnet/{id}.json"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("no saved key for {id}: {e}"))?)?;
    let sk: SecretKey = v["private_key"].as_str().ok_or_else(|| anyhow::anyhow!("no private_key for {id}"))?.parse()?;
    Ok(Account::from_secret_key(id.clone(), sk, worker))
}

/// A dev account made earlier by near-workspaces: its key is derived from its id.
/// Used ONLY by `consolidate`, to empty those old accounts. Never as a funder.
fn dev_account(worker: &Worker<Testnet>, id: &near_workspaces::AccountId) -> Account {
    Account::from_secret_key(id.clone(), SecretKey::from_seed(KeyType::ED25519, id.as_str()), worker)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // rpc.testnet.near.org is deprecated and returned HTTP 429 mid-run (run 3); default to FastNEAR.
    let rpc = std::env::var("TESTNET_RPC").unwrap_or_else(|_| "https://rpc.testnet.fastnear.com".into());
    let worker = near_workspaces::testnet().rpc_addr(&rpc).await?;
    match args.get(1).map(String::as_str) {
        Some("probe") => {
            let a = worker.dev_create_account().await?;
            let bal = a.view_account().await?.balance;
            println!("probe account {} balance {}", a.id(), bal);
        }
        Some("newfunder") => {
            // newfunder <prefix> : ONE top-level testnet account from the official
            // faucet helper (the same call `dev_create_account` makes), but with a fresh
            // RANDOM ed25519 key saved first (mode 600). One attempt; no retry loop here,
            // so the faucet's limit is never hammered.
            // Arg: the prefix only; the helper creates <prefix>.testnet.
            let prefix: near_workspaces::AccountId = args.get(2).ok_or_else(|| anyhow::anyhow!("need a prefix"))?.parse()?;
            let id: near_workspaces::AccountId = format!("{prefix}.testnet").parse()?;
            let path = std::path::PathBuf::from(std::env::var("HOME")?).join(format!(".near-credentials/testnet/{id}.json"));
            let sk = if path.exists() {
                // A previous attempt saved this key and the faucet refused: reuse it.
                load_account(&worker, &id)?.secret_key().clone()
            } else {
                let sk = SecretKey::from_random(KeyType::ED25519);
                save_cred(id.as_str(), &sk)?;
                sk
            };
            let r = worker.create_root_account_subaccount(prefix, sk).await?;
            eprintln!("newfunder {id}: ok={}", r.is_success());
            eprintln!("balance {}", NearToken::from_yoctonear(balance(&worker, &id).await?));
        }
        Some("balance") => {
            for a in &args[2..] {
                let id: near_workspaces::AccountId = a.parse()?;
                let b = balance(&worker, &id).await?;
                println!("{}", json!({"account": a, "balance_yocto": b.to_string(), "balance": NearToken::from_yoctonear(b).to_string()}));
            }
        }
        Some("topup") => {
            // topup <funder-id> <to-id> <millinear> : funder sends testnet NEAR (e.g. receipts gas).
            let f = load_account(&worker, &args[2].parse()?)?;
            let to: near_workspaces::AccountId = args[3].parse()?;
            let r = f.transfer_near(&to, NearToken::from_millinear(args[4].parse()?)).await?;
            eprintln!("topup {to}: ok={} tx={}", r.is_success(), r.outcome().transaction_hash);
        }
        Some("consolidate") => {
            // consolidate <funder-id> <source-id>... : move spare testnet NEAR from earlier
            // dev accounts (keys re-derived from their ids, as near-workspaces made them)
            // into the funder. Keeps each source's storage-locked amount + 0.05 NEAR.
            let funder: near_workspaces::AccountId = args[2].parse()?;
            for src in &args[3..] {
                let id: near_workspaces::AccountId = src.parse()?;
                let acct = dev_account(&worker, &id);
                let v = acct.view_account().await?;
                let locked = (v.storage_usage as u128) * 10u128.pow(19) + 50 * 10u128.pow(21);
                let free = v.balance.as_yoctonear().saturating_sub(locked);
                if free == 0 { eprintln!("{id}: nothing spare"); continue; }
                let r = acct.transfer_near(&funder, NearToken::from_yoctonear(free)).await?;
                eprintln!("{id}: sent {} to {funder}: ok={} tx={}", NearToken::from_yoctonear(free), r.is_success(), r.outcome().transaction_hash);
            }
            eprintln!("funder balance now {}", NearToken::from_yoctonear(balance(&worker, &funder).await?));
        }
        Some("costprobe") => {
            // costprobe <low-balance-account> <contract> : sends a max_gas call from an
            // account that cannot afford it; the RPC refuses it and reports the exact cost
            // NEAR reserves for 1,000 TGas. Nothing executes.
            let dir = std::path::PathBuf::from(std::env::var("HOME")?).join(".near-credentials/testnet");
            let raw = std::fs::read_to_string(dir.join(format!("{}.json", args[2])))?;
            let v: Value = serde_json::from_str(&raw)?;
            let sk: SecretKey = v["private_key"].as_str().unwrap_or("").parse()?;
            let acct = Account::from_secret_key(args[2].parse()?, sk, &worker);
            let c: near_workspaces::AccountId = args[3].parse()?;
            match acct.call(&c, "get_mode").args_json(json!({})).max_gas().transact().await {
                Ok(r) => eprintln!("executed (unexpected): ok={}", r.is_success()),
                Err(e) => eprintln!("refused: {e:?}"),
            }
        }
        Some("reclaim") => {
            // reclaim <funder-id> <account-id>... : delete accounts from FAILED trials
            // (keys from ~/.near-credentials/testnet) and send their NEAR back to the funder.
            let funder: near_workspaces::AccountId = args[2].parse()?;
            let dir = std::path::PathBuf::from(std::env::var("HOME")?).join(".near-credentials/testnet");
            for a in &args[3..] {
                let raw = match std::fs::read_to_string(dir.join(format!("{a}.json"))) {
                    Ok(r) => r,
                    Err(_) => { eprintln!("{a}: no saved key"); continue; }
                };
                let v: Value = serde_json::from_str(&raw)?;
                let sk: SecretKey = v["private_key"].as_str().unwrap_or("").parse()?;
                let acct = Account::from_secret_key(a.parse()?, sk, &worker);
                match acct.delete_account(&funder).await {
                    Ok(r) => eprintln!("{a}: deleted ok={} tx={}", r.is_success(), r.outcome().transaction_hash),
                    Err(e) => eprintln!("{a}: delete failed: {e}"),
                }
            }
            eprintln!("funder balance now {}", NearToken::from_yoctonear(balance(&worker, &funder).await?));
        }
        Some("run") => {
            let trials: usize = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(5);
            let out_path = args.get(3).cloned().unwrap_or_else(|| "testnet-raw.json".into());
            let funder_id: near_workspaces::AccountId = args.get(4).ok_or_else(|| anyhow::anyhow!("need funder id"))?.parse()?;
            let tag = args.get(5).cloned().unwrap_or_else(|| "r".into());
            let funder = load_account(&worker, &funder_id)?;
            let funder_start = balance(&worker, &funder_id).await?;
            let modes: Vec<String> = if args.len() > 6 {
                args[6..].to_vec()
            } else {
                vec!["vulnerable_fixture".into(), "fixed".into()]
            };
            let token_wasm = std::fs::read(TOKEN_WASM)?;
            let guard_wasm = std::fs::read(GUARD_WASM)?;
            // EXPECT_GUARD_SHA256: refuse to deploy anything but the pre-registered build.
            if let Ok(want) = std::env::var("EXPECT_GUARD_SHA256") {
                anyhow::ensure!(sha(&guard_wasm) == want, "guard.wasm is {}, plan says {want}: not deploying", sha(&guard_wasm));
            }
            let header = json!({
                "network": "testnet",
                "rpc": rpc,
                "started_unix_ms": now_ms().to_string(),
                "token_wasm_sha256": sha(&token_wasm),
                "guard_wasm_sha256": sha(&guard_wasm),
                "trials_per_mode": trials, "funder": funder_id.to_string(),
                "funder_balance_start_yocto": funder_start.to_string(),
                "trial_upfront_millinear": trial_upfront_milli().to_string(),
            });
            eprintln!("header: {header}");
            let mut results = Vec::new();
            let mut errors = Vec::new();
            let mut stopped = None;
            'outer: for mode in &modes {
                for n in 0..trials {
                    // Never start a trial the funder cannot finish: a half-built trial strands NEAR.
                    // Up-front + 0.04 NEAR: five account creations cost 0.0071 NEAR each (measured
                    // Nov 10, trial r11vf0). Re-read up to 3 times: right after a trial the RPC can
                    // still show the balance before the deleted accounts' NEAR arrived.
                    let need = (trial_upfront_milli() + 40) * 10u128.pow(21);
                    let mut before = balance(&worker, &funder_id).await?;
                    for _ in 0..3 {
                        if before >= need { break; }
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        before = balance(&worker, &funder_id).await?;
                    }
                    if before < need {
                        let msg = format!("stopped before mode={mode} trial={n}: funder has {} yocto, a trial needs {} (up-front + 0.04)", before, need);
                        eprintln!("   {msg}");
                        stopped = Some(msg);
                        break 'outer;
                    }
                    let keep = n + 1 == trials;
                    match trial(&worker, &funder, &tag, mode, n, keep, &token_wasm, &guard_wasm).await {
                        Ok(mut v) => {
                            // Let the deleted accounts' transfers land before reading (trial r11vf0
                            // read 8.71 right away; the true balance was ~2.3 NEAR higher).
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                            let after = balance(&worker, &funder_id).await?;
                            v["funder_balance_before_yocto"] = json!(before.to_string());
                            v["funder_balance_after_yocto"] = json!(after.to_string());
                            eprintln!("   funder {} -> {}", NearToken::from_yoctonear(before), NearToken::from_yoctonear(after));
                            results.push(v)
                        }
                        Err(e) => {
                            eprintln!("   TRIAL ERROR mode={mode} trial={n}: {e:#}");
                            errors.push(json!({"mode": mode, "trial": n, "error": format!("{e:#}")}));
                        }
                    }
                    // Write after every trial so a crash keeps what we have.
                    let doc = json!({"header": header, "trials": results, "errors": errors});
                    std::fs::write(&out_path, serde_json::to_string_pretty(&doc)?)?;
                }
            }
            let funder_end = balance(&worker, &funder_id).await?;
            let doc = json!({"header": header, "trials": results, "errors": errors, "stopped": stopped,
                             "funder_balance_end_yocto": funder_end.to_string()});
            std::fs::write(&out_path, serde_json::to_string_pretty(&doc)?)?;
            eprintln!("funder end balance {}", NearToken::from_yoctonear(funder_end));
            eprintln!("wrote {out_path}: {} trials, {} errors", results.len(), errors.len());
        }
        _ => anyhow::bail!("usage: see the header of src/main.rs"),
    }
    Ok(())
}
