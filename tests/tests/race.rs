//! Local-sandbox proof: does a guard that marks an invoice "paid" only in the
//! callback pay the same invoice twice when two `pay` calls arrive close together?
//!
//! Runs only against a local near-sandbox node started by near-workspaces.
//! No testnet, no mainnet.
//!
//! Every test prints an EVIDENCE block (balances before/after, guard's own record,
//! and the block height each receipt executed in) so the run log is citeable.

use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::NearToken;
use near_workspaces::{Account, Contract, Worker};
use serde_json::{json, Value};

const TOKEN_WASM: &str = "../contracts/target/wasm32-unknown-unknown/release/test_token.wasm";
const GUARD_WASM: &str = "../contracts/target/wasm32-unknown-unknown/release/guard.wasm";
/// Test-only build with the `fault-injection` feature: `on_transfer` panics for `crash-` ids.
const GUARD_FAULT_WASM: &str = "../contracts/target-fault/wasm32-unknown-unknown/release/guard.wasm";

const SUPPLY: u128 = 1_000_000;
const GUARD_FUNDING: u128 = 10_000;
const INVOICE_AMOUNT: u128 = 100;
const RACE_TRIALS: usize = 5;

struct Env {
    worker: Worker<Sandbox>,
    owner: Account,
    agent: Account,
    receiver: Account,
    token: Contract,
    guard: Contract,
}

async fn setup(mode: &str, register_receiver: bool) -> anyhow::Result<Env> {
    setup_with(mode, register_receiver, GUARD_WASM).await
}

async fn setup_with(mode: &str, register_receiver: bool, guard_wasm_path: &str) -> anyhow::Result<Env> {
    let worker = near_workspaces::sandbox().await?;
    let token_wasm = std::fs::read(TOKEN_WASM)
        .map_err(|e| anyhow::anyhow!("{TOKEN_WASM}: {e}. Run ./run.sh (it builds the contracts first)"))?;
    let guard_wasm = std::fs::read(guard_wasm_path)
        .map_err(|e| anyhow::anyhow!("{guard_wasm_path}: {e}. Run ./run.sh (it builds the contracts first)"))?;

    let owner = worker.dev_create_account().await?;
    let agent = worker.dev_create_account().await?;
    let receiver = worker.dev_create_account().await?;

    // Deploying is itself the check that the NEAR VM accepts the pinned-toolchain wasm.
    let token = worker.dev_deploy(&token_wasm).await?;
    let guard = worker.dev_deploy(&guard_wasm).await?;

    ok(owner
        .call(token.id(), "new")
        .args_json(json!({"owner_id": owner.id(), "total_supply": SUPPLY.to_string()}))
        .transact()
        .await?)?;
    ok(owner
        .call(guard.id(), "new")
        .args_json(json!({"mode": mode, "owner": owner.id(), "agent": agent.id(), "token": token.id()}))
        .transact()
        .await?)?;

    // Register the guard on the token (and optionally the receiver).
    let mut to_register = vec![guard.id().clone()];
    if register_receiver {
        to_register.push(receiver.id().clone());
    }
    for acct in to_register {
        ok(owner
            .call(token.id(), "storage_deposit")
            .args_json(json!({"account_id": acct}))
            .deposit(NearToken::from_millinear(10))
            .transact()
            .await?)?;
    }

    // Fund the guard with enough tokens to pay many invoices (so a double payout is possible).
    ok(owner
        .call(token.id(), "ft_transfer")
        .args_json(json!({"receiver_id": guard.id(), "amount": GUARD_FUNDING.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;

    Ok(Env { worker, owner, agent, receiver, token, guard })
}

fn ok(r: ExecutionFinalResult) -> anyhow::Result<()> {
    if r.is_failure() {
        anyhow::bail!("setup tx failed: {:?}", r.failures());
    }
    Ok(())
}

async fn balance(env: &Env, who: &near_workspaces::AccountId) -> anyhow::Result<u128> {
    let v: String = env
        .token
        .view("ft_balance_of")
        .args_json(json!({"account_id": who}))
        .await?
        .json()?;
    Ok(v.parse()?)
}

async fn invoice(env: &Env, id: &str) -> anyhow::Result<Value> {
    Ok(env.guard.view("get_invoice").args_json(json!({"id": id})).await?.json()?)
}

async fn approve(env: &Env, id: &str) -> anyhow::Result<()> {
    ok(env
        .owner
        .call(env.guard.id(), "approve_invoice")
        .args_json(json!({"id": id, "receiver": env.receiver.id(), "amount": INVOICE_AMOUNT.to_string()}))
        .transact()
        .await?)?;
    Ok(())
}

async fn pay(env: &Env, id: &str) -> anyhow::Result<ExecutionFinalResult> {
    Ok(env
        .agent
        .call(env.guard.id(), "pay")
        .args_json(json!({"id": id}))
        .max_gas()
        .transact()
        .await?)
}

/// Prints, for one tx, the block height + executor + logs + success of every step.
async fn trace(env: &Env, label: &str, r: &ExecutionFinalResult) -> anyhow::Result<()> {
    println!("  [{label}] tx success={} ", r.is_success());
    for o in r.outcomes() {
        let h = env.worker.view_block().block_hash(o.block_hash).await?.height();
        println!(
            "    block {h:>5}  on {:<40} ok={:<5} gas_burnt={:>6.2} TGas logs={:?}",
            o.executor_id.as_str(),
            o.is_success(),
            o.gas_burnt.as_gas() as f64 / 1e12,
            o.logs
        );
    }
    if r.is_failure() {
        for f in r.failures() {
            println!("    failure: {:?}", f.clone().into_result().err());
        }
    }
    Ok(())
}

/// Every failure message in a tx ("" if the tx and all its receipts succeeded).
fn failure_text(r: &ExecutionFinalResult) -> String {
    r.failures()
        .iter()
        .map(|f| format!("{:?}", (*f).clone().into_result().err()))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Sends two `pay(id)` txs back to back WITHOUT waiting for the first to finish,
/// then waits for both. Returns (result_a, result_b).
async fn race_two_pays(env: &Env, id: &str) -> anyhow::Result<(ExecutionFinalResult, ExecutionFinalResult)> {
    let a = env
        .agent
        .call(env.guard.id(), "pay")
        .args_json(json!({"id": id}))
        .max_gas()
        .transact_async()
        .await?;
    let b = env
        .agent
        .call(env.guard.id(), "pay")
        .args_json(json!({"id": id}))
        .max_gas()
        .transact_async()
        .await?;
    let ra = a.await?;
    let rb = b.await?;
    Ok((ra, rb))
}

/// Runs RACE_TRIALS races in a fresh sandbox for `mode`, returns receiver payouts per trial.
async fn run_race(mode: &str) -> anyhow::Result<Vec<(u128, String, String)>> {
    let env = setup(mode, true).await?;
    println!("\n===== EVIDENCE: race, mode={mode}, {RACE_TRIALS} trials, invoice amount {INVOICE_AMOUNT} =====");
    let mut paid_per_trial = Vec::new();
    for t in 0..RACE_TRIALS {
        let id = format!("race-{t}");
        approve(&env, &id).await?;
        let r_before = balance(&env, env.receiver.id()).await?;
        let g_before = balance(&env, env.guard.id()).await?;
        let (ra, rb) = race_two_pays(&env, &id).await?;
        let r_after = balance(&env, env.receiver.id()).await?;
        let g_after = balance(&env, env.guard.id()).await?;
        let inv = invoice(&env, &id).await?;
        let received = r_after - r_before;
        println!(
            "trial {t}: receiver +{received} (guard -{}), invoice record = {inv}",
            g_before - g_after
        );
        trace(&env, "pay A", &ra).await?;
        trace(&env, "pay B", &rb).await?;
        paid_per_trial.push((received, failure_text(&ra), failure_text(&rb)));
    }
    Ok(paid_per_trial)
}

/// Control: one pay, wait for it to finish, then a second pay. Both modes must refuse the second.
async fn run_sequential(mode: &str) -> anyhow::Result<(u128, String)> {
    let env = setup(mode, true).await?;
    println!("\n===== EVIDENCE: sequential control, mode={mode} =====");
    approve(&env, "seq").await?;
    let r1 = pay(&env, "seq").await?;
    trace(&env, "pay 1", &r1).await?;
    let r2 = pay(&env, "seq").await?;
    trace(&env, "pay 2 (after pay 1 finished)", &r2).await?;
    let received = balance(&env, env.receiver.id()).await?;
    println!("receiver total = {received}, invoice record = {}", invoice(&env, "seq").await?);
    Ok((received, failure_text(&r2)))
}

/// Recovery: receiver not registered on the token, so the transfer genuinely fails.
/// Then the receiver registers and the agent retries.
async fn run_recovery(mode: &str) -> anyhow::Result<(u128, Value, u128, Value, u128, String, String)> {
    let env = setup(mode, false).await?;
    println!("\n===== EVIDENCE: failed transfer then retry, mode={mode} =====");
    approve(&env, "rec").await?;
    let g0 = balance(&env, env.guard.id()).await?;
    let r1 = pay(&env, "rec").await?;
    trace(&env, "pay 1 (receiver unregistered)", &r1).await?;
    let after_fail_recv = balance(&env, env.receiver.id()).await?;
    let after_fail_inv = invoice(&env, "rec").await?;
    let g1 = balance(&env, env.guard.id()).await?;
    println!("after failed transfer: receiver={after_fail_recv}, guard change={}, invoice={after_fail_inv}", g0 as i128 - g1 as i128);

    ok(env
        .owner
        .call(env.token.id(), "storage_deposit")
        .args_json(json!({"account_id": env.receiver.id()}))
        .deposit(NearToken::from_millinear(10))
        .transact()
        .await?)?;
    let r2 = pay(&env, "rec").await?;
    trace(&env, "pay 2 (receiver now registered)", &r2).await?;
    let final_recv = balance(&env, env.receiver.id()).await?;
    let final_inv = invoice(&env, "rec").await?;
    println!("after retry: receiver={final_recv}, invoice={final_inv}");

    // A third call must be refused now that it is paid.
    let r3 = pay(&env, "rec").await?;
    trace(&env, "pay 3 (already paid)", &r3).await?;
    let end_recv = balance(&env, env.receiver.id()).await?;
    Ok((after_fail_recv, after_fail_inv, final_recv, final_inv, end_recv, failure_text(&r1), failure_text(&r3)))
}

#[tokio::test]
async fn t1_vulnerable_fixture_pays_same_invoice_twice_under_race() -> anyhow::Result<()> {
    let paid = run_race("vulnerable_fixture").await?;
    let amounts: Vec<u128> = paid.iter().map(|p| p.0).collect();
    println!("RESULT vulnerable_fixture race payouts per trial: {amounts:?}");
    for (t, (p, ea, eb)) in paid.iter().enumerate() {
        assert_eq!(*p, 2 * INVOICE_AMOUNT, "trial {t}: expected a double payout, got {p}");
        assert!(ea.is_empty() && eb.is_empty(), "trial {t}: both pays should fully succeed: {ea} / {eb}");
    }
    Ok(())
}

#[tokio::test]
async fn t2_fixed_pays_once_under_race() -> anyhow::Result<()> {
    let paid = run_race("fixed").await?;
    let amounts: Vec<u128> = paid.iter().map(|p| p.0).collect();
    println!("RESULT fixed race payouts per trial: {amounts:?}");
    for (t, (p, ea, eb)) in paid.iter().enumerate() {
        assert_eq!(*p, INVOICE_AMOUNT, "trial {t}: expected exactly one payout, got {p}");
        // Exactly one of the two was refused, and for the right reason.
        let refused: Vec<&String> = [ea, eb].into_iter().filter(|e| !e.is_empty()).collect();
        assert_eq!(refused.len(), 1, "trial {t}: expected exactly one refusal: {ea} / {eb}");
        assert!(refused[0].contains("payment already in flight"), "trial {t}: wrong refusal reason: {}", refused[0]);
    }
    Ok(())
}

#[tokio::test]
async fn t3_sequential_control_both_modes_refuse_second_pay() -> anyhow::Result<()> {
    for mode in ["vulnerable_fixture", "fixed"] {
        let (received, refusal) = run_sequential(mode).await?;
        println!("RESULT sequential {mode}: receiver={received}, second pay refusal={refusal}");
        assert_eq!(received, INVOICE_AMOUNT, "{mode}: sequential pays must pay once");
        assert!(refusal.contains("invoice already paid"), "{mode}: second pay should be refused as already paid: {refusal}");
    }
    Ok(())
}

#[tokio::test]
async fn t4_fixed_recovers_from_genuinely_failed_transfer() -> anyhow::Result<()> {
    let (fail_recv, fail_inv, final_recv, final_inv, end_recv, fail1, fail3) = run_recovery("fixed").await?;
    assert!(fail1.contains("is not registered"), "first transfer should fail because the receiver is unregistered: {fail1}");
    assert!(fail3.contains("invoice already paid"), "third pay should be refused as already paid: {fail3}");
    assert_eq!(fail_recv, 0, "nothing should arrive when the transfer fails");
    assert_eq!(fail_inv["status"], "Approved", "fixed mode must release the reservation on failure");
    assert_eq!(fail_inv["confirmed_payouts"], 0);
    assert_eq!(final_recv, INVOICE_AMOUNT, "retry after the failure must pay");
    assert_eq!(final_inv["status"], "Paid");
    assert_eq!(final_inv["confirmed_payouts"], 1);
    assert_eq!(end_recv, INVOICE_AMOUNT, "a third pay must not pay again");
    println!("RESULT fixed recovery: failed->Approved, retry paid {final_recv}, third pay refused");
    Ok(())
}

// ---------------------------------------------------------------------------------
// Callback-failure tests (2026-11-08, second run).
//
// Question: what happens when the token transfer reaches Sam (the receiver) but the
// guard's callback `on_transfer` fails? And when the transfer fails AND the callback
// fails? The failure is simulated with the test-only `fault-injection` build, whose
// `on_transfer` panics for invoice ids starting with `crash-`.
//
// Every step prints one row: Sam's token balance, the guard's token balance, the
// invoice status, and which case the state is in:
//   (a) STUCK, Sam PAID    -> the invoice is frozen in Pending although Sam has the money.
//                             Anything that blindly resets and retries it would pay twice.
//   (b) STUCK, Sam UNPAID  -> an honest invoice is frozen in Pending; retry is refused.
//   (c) NOT STUCK          -> the record matches reality (unpaid and unpaid, or paid once).
//   (d) WRONG RECORD       -> the record says unpaid but Sam already has the money;
//                             a retry WILL pay twice. (Only the vulnerable fixture gets here.)
// ---------------------------------------------------------------------------------

/// The `reconcile` waiting rule in the guard (RECONCILE_MIN_BLOCKS), plus a margin.
const RECONCILE_WAIT_BLOCKS: u64 = 105;

fn classify(sam: u128, status: &str) -> &'static str {
    match status {
        "Pending" if sam > 0 => "(a) STUCK, Sam PAID: a blind reset+retry would double pay",
        "Pending" => "(b) STUCK, Sam UNPAID: honest invoice frozen, retry refused",
        "Approved" if sam > 0 => "(d) WRONG RECORD: says unpaid, Sam already paid; retry WILL double pay",
        "Approved" => "(c) NOT STUCK: unpaid on record and in fact; retry is safe",
        "Paid" if sam == INVOICE_AMOUNT => "(c) NOT STUCK: Paid, Sam paid exactly once",
        "Paid" => "(!) Paid on record but Sam balance is not 1x",
        _ => "(?) unknown status",
    }
}

#[derive(Debug, Clone)]
struct Snap {
    sam: u128,
    guard: u128,
    status: String,
    confirmed: u64,
    started: u64,
}

async fn snap(env: &Env, id: &str, step: &str) -> anyhow::Result<Snap> {
    let sam = balance(env, env.receiver.id()).await?;
    let guard = balance(env, env.guard.id()).await?;
    let inv = invoice(env, id).await?;
    let s = Snap {
        sam,
        guard,
        status: inv["status"].as_str().unwrap_or("?").to_string(),
        confirmed: inv["confirmed_payouts"].as_u64().unwrap_or(0),
        started: inv["transfers_started"].as_u64().unwrap_or(0),
    };
    println!(
        "  STEP | {step:<44} | Sam={:>4} | guard={:>6} | status={:<8} | confirmed={} started={} | {}",
        s.sam,
        s.guard,
        s.status,
        s.confirmed,
        s.started,
        classify(s.sam, &s.status)
    );
    Ok(s)
}

async fn register_sam(env: &Env) -> anyhow::Result<()> {
    ok(env
        .owner
        .call(env.token.id(), "storage_deposit")
        .args_json(json!({"account_id": env.receiver.id()}))
        .deposit(NearToken::from_millinear(10))
        .transact()
        .await?)
}

async fn owner_call(env: &Env, method: &str, args: Value) -> anyhow::Result<ExecutionFinalResult> {
    Ok(env
        .owner
        .call(env.guard.id(), method)
        .args_json(args)
        .max_gas()
        .transact()
        .await?)
}

async fn sync_ledger(env: &Env) -> anyhow::Result<()> {
    let r = owner_call(env, "sync_ledger", json!({})).await?;
    trace(env, "sync_ledger", &r).await?;
    ok(r)?;
    println!("  ledger after sync = {}", env.guard.view("get_ledger").await?.json::<Value>()?);
    Ok(())
}

async fn ledger(env: &Env) -> anyhow::Result<Value> {
    Ok(env.guard.view("get_ledger").await?.json()?)
}

/// gas_burnt (in gas units) and success of the `on_transfer` receipt in a `pay` tx.
/// Found by its log line, so it only works when the callback did not panic.
fn callback_gas(r: &ExecutionFinalResult, guard: &near_workspaces::AccountId) -> Option<(u64, bool)> {
    r.receipt_outcomes()
        .iter()
        .find(|o| &o.executor_id == guard && o.logs.iter().any(|l| l.starts_with("on_transfer:")))
        .map(|o| (o.gas_burnt.as_gas(), o.is_success()))
}

/// Did the injected fault fire in this tx? (The callback receipt failed with the marker.)
fn fault_fired(r: &ExecutionFinalResult) -> bool {
    failure_text(r).contains("FAULT INJECTION")
}

fn retry_refused(failures: &str) -> bool {
    failures.contains("panicked: payment already in flight") || failures.contains("panicked: invoice already paid")
}

fn print_retry(failures: &str, sam_before: u128, sam_after: u128) {
    if retry_refused(failures) {
        println!("  RETRY RESULT: REFUSED by the guard, no transfer sent. Sam {sam_before} -> {sam_after}. [{failures}]");
    } else {
        println!("  RETRY RESULT: ACCEPTED, a transfer was sent. Sam {sam_before} -> {sam_after}. failures in tx: [{failures}]");
    }
}

/// Test 5 for one mode: transfer succeeds, callback panics, then one retry.
async fn run_t5(mode: &str) -> anyhow::Result<(Snap, Snap, String)> {
    let env = setup_with(mode, true, GUARD_FAULT_WASM).await?;
    let id = "crash-t5";
    println!("\n===== EVIDENCE: t5 transfer OK + callback panics, mode={mode}, invoice {INVOICE_AMOUNT} =====");
    approve(&env, id).await?;
    snap(&env, id, "0 approved").await?;
    let r1 = pay(&env, id).await?;
    trace(&env, "pay 1", &r1).await?;
    assert!(fault_fired(&r1), "{mode}: the injected callback panic did not fire: {}", failure_text(&r1));
    let s1 = snap(&env, id, "1 after pay (transfer ok, callback panicked)").await?;
    let r2 = pay(&env, id).await?;
    trace(&env, "retry pay", &r2).await?;
    let s2 = snap(&env, id, "2 after one retry pay").await?;
    let retry = failure_text(&r2);
    print_retry(&retry, s1.sam, s2.sam);
    Ok((s1, s2, retry))
}

/// Test 6 for one mode: transfer fails (Sam not registered), callback panics.
/// Sam is then registered so a retry COULD succeed, then one retry.
async fn run_t6(mode: &str) -> anyhow::Result<(Snap, Snap, String)> {
    let env = setup_with(mode, false, GUARD_FAULT_WASM).await?;
    let id = "crash-t6";
    println!("\n===== EVIDENCE: t6 transfer FAILS + callback panics, mode={mode}, invoice {INVOICE_AMOUNT} =====");
    approve(&env, id).await?;
    snap(&env, id, "0 approved (Sam not registered)").await?;
    let r1 = pay(&env, id).await?;
    trace(&env, "pay 1", &r1).await?;
    assert!(failure_text(&r1).contains("is not registered"), "{mode}: transfer should fail on unregistered Sam");
    assert!(fault_fired(&r1), "{mode}: the injected callback panic did not fire: {}", failure_text(&r1));
    let s1 = snap(&env, id, "1 after pay (transfer failed, cb panicked)").await?;
    register_sam(&env).await?;
    snap(&env, id, "1b owner registers Sam on the token").await?;
    let r2 = pay(&env, id).await?;
    trace(&env, "retry pay", &r2).await?;
    let s2 = snap(&env, id, "2 after one retry pay").await?;
    let retry = failure_text(&r2);
    print_retry(&retry, s1.sam, s2.sam);
    Ok((s1, s2, retry))
}

#[tokio::test]
async fn t5_transfer_ok_callback_panics_both_modes() -> anyhow::Result<()> {
    // vulnerable_fixture: the callback's "Paid" write is rolled back by the panic.
    let (s1, s2, retry) = run_t5("vulnerable_fixture").await?;
    assert_eq!((s1.sam, s1.status.as_str()), (INVOICE_AMOUNT, "Approved"), "vuln: Sam paid, record still Approved");
    assert!(!retry_refused(&retry), "vuln: retry should be accepted: {retry}");
    assert_eq!(s2.sam, 2 * INVOICE_AMOUNT, "vuln: the retry should pay Sam a second time");
    println!("RESULT t5 vulnerable_fixture: after pay Sam={} status={} (case d); after retry Sam={} status={} -> DOUBLE PAY", s1.sam, s1.status, s2.sam, s2.status);

    // fixed: the callback's write is rolled back too, so the invoice stays Pending.
    let (s1, s2, retry) = run_t5("fixed").await?;
    assert_eq!((s1.sam, s1.status.as_str()), (INVOICE_AMOUNT, "Pending"), "fixed: Sam paid, invoice stuck Pending");
    assert!(retry.contains("payment already in flight"), "fixed: retry must be refused: {retry}");
    assert_eq!((s2.sam, s2.status.as_str()), (INVOICE_AMOUNT, "Pending"), "fixed: retry changed nothing");
    println!("RESULT t5 fixed: after pay Sam={} status={} (case a); retry refused, Sam={} status={} -> no double pay, but stuck", s1.sam, s1.status, s2.sam, s2.status);
    Ok(())
}

#[tokio::test]
async fn t6_transfer_fails_callback_panics_both_modes() -> anyhow::Result<()> {
    let (s1, s2, retry) = run_t6("vulnerable_fixture").await?;
    assert_eq!((s1.sam, s1.status.as_str()), (0, "Approved"), "vuln: nothing paid, record Approved");
    assert!(!retry_refused(&retry), "vuln: retry should be accepted: {retry}");
    assert_eq!(s2.sam, INVOICE_AMOUNT, "vuln: retry pays once");
    assert_eq!(s2.status, "Approved", "vuln: the retry's callback also panicked, so the record still says unpaid");
    println!("RESULT t6 vulnerable_fixture: after pay Sam={} status={} (case c); after retry Sam={} status={} (case d: next retry would double pay)", s1.sam, s1.status, s2.sam, s2.status);

    let (s1, s2, retry) = run_t6("fixed").await?;
    assert_eq!((s1.sam, s1.status.as_str()), (0, "Pending"), "fixed: nothing paid, invoice stuck Pending");
    assert!(retry.contains("payment already in flight"), "fixed: retry must be refused: {retry}");
    assert_eq!((s2.sam, s2.status.as_str()), (0, "Pending"), "fixed: retry changed nothing");
    println!("RESULT t6 fixed: after pay Sam={} status={} (case b); retry refused even though Sam is now registered -> honest invoice frozen", s1.sam, s1.status);
    Ok(())
}

#[tokio::test]
async fn t7_fixed_reconcile_after_t5_marks_paid_and_blocks_retry() -> anyhow::Result<()> {
    let env = setup_with("fixed", true, GUARD_FAULT_WASM).await?;
    let id = "crash-t7";
    println!("\n===== EVIDENCE: t7 fixed, t5 scenario then owner reconcile =====");
    sync_ledger(&env).await?;
    approve(&env, id).await?;
    snap(&env, id, "0 approved").await?;
    let r1 = pay(&env, id).await?;
    trace(&env, "pay 1", &r1).await?;
    assert!(fault_fired(&r1));
    let s1 = snap(&env, id, "1 after pay (transfer ok, callback panicked)").await?;
    assert_eq!((s1.sam, s1.status.as_str()), (INVOICE_AMOUNT, "Pending"));

    let early = owner_call(&env, "reconcile", json!({"id": id})).await?;
    trace(&env, "reconcile right away", &early).await?;
    assert!(failure_text(&early).contains("too early"), "reconcile must wait: {}", failure_text(&early));
    snap(&env, id, "1b reconcile right away -> refused, too early").await?;

    let stranger = env.agent.call(env.guard.id(), "reconcile").args_json(json!({"id": id})).max_gas().transact().await?;
    assert!(failure_text(&stranger).contains("owner only"), "agent must not reconcile");

    env.worker.fast_forward(RECONCILE_WAIT_BLOCKS).await?;
    let rec = owner_call(&env, "reconcile", json!({"id": id})).await?;
    trace(&env, "reconcile after waiting", &rec).await?;
    ok(rec)?;
    let s2 = snap(&env, id, "2 after reconcile").await?;
    println!("  ledger = {}", ledger(&env).await?);
    assert_eq!(s2.status, "Paid", "the balance shows the money left, so reconcile must mark Paid");

    let r3 = pay(&env, id).await?;
    trace(&env, "retry pay", &r3).await?;
    let s3 = snap(&env, id, "3 after one retry pay").await?;
    assert!(failure_text(&r3).contains("invoice already paid"), "retry must be refused: {}", failure_text(&r3));
    assert_eq!(s3.sam, INVOICE_AMOUNT, "Sam stays at 1x");
    let l = ledger(&env).await?;
    assert_eq!(l["expected_balance"], (GUARD_FUNDING - INVOICE_AMOUNT).to_string());
    assert_eq!(l["pending_count"], 0);
    println!("RESULT t7: stuck Pending + Sam paid -> reconcile -> Paid; retry refused; Sam={}", s3.sam);
    Ok(())
}

#[tokio::test]
async fn t8_fixed_reconcile_after_t6_returns_to_approved_then_pays_once() -> anyhow::Result<()> {
    let env = setup_with("fixed", false, GUARD_FAULT_WASM).await?;
    let id = "crash-t8";
    println!("\n===== EVIDENCE: t8 fixed, t6 scenario then owner reconcile =====");
    sync_ledger(&env).await?;
    approve(&env, id).await?;
    snap(&env, id, "0 approved (Sam not registered)").await?;
    let r1 = pay(&env, id).await?;
    trace(&env, "pay 1", &r1).await?;
    assert!(fault_fired(&r1));
    let s1 = snap(&env, id, "1 after pay (transfer failed, cb panicked)").await?;
    assert_eq!((s1.sam, s1.status.as_str()), (0, "Pending"));

    env.worker.fast_forward(RECONCILE_WAIT_BLOCKS).await?;
    let rec = owner_call(&env, "reconcile", json!({"id": id})).await?;
    trace(&env, "reconcile", &rec).await?;
    ok(rec)?;
    let s2 = snap(&env, id, "2 after reconcile").await?;
    assert_eq!(s2.status, "Approved", "the balance shows the money did not leave");

    register_sam(&env).await?;
    snap(&env, id, "3 owner registers Sam").await?;
    let r4 = pay(&env, id).await?;
    trace(&env, "retry pay", &r4).await?;
    // The fault build panics on EVERY crash- callback, so this one panics too.
    assert!(fault_fired(&r4));
    let s4 = snap(&env, id, "4 after retry (transfer ok, cb panicked again)").await?;
    assert_eq!((s4.sam, s4.status.as_str()), (INVOICE_AMOUNT, "Pending"), "retry pays exactly once");

    env.worker.fast_forward(RECONCILE_WAIT_BLOCKS).await?;
    let rec2 = owner_call(&env, "reconcile", json!({"id": id})).await?;
    trace(&env, "reconcile again", &rec2).await?;
    ok(rec2)?;
    let s5 = snap(&env, id, "5 after second reconcile").await?;
    assert_eq!(s5.status, "Paid");

    let r6 = pay(&env, id).await?;
    let s6 = snap(&env, id, "6 one more pay").await?;
    assert!(failure_text(&r6).contains("invoice already paid"), "{}", failure_text(&r6));
    assert_eq!(s6.sam, INVOICE_AMOUNT, "Sam paid exactly once overall");
    println!("  ledger = {}", ledger(&env).await?);
    println!("RESULT t8: stuck Pending + Sam unpaid -> reconcile -> Approved; register Sam; retry paid once (Sam={}); reconcile -> Paid; next pay refused", s6.sam);
    Ok(())
}

#[tokio::test]
async fn t9_fixed_reconcile_refuses_when_two_invoices_pending() -> anyhow::Result<()> {
    let env = setup_with("fixed", true, GUARD_FAULT_WASM).await?;
    println!("\n===== EVIDENCE: t9 fixed, two stuck invoices -> reconcile must refuse =====");
    sync_ledger(&env).await?;
    for id in ["crash-a", "crash-b"] {
        approve(&env, id).await?;
        let r = pay(&env, id).await?;
        assert!(fault_fired(&r));
        snap(&env, id, &format!("after pay {id}")).await?;
    }
    env.worker.fast_forward(RECONCILE_WAIT_BLOCKS).await?;
    let rec = owner_call(&env, "reconcile", json!({"id": "crash-a"})).await?;
    trace(&env, "reconcile crash-a", &rec).await?;
    let f = failure_text(&rec);
    assert!(f.contains("ambiguous: 2 invoices are Pending"), "{f}");
    let a = snap(&env, "crash-a", "crash-a after refused reconcile").await?;
    assert_eq!(a.status, "Pending");
    println!("RESULT t9: two Pending invoices -> reconcile refused as ambiguous, nothing changed");
    Ok(())
}

#[tokio::test]
async fn t10_normal_build_has_no_fault_and_callback_gas() -> anyhow::Result<()> {
    println!("\n===== EVIDENCE: t10 normal build has no fault injection; callback gas =====");
    // Static check: the fault marker string is in the fault build only.
    let normal = std::fs::read(GUARD_WASM)?;
    let fault = std::fs::read(GUARD_FAULT_WASM)?;
    let marker = b"FAULT INJECTION";
    let has = |b: &[u8]| b.windows(marker.len()).any(|w| w == marker);
    println!("  marker in normal guard.wasm: {}, in fault guard.wasm: {}", has(&normal), has(&fault));
    assert!(!has(&normal), "normal guard.wasm must not contain the fault-injection code");
    assert!(has(&fault), "sanity: the fault build should contain the marker (else this check proves nothing)");

    const RESERVED_TGAS: f64 = 15.0;
    let mut rows = Vec::new();
    for mode in ["vulnerable_fixture", "fixed"] {
        // Normal build, Sam unregistered first, so we get both callback paths.
        let env = setup(mode, false).await?;
        if mode == "fixed" {
            sync_ledger(&env).await?; // ledger active = the fixed callback does its full work
        }
        let id = "crash-normal";
        approve(&env, id).await?;
        let r1 = pay(&env, id).await?;
        trace(&env, &format!("{mode} pay (transfer fails)"), &r1).await?;
        assert!(!fault_fired(&r1), "{mode}: normal build must not panic for crash- ids");
        let (g_fail, ok_fail) = callback_gas(&r1, env.guard.id()).expect("callback outcome not found");
        register_sam(&env).await?;
        let r2 = pay(&env, id).await?;
        trace(&env, &format!("{mode} retry (transfer ok)"), &r2).await?;
        assert!(r2.is_success(), "{mode}: normal build, crash- id, registered Sam: must fully succeed: {}", failure_text(&r2));
        let (g_ok, ok_ok) = callback_gas(&r2, env.guard.id()).expect("callback outcome not found");
        let s = snap(&env, id, &format!("{mode} normal build, crash- id")).await?;
        assert_eq!((s.sam, s.status.as_str()), (INVOICE_AMOUNT, "Paid"));
        assert!(ok_fail && ok_ok);
        rows.push((mode, g_fail, g_ok));
    }
    for (mode, g_fail, g_ok) in rows {
        let f = g_fail as f64 / 1e12;
        let o = g_ok as f64 / 1e12;
        println!(
            "RESULT t10 callback gas_burnt, {mode}: transfer-failed path {f:.3} TGas ({:.0}% of {RESERVED_TGAS}), transfer-ok path {o:.3} TGas ({:.0}% of {RESERVED_TGAS})",
            100.0 * f / RESERVED_TGAS,
            100.0 * o / RESERVED_TGAS
        );
        assert!(f < RESERVED_TGAS && o < RESERVED_TGAS);
    }
    Ok(())
}
