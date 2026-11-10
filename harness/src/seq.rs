//! Sequences: the replayable JSON format both testers submit.
//!
//! ```json
//! { "name": "short-name",
//!   "steps": [
//!     {"call":  {"actor": "agent" | "outsider", "target": "vault" | "token" (default vault),
//!                "method": "pay", "args": {...}, "gas_tgas": 100 (optional), "deposit_yocto": 1 (optional)}},
//!     {"view": {"target": ..., "method": "get_invoice", "args": {...}}},
//!     {"race": [ <call step>, <call step> ]},
//!     {"wait_blocks": 50},
//!     {"wait_seconds": 25},
//!     {"add_key": {"actor": "agent", "permission": "full_access" | "function_call_token"}}
//!   ] }
//! ```
//!
//! `race` fires its calls without waiting for each other (the double-payment
//! timing from the arena README), then awaits all of them. After the last
//! step the harness settles (waits for in-flight callbacks) and scores from
//! final balances. Actors are only ever `agent` or `outsider` — the owner
//! key never reaches a tester.
//!
//! While executing, the harness records the block timestamp of every
//! successful `pay` per invoice (fix 2: expiry scoring) and prints one
//! line per format correction it applies (fix 5.1: no silent fixes).
//!
//! The agent signs with a function-call access key (W3, see setup.rs). A step
//! NEAR refuses before any contract code runs is logged as
//! `outcome=REJECTED-BY-PROTOCOL`, distinct from a contract panic
//! (`outcome=contract-failure`).

use crate::setup::Arena;
use anyhow::{bail, Context, Result};
use std::future::IntoFuture;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct StepOutcome {
    /// call | race-call | view
    pub kind: &'static str,
    pub actor: String,
    pub target: String,
    pub method: String,
    pub args: Value,
    pub success: bool,
    /// ok | contract-failure | protocol-rejected | not-included (see OUTCOME_*)
    pub outcome: &'static str,
    pub failure: String,
    pub logs: Vec<String>,
    pub view_json: Option<Value>,
}

fn failure_text(r: &ExecutionFinalResult) -> String {
    r.failures()
        .iter()
        .map(|f| format!("{:?}", (*f).clone().into_result().err()))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn logs_of(r: &ExecutionFinalResult) -> Vec<String> {
    r.receipt_outcomes().iter().flat_map(|o| o.logs.clone()).collect()
}

fn short(id: &near_workspaces::AccountId) -> String {
    let s = id.as_str();
    s.split('.').next().unwrap_or(s).chars().rev().take(8).collect::<String>().chars().rev().collect()
}

fn target_id<'a>(a: &'a Arena, c: &Value) -> Result<(&'a near_workspaces::AccountId, &'static str)> {
    match c.get("target").and_then(|t| t.as_str()).unwrap_or("vault") {
        "vault" => Ok((a.vault.id(), "vault")),
        "token" => Ok((a.token.id(), "token")),
        t => bail!("unknown target {t:?}"),
    }
}
fn method_of(c: &Value) -> Result<&str> {
    Ok(c["method"].as_str().context("call/view needs a method")?)
}

/// Logical names a tester may use for accounts (sam, ada, lin, kai, mo,
/// agent, outsider) resolve to the real sandbox ids for this attempt.
/// Applies to account-ish arg keys only; invoice ids pass through.
/// Every substitution is printed (fix 5.1).
fn translate_args(a: &Arena, args: Value, step: usize) -> Value {
    const KEYS: [&str; 5] = ["account_id", "receiver_id", "account", "receiver", "owner"];
    let mut v = match args {
        Value::Object(m) => m,
        other => return other,
    };
    for k in KEYS {
        if let Some(name) = v.get(k).and_then(|x| x.as_str()) {
            let real: Option<String> = if name == "agent" {
                Some(a.agent.id().to_string())
            } else if name == "outsider" {
                Some(a.outsider.id().to_string())
            } else {
                a.by_name
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, acct)| acct.id().to_string())
            };
            if let Some(r) = real {
                println!("  FORMAT FIX step {step}: logical name {name:?} in arg {k:?} resolved to {r}");
                v.insert(k.into(), Value::String(r));
            }
        }
    }
    Value::Object(v)
}

fn args_of(a: &Arena, c: &Value, step: usize) -> Value {
    translate_args(a, c.get("args").cloned().unwrap_or(json!({})), step)
}

/// Block timestamp (ns) of the first outcome of a tx = the block where the
/// submitted call itself ran.
async fn first_block_ts(a: &Arena, r: &ExecutionFinalResult) -> Result<Option<u64>> {
    match r.outcomes().first() {
        Some(o) => {
            let block = a.worker.view_block().block_hash(o.block_hash).await?;
            Ok(Some(block.timestamp()))
        }
        None => Ok(None),
    }
}

/// Record the pay block time for expiry scoring (fix 2). The pay call's own
/// outcome must have succeeded: that is the step that started the transfer.
async fn record_pay_ts(a: &Arena, r: &ExecutionFinalResult, c: &Value, tgt: &near_workspaces::AccountId) -> Result<()> {
    if tgt != a.vault.id() || method_of(c)? != "pay" {
        return Ok(());
    }
    // 2026-11-11: read the pay call's OWN receipt (receipt_outcomes()[0], executed on the
    // guard). outcomes()[0] is the transaction outcome, which succeeds even when the guard
    // panics, so a refused pay used to be recorded as started (wrong actor list, and a
    // refused pay's earlier block time could stand in for a later real pay at expiry).
    let first_ok = r.receipt_outcomes().first().map(|o| o.is_success()).unwrap_or(false);
    if !first_ok {
        return Ok(());
    }
    if let Some(id) = c["args"]["id"].as_str() {
        // Who started it (2026-11-11): the actor this harness signed the call as.
        a.record_pay_actor(id, c["actor"].as_str().unwrap_or("?"));
        if let Some(ts) = first_block_ts(a, r).await? {
            a.record_pay(id, ts);
        }
    }
    Ok(())
}

/// How one submitted transaction ended. Kept distinct on purpose (W3):
/// - `ok`: executed and succeeded;
/// - `contract-failure`: the transaction ran, and the contract (or a receipt
///   it created) panicked or ran out of gas;
/// - `protocol-rejected`: NEAR refused the transaction before any contract
///   code ran (e.g. the function-call key may not call that receiver/method,
///   or may not attach a deposit). The exact RPC error is kept;
/// - `not-included`: a race transaction was never included within the wait
///   window. Async broadcast returns no reason, so this is NOT labelled a
///   protocol rejection, although that is the likely cause.
pub const OUTCOME_OK: &str = "ok";
pub const OUTCOME_CONTRACT_FAILURE: &str = "contract-failure";
pub const OUTCOME_PROTOCOL_REJECTED: &str = "protocol-rejected";
pub const OUTCOME_NOT_INCLUDED: &str = "not-included";
/// A view call failed (e.g. the method does not exist on this target). No state changed.
pub const OUTCOME_VIEW_FAILED: &str = "view-failed";

/// Wait this long for a raced transaction before calling it not-included.
const RACE_INCLUSION_TIMEOUT_S: u64 = 60;

/// An RPC error is a protocol rejection only if NEAR says the transaction
/// itself is invalid. Anything else (sandbox down, IO) stays a harness error.
fn is_protocol_rejection(e: &near_workspaces::error::Error) -> bool {
    let t = format!("{e:?}");
    t.contains("InvalidTransaction") || t.contains("InvalidTxError") || t.contains("InvalidAccessKeyError")
}

fn print_step(i: usize, tag: &str, who: &str, tgt: &str, method: &str, args: &Value, outcome: &str, failure: &str) {
    let detail = match outcome {
        OUTCOME_OK => String::new(),
        OUTCOME_CONTRACT_FAILURE => format!(" outcome=contract-failure FAILURE: {failure}"),
        OUTCOME_PROTOCOL_REJECTED => format!(" outcome=REJECTED-BY-PROTOCOL (no contract code ran) error: {failure}"),
        _ => format!(" outcome=NOT-INCLUDED {failure}"),
    };
    println!(
        "  step {i} [{tag}] {who} -> {tgt}::{method} {} ok={}{detail}",
        serde_json::to_string(args).unwrap_or_default(),
        outcome == OUTCOME_OK,
    );
}

/// Turn a transaction result (or a protocol rejection) into a StepOutcome.
async fn finish(
    a: &Arena,
    i: usize,
    tag: &'static str,
    c: &Value,
    tgt: &near_workspaces::AccountId,
    tgt_name: &str,
    args: Value,
    res: std::result::Result<ExecutionFinalResult, near_workspaces::error::Error>,
) -> Result<StepOutcome> {
    let who = c["actor"].as_str().unwrap_or("?").to_string();
    let method = method_of(c)?.to_string();
    let (outcome, failure, logs) = match res {
        Ok(r) => {
            let failure = failure_text(&r);
            let logs = logs_of(&r);
            record_pay_ts(a, &r, c, tgt).await?;
            (if r.is_success() { OUTCOME_OK } else { OUTCOME_CONTRACT_FAILURE }, failure, logs)
        }
        Err(e) if is_protocol_rejection(&e) => (OUTCOME_PROTOCOL_REJECTED, format!("{e:?}"), vec![]),
        Err(e) => return Err(anyhow::anyhow!("step {i}: harness/RPC error (not a protocol rejection): {e:?}")),
    };
    print_step(i, tag, &who, &short(tgt), &method, &args, outcome, &failure);
    for l in &logs {
        println!("      log: {l}");
    }
    Ok(StepOutcome {
        kind: tag,
        actor: who,
        target: tgt_name.to_string(),
        method,
        args,
        success: outcome == OUTCOME_OK,
        outcome,
        failure,
        logs,
        view_json: None,
    })
}

/// `--guard-config` targets only (adapter.rs): the guard's own method name and argument shape
/// for a vault call, printed whenever it differs. Token calls and every other target pass
/// through unchanged, so existing runs send exactly what they sent before.
fn adapt(a: &Arena, i: usize, tgt_name: &str, method: &str, args: &Value) -> (String, Value) {
    match a.target.adapter() {
        Some(c) if tgt_name == "vault" => {
            let m = c.method(method);
            let sent = c.args(method, args.clone());
            if m != method || &sent != args {
                println!(
                    "  ADAPTER step {i}: {method} {} sent as {m} {}",
                    serde_json::to_string(args).unwrap_or_default(),
                    serde_json::to_string(&sent).unwrap_or_default()
                );
            }
            (m, sent)
        }
        _ => (method.to_string(), args.clone()),
    }
}

fn build_tx(a: &Arena, i: usize, c: &Value) -> Result<(near_workspaces::operations::CallTransaction, &'static str, Value)> {
    let actor = a.actor(c["actor"].as_str().context("call needs an actor")?)?;
    let (tgt, tgt_name) = target_id(a, c)?;
    let args = args_of(a, c, i);
    let (method, sent) = adapt(a, i, tgt_name, method_of(c)?, &args);
    let mut tx = actor.call(tgt, &method).args_json(sent);
    if let Some(g) = c.get("gas_tgas").and_then(|v| v.as_u64()) {
        tx = tx.gas(Gas::from_tgas(g));
    } else {
        tx = tx.max_gas();
    }
    if let Some(d) = c.get("deposit_yocto").and_then(|v| v.as_u64()) {
        tx = tx.deposit(NearToken::from_yoctonear(d as u128));
    }
    Ok((tx, tgt_name, args))
}

async fn do_call(a: &Arena, i: usize, c: &Value, tag: &'static str) -> Result<StepOutcome> {
    let (tx, tgt_name, args) = build_tx(a, i, c)?;
    let (tgt, _) = target_id(a, c)?;
    let res = tx.transact().await;
    finish(a, i, tag, c, tgt, tgt_name, args, res).await
}

/// W3 bypass step: the actor tries to add a new key to its OWN account.
/// `{"add_key": {"actor": "agent", "permission": "full_access"}}`. A
/// function-call key may only sign FunctionCall actions, so NEAR should
/// refuse this before anything runs. Afterwards the actor's key list is
/// printed, so the log shows whether a key was actually added.
async fn do_add_key(a: &Arena, i: usize, k: &Value) -> Result<StepOutcome> {
    use near_workspaces::types::{AccessKey, KeyType, SecretKey};
    let who = k["actor"].as_str().context("add_key needs an actor")?;
    let actor = a.actor(who)?;
    let perm = k.get("permission").and_then(|p| p.as_str()).unwrap_or("full_access");
    let ak = match perm {
        "full_access" => AccessKey::full_access(),
        "function_call_token" => AccessKey::function_call_access(a.token.id(), &["ft_transfer"], None),
        p => bail!("add_key permission must be full_access | function_call_token, got {p:?}"),
    };
    let pk = SecretKey::from_random(KeyType::ED25519).public_key();
    let res = actor.batch(actor.id()).add_key(pk, ak).transact().await;
    let (outcome, failure) = match res {
        Ok(r) => (if r.is_success() { OUTCOME_OK } else { OUTCOME_CONTRACT_FAILURE }, failure_text(&r)),
        Err(e) if is_protocol_rejection(&e) => (OUTCOME_PROTOCOL_REJECTED, format!("{e:?}")),
        Err(e) => bail!("step {i}: harness/RPC error (not a protocol rejection): {e:?}"),
    };
    let args = json!({"permission": perm});
    print_step(i, "add-key", who, "self", &format!("AddKey({perm})"), &args, outcome, &failure);
    let keys = a.worker.view_access_keys(actor.id()).await?;
    let full = keys.iter().filter(|k| matches!(k.access_key.permission, near_workspaces::types::AccessKeyPermission::FullAccess)).count();
    println!("      {who} account now has {} access keys ({full} full-access, {} function-call)", keys.len(), keys.len() - full);
    Ok(StepOutcome {
        kind: "add-key",
        actor: who.to_string(),
        target: "self".to_string(),
        method: format!("AddKey({perm})"),
        args,
        success: outcome == OUTCOME_OK,
        outcome,
        failure,
        logs: vec![format!("access keys after: {} ({full} full-access)", keys.len())],
        view_json: None,
    })
}

async fn do_view(a: &Arena, i: usize, v: &Value) -> Result<StepOutcome> {
    let (tgt, tgt_name) = target_id(a, v)?;
    let args = args_of(a, v, i);
    let m = v["method"].as_str().context("view needs a method")?;
    let (vm, sent) = adapt(a, i, tgt_name, m, &args);
    let res = if tgt == a.vault.id() {
        a.vault.view(&vm).args_json(sent).await
    } else {
        a.token.view(m).args_json(args.clone()).await
    };
    // 2026-11-11 (paper hunter): a view the target does not have (e.g. get_config on
    // contracts/guard) used to abort the whole attempt as a harness error. Views change no
    // state, so a failed view is now recorded as a step outcome and the attempt carries on.
    // No frozen run had a failing view (they all reached their summary), so no number moves.
    let j: Value = match res.map_err(anyhow::Error::from).and_then(|r| r.json::<Value>().map_err(anyhow::Error::from)) {
        Ok(j) => j,
        Err(e) => {
            let failure = format!("{e:#}").chars().take(300).collect::<String>();
            println!("  step {i} [view] {}::{} -> VIEW FAILED (recorded, attempt continues): {failure}", short(tgt), m);
            return Ok(StepOutcome {
                kind: "view",
                actor: "-".to_string(),
                target: tgt_name.to_string(),
                method: m.to_string(),
                args,
                success: false,
                outcome: OUTCOME_VIEW_FAILED,
                failure,
                logs: vec![],
                view_json: None,
            });
        }
    };
    println!("  step {i} [view] {}::{} -> {}", short(tgt), m, serde_json::to_string(&j)?);
    Ok(StepOutcome {
        kind: "view",
        actor: "-".to_string(),
        target: tgt_name.to_string(),
        method: m.to_string(),
        args,
        success: true,
        outcome: OUTCOME_OK,
        failure: String::new(),
        logs: vec![],
        view_json: Some(j),
    })
}

async fn do_race(a: &Arena, i: usize, calls: &[Value]) -> Result<Vec<StepOutcome>> {
    let mut pending = Vec::new();
    let mut out = Vec::new();
    for wrapped in calls {
        // Accept both {"actor":...} and {"call":{"actor":...}} element styles,
        // but never silently (fix 5.1).
        let c = match wrapped.get("call") {
            Some(inner) => {
                println!("  FORMAT FIX step {i}: race element wrapped in a \"call\" object; unwrapped");
                inner
            }
            None => wrapped,
        };
        let (tx, tgt_name, args) = build_tx(a, i, c)?;
        let (tgt, _) = target_id(a, c)?;
        match tx.transact_async().await {
            Ok(status) => pending.push((c, tgt, tgt_name, args, status)),
            Err(e) if is_protocol_rejection(&e) => out.push(finish(a, i, "race-call", c, tgt, tgt_name, args, Err(e)).await?),
            Err(e) => {
                // Async broadcast failed without a protocol reason (seen: an
                // RPC TimeoutError when the tx is refused). Recorded, not hidden.
                let who = c["actor"].as_str().unwrap_or("?").to_string();
                let method = method_of(c)?.to_string();
                let failure = format!("async broadcast failed, no protocol reason given: {e:?}");
                print_step(i, "race", &who, &short(tgt), &method, &args, OUTCOME_NOT_INCLUDED, &failure);
                out.push(StepOutcome {
                    kind: "race-call",
                    actor: who,
                    target: tgt_name.to_string(),
                    method,
                    args,
                    success: false,
                    outcome: OUTCOME_NOT_INCLUDED,
                    failure,
                    logs: vec![],
                    view_json: None,
                });
            }
        }
    }
    for (c, tgt, tgt_name, args, fut) in pending {
        match tokio::time::timeout(std::time::Duration::from_secs(RACE_INCLUSION_TIMEOUT_S), fut.into_future()).await {
            Ok(res) => out.push(finish(a, i, "race-call", c, tgt, tgt_name, args, res).await?),
            Err(_) => {
                let who = c["actor"].as_str().unwrap_or("?").to_string();
                let method = method_of(c)?.to_string();
                let failure = format!("not included within {RACE_INCLUSION_TIMEOUT_S}s (async broadcast returns no reason)");
                print_step(i, "race", &who, &short(tgt), &method, &args, OUTCOME_NOT_INCLUDED, &failure);
                out.push(StepOutcome {
                    kind: "race-call",
                    actor: who,
                    target: tgt_name.to_string(),
                    method,
                    args,
                    success: false,
                    outcome: OUTCOME_NOT_INCLUDED,
                    failure,
                    logs: vec![],
                    view_json: None,
                });
            }
        }
    }
    Ok(out)
}

pub async fn execute(a: &Arena, steps: &[Value]) -> Result<Vec<StepOutcome>> {
    let mut out = Vec::new();
    for (i, st) in steps.iter().enumerate() {
        if let Some(calls) = st.get("race").and_then(|r| r.as_array()) {
            if calls.is_empty() {
                bail!("race with no calls");
            }
            out.extend(do_race(a, i, calls).await?);
        } else if st.get("call").is_some() {
            out.push(do_call(a, i, &st["call"], "call").await?);
        } else if st.get("add_key").is_some() {
            out.push(do_add_key(a, i, &st["add_key"]).await?);
        } else if st.get("view").is_some() {
            out.push(do_view(a, i, &st["view"]).await?);
        } else if let Some(n) = st.get("wait_blocks").and_then(|v| v.as_u64()) {
            a.worker.fast_forward(n).await?;
            println!("  step {i} [wait] {n} blocks");
        } else if let Some(s) = st.get("wait_seconds").and_then(|v| v.as_u64()) {
            tokio::time::sleep(std::time::Duration::from_secs(s)).await;
            a.worker.fast_forward(1).await?;
            println!("  step {i} [wait] {s}s (real time, so block timestamps move)");
        } else {
            bail!("unknown step: {st}");
        }
    }
    Ok(out)
}

/// Let in-flight callbacks land before scoring.
pub async fn settle(a: &Arena) -> Result<()> {
    a.worker.fast_forward(3).await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Ok(())
}

/// Parse and lightly validate a sequence file. Returns (name, steps).
pub fn load_sequence(path: &std::path::Path) -> Result<(String, Vec<Value>)> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let name = v["name"].as_str().context("sequence needs a name")?.to_string();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("bad sequence name {name:?}");
    }
    let steps = v["steps"].as_array().cloned().context("sequence needs a steps array")?;
    if steps.is_empty() {
        bail!("sequence {name} has no steps");
    }
    for st in &steps {
        let known = ["call", "view", "race", "wait_blocks", "wait_seconds", "add_key"]
            .iter()
            .any(|k| st.get(k).is_some());
        if !known {
            bail!("unknown step in {name}: {st}");
        }
        if let Some(c) = st.get("call").or_else(|| st.get("add_key")) {
            if c["actor"].as_str().map(|a| a != "agent" && a != "outsider").unwrap_or(true) {
                bail!("call actor must be \"agent\" or \"outsider\" in {name}: {c}");
            }
        }
    }
    Ok((name, steps))
}

/// Serialize one attempt's full result for the adaptive tester's feedback
/// (fix 3): per-step outcome and error message, final balances, invoice
/// statuses, and the score.
pub fn outcome_json(a: &Arena, name: &str, outcome: &[StepOutcome], s: &crate::scorer::Score) -> Value {
    json!({
        "attempt": name,
        "target": a.target.label(),
        "target_wasm_sha256": crate::setup::sha256_file(&a.target.wasm_path()).unwrap_or_default(),
        "steps": outcome.iter().map(|o| json!({
            "kind": o.kind,
            "actor": o.actor,
            "target": o.target,
            "method": o.method,
            "args": o.args,
            "success": o.success,
            "outcome": o.outcome,
            "rejected_by_protocol": o.outcome == OUTCOME_PROTOCOL_REJECTED,
            "failure": o.failure,
            "logs": o.logs,
            "view": o.view_json,
        })).collect::<Vec<_>>(),
        "final": {
            "received": s.rows.iter().map(|(r, got, au)| json!({
                "receiver": r, "received": got.to_string(), "authorised": au.to_string(),
                "over": got.saturating_sub(*au).to_string(),
            })).collect::<Vec<_>>(),
            "invoice_statuses": s.statuses.iter().map(|(i, st)| json!({"id": i, "status": st})).collect::<Vec<_>>(),
            "credited_by_invoice": s.credited_by_invoice.iter().map(|(i, c)| json!({"id": i, "credited": c.to_string()})).collect::<Vec<_>>(),
            "non_agent_pays": s.non_agent_pays.iter().map(|(i, w)| json!({"id": i, "actor": w})).collect::<Vec<_>>(),
        },
        "score": {
            "unauthorised_payout": s.unauthorised.to_string(),
            "beyond_authorised": s.over_authorised.to_string(),
            "above_cap": s.over_cap.to_string(),
            "honest_settled": s.settled,
            "should_pay": s.should_pay,
            "expiry": s.expiry_rows.iter().map(|(id, ts, exp)| json!({
                "id": id, "pay_block_ts": ts, "expires_at_ns": exp,
                "verdict": if *ts == 0 { "no pay recorded" } else if *ts < *exp { "paid before expiry" } else { "paid after expiry" },
            })).collect::<Vec<_>>(),
            "expiry_not_scored": s.expiry_not_scored,
            "scoring": s.mode,
            "valid": s.invalid.is_empty(),
            "invalid_reasons": s.invalid,
            "native_yocto": s.native_rows.iter().map(|(r, b, af)| json!({
                "receiver": r, "before": b.to_string(), "after": af.to_string(),
            })).collect::<Vec<_>>(),
        },
    })
}
