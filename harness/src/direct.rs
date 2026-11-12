//! Direct-payment guards (`"shape": "direct"` in a guard config).
//!
//! The invoice path (seq.rs, scorer.rs) assumes the owner approves an invoice and the agent pays it
//! by id. A direct-pay guard has no invoices: the agent names a receiver and an amount, and the
//! guard decides from its own rules (an allowlist, a per-payment limit, a limit per UTC day, an
//! approval threshold). This module runs ONE sequence against such a guard on a fresh sandbox and
//! writes down only what it observed:
//!
//! - every request: who sent it, to whom, how much, whether NEAR accepted it, what the guard
//!   returned (for example `{"status":"pending","request_id":"3"}`) and its panic text;
//! - what each of the five receivers received, from their native NEAR balances (they sign
//!   nothing, so gas never touches them), in units of 1 milliNEAR;
//! - NEAR that reached the agent, the outsider, the owner (net of the gas each paid) or the
//!   never-created "ghost" receiver;
//! - a conservation check: what left the guard must be found at those accounts;
//! - two validity checks: the UTC day did not change between setup and the end (a guard's day
//!   limit restarts at 00:00 UTC), and the guard's balance had stopped moving when it was read.
//!
//! It does NOT decide held or broke. tools/check/direct_check.py does that, from these facts and
//! the gate's results, with fixed rules. Nothing here reads the guard's own views to score.
//!
//! The owner signs only setup and, with `--gate`, the gate's owner steps (set a new policy,
//! approve or reject the last pending request). An attack sequence may not use the owner.

use crate::setup::{resolve, snapshot_receiver, ReceiverSnapshot, NATIVE_UNIT, RECEIVERS};
use anyhow::{bail, Context, Result};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{AccessKey, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::{json, Map, Value};
use std::future::IntoFuture;

/// The receiver id that is on the allowlist but never created. A transfer to it fails and the
/// NEAR comes back to the guard, so it tests what the guard does when a payment fails.
pub const GHOST: &str = "arena-ghost.test.near";
/// Gas for every step Arena sends here (the researched guard asks for at least 100 TGas on `spend`).
const STEP_TGAS: u64 = 150;
/// Same allowance as the invoice path's agent key (setup.rs AGENT_KEY_ALLOWANCE_NEAR).
const AGENT_KEY_ALLOWANCE_NEAR: u128 = 10;
/// 1 milliNEAR: NEAR an account may gain unexplained (rounding of gas refunds).
const TOLERANCE_YOCTO: i128 = NATIVE_UNIT as i128;
const DAY_NS: u64 = 86_400_000_000_000;
const RACE_TIMEOUT_S: u64 = 60;

/// Arena's policy for a direct guard, in units (1 unit = 1 milliNEAR).
#[derive(Clone, Debug, PartialEq)]
pub struct Rules {
    pub allowlist: Vec<String>,
    pub per_payment: u128,
    pub window_limit: u128,
    pub approval_above: u128,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            allowlist: ["sam", "ada", "mo", "kai", "ghost"].iter().map(|s| s.to_string()).collect(),
            per_payment: 200,
            window_limit: 300,
            approval_above: 100,
        }
    }
}

impl Rules {
    /// The default rules with a step's overrides applied (keys: allowlist, per_payment,
    /// window_limit, approval_above). Unknown keys are refused, so a typo never silently
    /// keeps the default.
    pub fn with(&self, o: &Value) -> Result<Rules> {
        let mut r = self.clone();
        let m = match o.as_object() {
            Some(m) => m,
            None => return Ok(r),
        };
        for (k, v) in m {
            match k.as_str() {
                "actor" => {}
                "allowlist" => {
                    r.allowlist = v
                        .as_array()
                        .context("allowlist must be a list of logical names")?
                        .iter()
                        .map(|x| x.as_str().map(|s| s.to_string()).context("allowlist entries are strings"))
                        .collect::<Result<_>>()?
                }
                "per_payment" => r.per_payment = v.as_u64().context("per_payment is a whole number of units")? as u128,
                "window_limit" => r.window_limit = v.as_u64().context("window_limit is a whole number of units")? as u128,
                "approval_above" => r.approval_above = v.as_u64().context("approval_above is a whole number of units")? as u128,
                other => bail!("unknown policy key {other:?} (allowed: allowlist, per_payment, window_limit, approval_above)"),
            }
        }
        Ok(r)
    }
}

/// A direct guard's config (the `"direct"` block plus `init`), read from the guard-config file.
#[derive(Clone, Debug)]
pub struct DirectConfig {
    pub init_method: String,
    pub init_args: Value,
    pub claims: Vec<String>,
    pub pay_method: String,
    pub receiver_field: String,
    pub amount_field: String,
    pub extra_args: Map<String, Value>,
    pub policy_method: String,
    pub policy_args: Value,
    pub set_policy_method: String,
    pub set_policy_args: Value,
    pub approve: Option<(String, String)>,
    pub reject: Option<(String, String)>,
    /// (status field, value meaning "held for approval", id field)
    pub pending: Option<(String, String, String)>,
    pub callback: Option<(String, String)>,
    /// If set, the harness refuses to run any wasm whose sha256 differs (a guard Arena does not redistribute).
    pub wasm_sha256: Option<String>,
    /// Extended direct mode (direct_ext.rs); empty when the config has no `direct.ext` block.
    pub ext: crate::direct_ext::Ext,
}

pub const CLAIMS: [&str; 4] = ["allowlist", "per_payment", "window_utc_day", "approval"];

fn s(v: &Value, k: &str, what: &str) -> Result<String> {
    v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string()).with_context(|| format!("{what}: needs a string \"{k}\""))
}

fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.chars().next().map(|c| c.is_ascii_lowercase() || c == '_').unwrap_or(false)
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl DirectConfig {
    pub fn from_value(v: &Value) -> Result<Self> {
        if v.get("shape").and_then(|x| x.as_str()) != Some("direct") {
            bail!("not a direct guard config (\"shape\": \"direct\" missing)");
        }
        if v.get("pays_in").and_then(|x| x.as_str()) != Some("native") {
            bail!("a direct guard config must say \"pays_in\": \"native\" (direct guards paying in tokens are not supported yet)");
        }
        let allowed = ["arena_guard_config", "shape", "pays_in", "init", "direct", "notes", "wasm_sha256"];
        for k in v.as_object().context("guard config must be a JSON object")?.keys() {
            if !allowed.contains(&k.as_str()) {
                bail!("key {k:?} does not apply to a direct guard (allowed: {allowed:?}); invoice-path keys such as methods, shapes, features and deposits are refused here");
            }
        }
        let init = v.get("init").context("direct config needs init {method, args}")?;
        let d = v.get("direct").context("direct config needs a \"direct\" block")?;
        let pay = d.get("pay").context("direct.pay is required")?;
        let claims: Vec<String> = d
            .get("claims")
            .and_then(|c| c.as_array())
            .context("direct.claims must be a list")?
            .iter()
            .map(|c| c.as_str().map(|s| s.to_string()).context("claims are strings"))
            .collect::<Result<_>>()?;
        let ext = crate::direct_ext::Ext::from_direct(d)?;
        for c in &claims {
            if !CLAIMS.contains(&c.as_str()) && Some(c.as_str()) != ext.window_claim() {
                bail!("unknown claim {c:?} (allowed: {CLAIMS:?}, or the window claim declared in direct.ext.window)");
            }
        }
        if ext.window.is_some() && claims.iter().any(|c| c == "window_utc_day") {
            bail!("a guard has one window: claim window_utc_day or declare direct.ext.window, not both");
        }
        let pol = d.get("policy").context("direct.policy {method, args} is required")?;
        let no_setp = json!({"method": "", "args": {}});
        let setp = match d.get("set_policy") {
            Some(x) => x,
            None if !ext.set_policy_calls.is_empty() => &no_setp,
            None => bail!("direct.set_policy {{method, args}} is required (or direct.ext.set_policy_calls)"),
        };
        if d.get("set_policy").is_some() && !ext.set_policy_calls.is_empty() {
            bail!("give direct.set_policy or direct.ext.set_policy_calls, not both");
        }
        let pair = |k: &str, field: &str| -> Result<Option<(String, String)>> {
            match d.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(x) => Ok(Some((s(x, "method", k)?, s(x, field, k)?))),
            }
        };
        let pending = match d.get("pending") {
            None | Some(Value::Null) => None,
            Some(p) => Some((s(p, "status_field", "pending")?, s(p, "pending_value", "pending")?, s(p, "id_field", "pending")?)),
        };
        let c = DirectConfig {
            init_method: s(init, "method", "init")?,
            init_args: init.get("args").cloned().unwrap_or(json!({})),
            claims,
            pay_method: s(pay, "method", "pay")?,
            receiver_field: if ext.pay_args.is_some() { String::new() } else { s(pay, "receiver_field", "pay")? },
            amount_field: if ext.pay_args.is_some() { String::new() } else { s(pay, "amount_field", "pay")? },
            extra_args: pay.get("extra_args").and_then(|e| e.as_object()).cloned().unwrap_or_default(),
            policy_method: s(pol, "method", "policy")?,
            policy_args: pol.get("args").cloned().context("policy.args")?,
            set_policy_method: s(setp, "method", "set_policy")?,
            set_policy_args: setp.get("args").cloned().context("set_policy.args")?,
            approve: pair("approve", "id_field")?,
            reject: pair("reject", "id_field")?,
            pending,
            callback: pair("callback", "id_field")?,
            wasm_sha256: v.get("wasm_sha256").and_then(|x| x.as_str()).map(|x| x.to_ascii_lowercase()),
            ext,
        };
        for m in c.methods() {
            if !name_ok(&m) {
                bail!("method name {m:?} is not a NEAR method name");
            }
        }
        if c.claims.iter().any(|x| x == "approval") && (c.approve.is_none() || c.reject.is_none() || (c.pending.is_none() && !c.ext.pending_bare_id)) {
            bail!("the approval claim needs direct.approve, direct.reject and direct.pending");
        }
        Ok(c)
    }

    pub fn load(path: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("read {path}"))?)
            .with_context(|| format!("{path}: not JSON"))?;
        Self::from_value(&v).with_context(|| format!("{path}"))
    }

    pub fn methods(&self) -> Vec<String> {
        let mut m = vec![self.init_method.clone(), self.pay_method.clone(), self.policy_method.clone(), self.set_policy_method.clone()];
        for (x, _) in [&self.approve, &self.reject, &self.callback].into_iter().flatten() {
            m.push(x.clone());
        }
        m.extend(self.ext.methods());
        m.retain(|x| !x.is_empty());
        m
    }
}

/// Fill a template: a string that is exactly one placeholder becomes its value (a string, or a
/// list for $allowlist); every other value is copied. Unknown placeholders are an error.
pub fn fill(t: &Value, vars: &[(&str, Value)]) -> Result<Value> {
    Ok(match t {
        Value::String(x) if x.starts_with('$') => vars
            .iter()
            .find(|(k, _)| *k == x.as_str())
            .map(|(_, v)| v.clone())
            .with_context(|| format!("unknown placeholder {x} (known: {:?})", vars.iter().map(|(k, _)| *k).collect::<Vec<_>>()))?,
        Value::Array(a) => Value::Array(a.iter().map(|x| fill(x, vars)).collect::<Result<_>>()?),
        Value::Object(o) => {
            let mut m = Map::new();
            for (k, v) in o {
                m.insert(k.clone(), fill(v, vars)?);
            }
            Value::Object(m)
        }
        other => other.clone(),
    })
}

/// Conservation, pure: guard outflow vs what Arena found. All yocto.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Flow {
    pub guard_out: i128,
    pub receivers_in: i128,
    /// (label, yocto gained net of own gas) for agent, outsider, owner, ghost
    pub others: Vec<(String, i128)>,
    pub reward_bound: i128,
}

/// Returns (unaccounted yocto, invalid reasons).
pub fn conserve(f: &Flow) -> (i128, Vec<String>) {
    let found: i128 = f.receivers_in + f.others.iter().map(|(_, g)| (*g).max(0)).filter(|g| *g > TOLERANCE_YOCTO).sum::<i128>();
    let un = f.guard_out - found;
    let mut bad = Vec::new();
    if un > TOLERANCE_YOCTO {
        bad.push(format!(
            "{} yoctoNEAR left the guard and Arena cannot see where it went (guard outflow {}, found {})",
            un, f.guard_out, found
        ));
    } else if un < -(TOLERANCE_YOCTO + f.reward_bound) {
        bad.push(format!(
            "accounts gained {} yoctoNEAR more than left the guard (outflow {}, found {}, gas-reward bound {}); the accounting does not add up",
            -un, f.guard_out, found, f.reward_bound
        ));
    }
    (un, bad)
}

/// The UTC day number of a block timestamp.
pub fn utc_day(ts_ns: u64) -> u64 {
    ts_ns / DAY_NS
}

struct Ctx {
    worker: Worker<Sandbox>,
    owner: Account,
    agent: Account,
    agent_full: Account,
    outsider: Account,
    guard: Contract,
    receivers: Vec<(&'static str, Account)>,
    cfg: DirectConfig,
    gate: bool,
    /// (actor, tokens burnt over the whole transaction)
    burnt: std::sync::Mutex<Vec<(String, u128)>>,
    burnt_on_guard: std::sync::Mutex<u128>,
    pending_ids: std::sync::Mutex<Vec<Value>>,
    transfer_ids: std::sync::Mutex<Vec<Value>>,
    /// Read the guard's calls to itself after each step (gate runs, and any sequence that forges a callback).
    want_self_calls: bool,
    /// (transfer id the payment returned, the arguments the guard passed when it called its own
    /// mapped callback for that payment). A forged callback for "last_transfer" sends exactly these.
    self_args: std::sync::Mutex<Vec<(Value, Value)>>,
    /// Extended direct mode (direct_ext.rs): nonce counter, captured setup values, clock moves.
    xs: std::sync::Mutex<crate::direct_ext::State>,
    /// The key Arena signs payments with, for a guard that checks a signature (ext.sign).
    signer_sk: Option<SecretKey>,
    /// The agent's key when it sits on the guard's own account (ext.pay_key).
    agent_pk: Option<String>,
}

impl Ctx {
    fn id_of(&self, logical: &str) -> Result<String> {
        if logical == "ghost" {
            return Ok(GHOST.to_string());
        }
        match logical {
            "agent" => return Ok(self.agent_full.id().to_string()),
            "outsider" => return Ok(self.outsider.id().to_string()),
            "owner" => return Ok(self.owner.id().to_string()),
            _ => {}
        }
        self.receivers
            .iter()
            .find(|(n, _)| *n == logical)
            .map(|(_, a)| a.id().to_string())
            .with_context(|| format!("unknown account name {logical:?} (sam, ada, lin, kai, mo, ghost, agent, outsider, owner)"))
    }

    fn signer(&self, actor: &str) -> Result<&Account> {
        match actor {
            "agent" => Ok(&self.agent),
            "outsider" => Ok(&self.outsider),
            "owner" if self.gate => Ok(&self.owner),
            "owner" => bail!("the owner signs only in gate runs (--gate); an attack may act only as agent or outsider"),
            other => bail!("actor must be agent or outsider, got {other:?}"),
        }
    }

    fn policy_vars(&self, r: &Rules) -> Result<Vec<(&'static str, Value)>> {
        let ids: Vec<Value> = r.allowlist.iter().map(|n| self.id_of(n).map(Value::String)).collect::<Result<_>>()?;
        Ok(vec![
            ("$owner", json!(self.owner.id())),
            ("$agent", json!(self.agent_full.id())),
            ("$allowlist", Value::Array(ids)),
            ("$per_payment", json!((r.per_payment * NATIVE_UNIT).to_string())),
            ("$window_limit", json!((r.window_limit * NATIVE_UNIT).to_string())),
            ("$approval_above", json!((r.approval_above * NATIVE_UNIT).to_string())),
        ]
        .into_iter()
        .chain(crate::direct_ext::vars(self.guard.id().as_str(), r.approval_above * NATIVE_UNIT, self.agent_pk.as_deref(), self.signer_sk.as_ref(), &self.xs.lock().unwrap()))
        .collect())
    }

    /// Fill a template: the extended operators ($concat, $prefix_each) only for an ext config, so
    /// a config without `direct.ext` is filled exactly as before.
    fn tfill(&self, t: &Value, vars: &[(&str, Value)]) -> Result<Value> {
        if self.cfg.ext.present {
            crate::direct_ext::expand(t, vars)
        } else {
            fill(t, vars)
        }
    }

    /// Who paid a transaction's gas: the agent's key on the guard account is paid by the guard.
    fn gas_payer(&self, actor: &str) -> String {
        if actor == "agent" && self.agent_pk.is_some() {
            "guard-key".into()
        } else {
            actor.into()
        }
    }

    fn record(&self, actor: &str, r: &ExecutionFinalResult) {
        let burnt: u128 = r.outcomes().iter().map(|o| o.tokens_burnt.as_yoctonear()).sum();
        let on_guard: u128 = r.outcomes().iter().filter(|o| &o.executor_id == self.guard.id()).map(|o| o.tokens_burnt.as_yoctonear()).sum();
        self.burnt.lock().unwrap().push((self.gas_payer(actor), burnt));
        *self.burnt_on_guard.lock().unwrap() += on_guard;
    }
}

fn is_protocol_rejection(e: &near_workspaces::error::Error) -> bool {
    let t = format!("{e:?}");
    t.contains("InvalidTransaction") || t.contains("InvalidTxError") || t.contains("InvalidAccessKeyError")
}

fn failure_text(r: &ExecutionFinalResult) -> String {
    match r.clone().into_result() {
        Ok(_) => String::new(),
        Err(e) => {
            // Keep the guard's own panic text, not the whole debug dump.
            let t = format!("{e:?}");
            let from = t.find("Smart contract panicked").or_else(|| t.find("ExecutionError")).or_else(|| t.find("ActionError")).unwrap_or(0);
            t[from..].chars().take(300).collect()
        }
    }
}

/// One planned call: (actor, method, args, ledger fields).
struct Planned {
    actor: String,
    method: String,
    args: Value,
    entry: Value,
    /// yoctoNEAR attached (ext.deposits / a call's deposit); 0 for every non-ext config
    deposit: u128,
    /// the last call of a multi-call set-policy: on success the policy version moves on
    bump: bool,
}

fn plan_pay(cx: &Ctx, p: &Value) -> Result<Planned> {
    let actor = p.get("actor").and_then(|x| x.as_str()).unwrap_or("agent").to_string();
    let recv = p.get("receiver").and_then(|x| x.as_str()).context("pay needs a receiver (logical name)")?;
    let amount = p.get("amount").and_then(|x| x.as_u64()).context("pay needs an amount in units")? as u128;
    let args = if cx.cfg.ext.present {
        crate::direct_ext::pay_args(&cx.cfg, &cx.policy_vars(&Rules::default())?, &cx.id_of(recv)?, amount * NATIVE_UNIT, cx.signer_sk.as_ref(), &mut cx.xs.lock().unwrap())?
    } else {
        let mut args = cx.cfg.extra_args.clone();
        args.insert(cx.cfg.receiver_field.clone(), json!(cx.id_of(recv)?));
        args.insert(cx.cfg.amount_field.clone(), json!((amount * NATIVE_UNIT).to_string()));
        Value::Object(args)
    };
    Ok(Planned {
        actor: actor.clone(),
        method: cx.cfg.pay_method.clone(),
        args,
        entry: json!({"kind": "pay", "actor": actor, "receiver": recv, "amount": amount.to_string()}),
        deposit: 0,
        bump: false,
    })
}

fn plan_set_policy(cx: &Ctx, p: &Value) -> Result<Vec<Planned>> {
    let actor = p.get("actor").and_then(|x| x.as_str()).unwrap_or("owner").to_string();
    let r = Rules::default().with(p)?;
    let entry = json!({"kind": "set_policy", "actor": actor, "rules": {
            "allowlist": r.allowlist, "per_payment": r.per_payment.to_string(),
            "window_limit": r.window_limit.to_string(), "approval_above": r.approval_above.to_string()}});
    if cx.cfg.ext.set_policy_calls.is_empty() {
        let args = cx.tfill(&cx.cfg.set_policy_args, &cx.policy_vars(&r)?)?;
        return Ok(vec![Planned { actor, method: cx.cfg.set_policy_method.clone(), args, entry, deposit: cx.cfg.ext.dep_set_policy, bump: true }]);
    }
    // Several owner calls; `each` repeats one per account (on the new list, added, or removed).
    let ids = |names: &[String]| -> Result<Vec<String>> { names.iter().map(|n| cx.id_of(n)).collect() };
    let (new, setup) = (ids(&r.allowlist)?, ids(&Rules::default().allowlist)?);
    let mut vars = cx.policy_vars(&r)?;
    let next = cx.xs.lock().unwrap().policy_version + 1;
    vars.retain(|(k, _)| *k != "$policy_version");
    vars.push(("$policy_version", json!(next)));
    let mut out = Vec::new();
    for c in &cx.cfg.ext.set_policy_calls {
        let each: Vec<Option<String>> = match &c.each {
            Some(e) => crate::direct_ext::each_list(e, &new, &setup).into_iter().map(Some).collect(),
            None => vec![None],
        };
        for a in each {
            let mut v = vars.clone();
            if let Some(a) = &a {
                v.push(("$each", json!(a)));
            }
            let mut e = entry.clone();
            e["part"] = json!(out.len());
            out.push(Planned { actor: actor.clone(), method: c.method.clone(), args: cx.tfill(&c.args, &v)?, entry: e, deposit: c.deposit, bump: false });
        }
    }
    if let Some(l) = out.last_mut() {
        l.bump = true;
    }
    Ok(out)
}

fn plan_decide(cx: &Ctx, kind: &str, p: &Value) -> Result<Planned> {
    let actor = p.get("actor").and_then(|x| x.as_str()).unwrap_or("owner").to_string();
    let (m, field) = if kind == "approve" { cx.cfg.approve.clone() } else { cx.cfg.reject.clone() }
        .with_context(|| format!("{kind}: the config maps no {kind} method"))?;
    let id = cx.pending_ids.lock().unwrap().last().cloned().with_context(|| format!("{kind}: no pending request id was returned earlier in this sequence"))?;
    let (extra, deposit) = if kind == "approve" { (&cx.cfg.ext.approve_args, cx.cfg.ext.dep_approve) } else { (&cx.cfg.ext.reject_args, cx.cfg.ext.dep_reject) };
    let mut args = match cx.tfill(&Value::Object(extra.clone()), &cx.policy_vars(&Rules::default())?)? {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    args.insert(field, id.clone());
    Ok(Planned { actor: actor.clone(), method: m, args: Value::Object(args), entry: json!({"kind": kind, "actor": actor, "request_id": id}), deposit, bump: false })
}

fn plan_callback(cx: &Ctx, p: &Value) -> Result<Planned> {
    let actor = p.get("actor").and_then(|x| x.as_str()).unwrap_or("outsider").to_string();
    let (m, field) = cx.cfg.callback.clone().context("callback: the config maps no callback method")?;
    let id = match p.get("id") {
        Some(Value::String(x)) if x == "last_transfer" => cx.transfer_ids.lock().unwrap().last().cloned().context("no transfer id returned earlier")?,
        Some(v) if v.is_u64() => json!(v.as_u64().unwrap().to_string()),
        Some(v) => v.clone(),
        None => bail!("callback needs an id (a number, or \"last_transfer\")"),
    };
    // The forge is the guard's own callback call for that payment, byte for byte in meaning: every
    // per-payment value (amount, nonce, receiver, hash) matches by construction. Only the caller differs.
    let args = cx
        .self_args
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(i, _)| i == &id)
        .map(|(_, a)| a.clone())
        .with_context(|| format!("callback: the guard never called {m} on itself with {field}={id} after that payment, so Arena cannot build the forged call"))?;
    Ok(Planned { actor: actor.clone(), method: m, args, entry: json!({"kind": "callback", "actor": actor, "id": id}), deposit: 0, bump: false })
}

fn plan(cx: &Ctx, st: &Value) -> Result<Vec<Planned>> {
    if let Some(p) = st.get("pay") {
        Ok(vec![plan_pay(cx, p)?])
    } else if let Some(p) = st.get("set_policy") {
        plan_set_policy(cx, p)
    } else if let Some(p) = st.get("approve") {
        Ok(vec![plan_decide(cx, "approve", p)?])
    } else if let Some(p) = st.get("reject") {
        Ok(vec![plan_decide(cx, "reject", p)?])
    } else if let Some(p) = st.get("callback") {
        Ok(vec![plan_callback(cx, p)?])
    } else {
        bail!("unknown direct step {st} (pay, set_policy, approve, reject, callback, race, wait_blocks, advance)")
    }
}

async fn finish(cx: &Ctx, i: usize, pl: Planned, res: std::result::Result<ExecutionFinalResult, near_workspaces::error::Error>) -> Result<Value> {
    let mut e = pl.entry.clone();
    e["step"] = json!(i);
    e["method"] = json!(pl.method);
    e["args"] = pl.args.clone();
    if pl.deposit > 0 {
        e["deposit_yocto"] = json!(pl.deposit.to_string());
    }
    match res {
        Ok(r) => {
            cx.record(&pl.actor, &r);
            e["receipts"] = crate::receipts::trace(&cx.worker, &r).await;
            if cx.want_self_calls {
                e["self_calls"] = crate::selfcalls::trace(&cx.worker, &r, cx.guard.id().as_str()).await;
            }
            let ok = r.is_success();
            e["outcome"] = json!(if ok { "ok" } else { "contract-failure" });
            e["failure"] = json!(failure_text(&r));
            e["logs"] = json!(r.logs().iter().map(|l| l.chars().take(300).collect::<String>()).collect::<Vec<_>>());
            if ok {
                let ret: Value = r.json().unwrap_or(Value::Null);
                if pl.bump && pl.entry.get("kind").and_then(|k| k.as_str()) == Some("set_policy") {
                    cx.xs.lock().unwrap().policy_version += 1;
                }
                if cx.cfg.ext.pending_bare_id && (ret.is_string() || ret.is_u64()) {
                    cx.pending_ids.lock().unwrap().push(ret.clone());
                    e["held"] = json!(true);
                }
                if let Some((sf, pv, idf)) = &cx.cfg.pending {
                    if ret.get(sf).and_then(|x| x.as_str()) == Some(pv.as_str()) {
                        if let Some(id) = ret.get(idf) {
                            cx.pending_ids.lock().unwrap().push(id.clone());
                            e["held"] = json!(true);
                        }
                    }
                }
                if let Some((cm, f)) = &cx.cfg.callback {
                    if let Some(id) = ret.get(f) {
                        cx.transfer_ids.lock().unwrap().push(id.clone());
                        // Same JSON value, same type (serde_json equality is type-strict).
                        for c in e.get("self_calls").and_then(|x| x.as_array()).into_iter().flatten() {
                            if c.get("method").and_then(|x| x.as_str()) == Some(cm.as_str()) && c.pointer(&format!("/args/{f}")) == Some(id) {
                                cx.self_args.lock().unwrap().push((id.clone(), c["args"].clone()));
                            }
                        }
                    }
                }
                e["returned"] = ret;
            }
        }
        Err(err) if is_protocol_rejection(&err) => {
            e["outcome"] = json!("protocol-rejected");
            e["failure"] = json!(format!("{err:?}").chars().take(400).collect::<String>());
        }
        Err(err) => bail!("step {i}: harness/RPC error (not a protocol rejection): {err:?}"),
    }
    println!("  step {i} {}", serde_json::to_string(&e)?);
    Ok(e)
}

fn tx<'a>(cx: &'a Ctx, pl: &Planned) -> Result<near_workspaces::operations::CallTransaction> {
    let who = cx.signer(&pl.actor)?;
    Ok(who.call(cx.guard.id(), &pl.method).args_json(pl.args.clone()).gas(Gas::from_tgas(STEP_TGAS)).deposit(NearToken::from_yoctonear(pl.deposit)))
}

async fn execute(cx: &Ctx, steps: &[Value]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (i, st) in steps.iter().enumerate() {
        if cx.cfg.ext.present {
            crate::direct_ext::before_step(&cx.worker, cx.guard.id(), &cx.cfg, &mut *cx.xs.lock().unwrap()).await?;
        }
        if let Some(a) = st.get("advance") {
            out.push(crate::direct_ext::advance_step(&cx.worker, &cx.cfg, a, i, &mut *cx.xs.lock().unwrap()).await?);
            continue;
        }
        if let Some(n) = st.get("wait_blocks").and_then(|v| v.as_u64()) {
            cx.worker.fast_forward(n).await?;
            out.push(json!({"step": i, "kind": "wait_blocks", "n": n}));
            continue;
        }
        if let Some(calls) = st.get("race").and_then(|r| r.as_array()) {
            let mut sent = Vec::new();
            for c in calls {
                for pl in plan(cx, c)? {
                    match tx(cx, &pl)?.transact_async().await {
                        Ok(status) => sent.push((pl, status)),
                        Err(err) if is_protocol_rejection(&err) => out.push(finish(cx, i, pl, Err(err)).await?),
                        Err(err) => bail!("step {i}: async broadcast failed: {err:?}"),
                    }
                }
            }
            for (pl, fut) in sent {
                match tokio::time::timeout(std::time::Duration::from_secs(RACE_TIMEOUT_S), fut.into_future()).await {
                    Ok(res) => out.push(finish(cx, i, pl, res).await?),
                    Err(_) => {
                        let mut e = pl.entry.clone();
                        e["step"] = json!(i);
                        e["outcome"] = json!("not-included");
                        out.push(e);
                    }
                }
            }
            continue;
        }
        for pl in plan(cx, st)? {
            let res = tx(cx, &pl)?.transact().await;
            out.push(finish(cx, i, pl, res).await?);
        }
    }
    Ok(out)
}

async fn yocto(w: &Worker<Sandbox>, id: &str) -> Result<Option<u128>> {
    let acct: near_workspaces::AccountId = id.parse()?;
    Ok(w.view_account(&acct).await.ok().map(|d| d.balance.as_yoctonear()))
}

async fn block_ts(w: &Worker<Sandbox>) -> Result<u64> {
    Ok(w.view_block().await?.timestamp())
}

/// Run one direct sequence. Returns the result JSON (also when setup fails: `setup_error`).
pub async fn run(seq_path: &std::path::Path, wasm: &std::path::Path, cfg_path: &str, gate: bool) -> Result<Value> {
    let cfg = DirectConfig::load(cfg_path)?;
    let sv: Value = serde_json::from_str(&std::fs::read_to_string(seq_path)?).with_context(|| format!("{}: not JSON", seq_path.display()))?;
    let name = sv.get("name").and_then(|x| x.as_str()).unwrap_or("unnamed").to_string();
    let steps = sv.get("steps").and_then(|x| x.as_array()).cloned().context("sequence needs steps")?;
    let wasm_bytes = std::fs::read(wasm).with_context(|| format!("{}: missing", wasm.display()))?;
    let sha = crate::setup::sha256_file(wasm)?;
    if let Some(pin) = &cfg.wasm_sha256 {
        if &sha != pin {
            bail!("{}: sha256 {sha} is not the {pin} the guard config pins; refusing to run", wasm.display());
        }
    }
    let mut result = json!({
        "arena_direct_result": 1, "name": name, "wasm_sha256": sha, "gate": gate,
        "claims": cfg.claims, "unit": "1 milliNEAR", "ghost": GHOST,
    });

    let worker = near_workspaces::sandbox().await?;
    let owner = worker.dev_create_account().await?;
    let agent_full = worker.dev_create_account().await?;
    let outsider = worker.dev_create_account().await?;
    let mut receivers = Vec::new();
    for r in RECEIVERS {
        receivers.push((r, worker.dev_create_account().await?));
    }
    let guard = worker.dev_deploy(&wasm_bytes).await?;
    let fc = SecretKey::from_random(KeyType::ED25519);
    let pay_m = [cfg.pay_method.as_str()];
    let key_on_guard = cfg.ext.pay_key.clone();
    let agent = if let Some(how) = &key_on_guard {
        // ext.pay_key: the agent is a key on the guard's own account (see direct_ext.rs).
        if *how == crate::direct_ext::KeyInstall::Arena {
            let r = guard
                .as_account()
                .batch(guard.id())
                .add_key(fc.public_key(), AccessKey::function_call_access(guard.id(), &pay_m, Some(NearToken::from_near(AGENT_KEY_ALLOWANCE_NEAR))))
                .transact()
                .await?;
            if !r.is_success() {
                bail!("SETUP: adding the agent's function-call key to the guard account failed");
            }
        }
        Account::from_secret_key(guard.id().clone(), fc.clone(), &worker)
    } else {
        let r = agent_full
            .batch(agent_full.id())
            .add_key(fc.public_key(), AccessKey::function_call_access(guard.id(), &pay_m, Some(NearToken::from_near(AGENT_KEY_ALLOWANCE_NEAR))))
            .transact()
            .await?;
        if !r.is_success() {
            bail!("SETUP: adding the agent's function-call key failed");
        }
        Account::from_secret_key(agent_full.id().clone(), fc.clone(), &worker)
    };
    let signer_sk = cfg.ext.sign.as_ref().map(|_| SecretKey::from_random(KeyType::ED25519));
    let cx = Ctx {
        worker: worker.clone(),
        owner,
        agent,
        agent_full,
        outsider,
        guard,
        receivers,
        cfg: cfg.clone(),
        gate,
        burnt: Default::default(),
        burnt_on_guard: Default::default(),
        pending_ids: Default::default(),
        transfer_ids: Default::default(),
        want_self_calls: gate || steps.iter().any(|st| st.get("callback").is_some() || st.get("race").and_then(|r| r.as_array()).map_or(false, |r| r.iter().any(|c| c.get("callback").is_some()))),
        self_args: Default::default(),
        xs: Default::default(),
        signer_sk,
        agent_pk: key_on_guard.as_ref().map(|_| fc.public_key().to_string()),
    };
    result["agent_key"] = match &key_on_guard {
        None => json!({"on": "the agent's own account", "receiver": "the guard", "methods": [cfg.pay_method], "allowance_near": AGENT_KEY_ALLOWANCE_NEAR.to_string()}),
        Some(how) => json!({"on": "the guard's own account", "installed_by": format!("{how:?}").to_lowercase(), "public_key": fc.public_key().to_string()}),
    };
    if cx.signer_sk.is_some() {
        result["signer"] = json!("Arena generated the signing key the guard was initialised with and signed every payment itself: this tests the guard's on-chain checks of a signature, not the real off-chain service");
    }

    // Setup: init (signed by the guard account itself), then the owner sets Arena's policy.
    let rules = Rules::default();
    let vars = cx.policy_vars(&rules)?;
    let init_args = cx.tfill(&cfg.init_args, &vars)?;
    let r = cx.guard.call(&cfg.init_method).args_json(init_args.clone()).transact().await?;
    if !r.is_success() {
        result["setup_error"] = json!(format!("init `{}` failed: {}", cfg.init_method, failure_text(&r)));
        return Ok(result);
    }
    let pol_args = cx.tfill(&cfg.policy_args, &vars)?;
    let r = cx.owner.call(cx.guard.id(), &cfg.policy_method).args_json(pol_args.clone()).gas(Gas::from_tgas(STEP_TGAS))
        .deposit(NearToken::from_yoctonear(cfg.ext.dep_policy)).transact().await?;
    if !r.is_success() {
        result["setup_error"] = json!(format!("policy `{}` failed: {}", cfg.policy_method, failure_text(&r)));
        return Ok(result);
    }
    if cfg.ext.present {
        cx.xs.lock().unwrap().captures_from(&cfg.ext, cfg.ext.policy_returns_as.as_deref(), &r);
        match crate::direct_ext::setup_calls(&cx.owner, cx.guard.id(), &cfg.ext, &rules.allowlist.iter().map(|n| cx.id_of(n)).collect::<Result<Vec<_>>>()?,
            |extra| { let mut v = cx.policy_vars(&rules)?; v.extend(extra); Ok(v) }, |t, v| cx.tfill(t, v), &cx.xs).await? {
            Ok(done) => result["setup_ext"] = done,
            Err(why) => {
                result["setup_error"] = json!(why);
                return Ok(result);
            }
        }
        if key_on_guard.is_some() {
            match crate::direct_ext::check_pay_key(&worker, cx.guard.id(), &fc.public_key(), &cfg.pay_method).await? {
                Ok(seen) => result["agent_key"]["seen_on_chain"] = seen,
                Err(why) => {
                    result["setup_error"] = json!(why);
                    return Ok(result);
                }
            }
        }
    }
    println!("DIRECT setup: init {}({init_args}); owner {}({pol_args})", cfg.init_method, cfg.policy_method);
    result["setup"] = json!({"init": {"method": cfg.init_method, "args": init_args}, "policy": {"method": cfg.policy_method, "args": pol_args},
        "rules": {"allowlist": rules.allowlist, "per_payment": rules.per_payment.to_string(), "window_limit": rules.window_limit.to_string(), "approval_above": rules.approval_above.to_string()}});

    // Before: receivers (balance + key nonces), the guard, agent, outsider, owner.
    let mut snaps: Vec<ReceiverSnapshot> = Vec::new();
    for (n, a) in &cx.receivers {
        snaps.push(snapshot_receiver(&worker, n, a.id()).await?);
    }
    let gid = cx.guard.id().to_string();
    // Setup's own gas refunds land a few blocks after its transactions: wait until the owner's,
    // the agent's and the guard's balances stop moving, so they are not read as a payment.
    let watch = [gid.clone(), cx.owner.id().to_string(), cx.agent_full.id().to_string()];
    let mut prev: Vec<Option<u128>> = Vec::new();
    for round in 0..10 {
        worker.fast_forward(2).await?;
        let mut now = Vec::new();
        for id in &watch {
            now.push(yocto(&worker, id).await?);
        }
        if now == prev {
            break;
        }
        if round == 9 {
            bail!("SETUP: balances were still moving after setup (10 rounds); not starting the attempt");
        }
        prev = now;
    }
    let parties = [("agent", cx.agent_full.id().to_string()), ("outsider", cx.outsider.id().to_string()), ("owner", cx.owner.id().to_string())];
    let guard_before = yocto(&worker, &gid).await?.context("guard missing")?;
    let mut party_before = Vec::new();
    for (_l, id) in &parties {
        party_before.push(yocto(&worker, id).await?.unwrap_or(0));
    }
    let ts0 = block_ts(&worker).await?;

    let ledger = execute(&cx, &steps).await?;

    // Settle: wait until the guard's balance stops moving (two equal reads 3 blocks apart).
    let mut stable = false;
    let mut last = yocto(&worker, &gid).await?.unwrap_or(0);
    for _ in 0..8 {
        worker.fast_forward(3).await?;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let now = yocto(&worker, &gid).await?.unwrap_or(0);
        if now == last {
            stable = true;
            break;
        }
        last = now;
    }
    let ts1 = block_ts(&worker).await?;
    let mut invalid: Vec<String> = Vec::new();
    if !stable {
        invalid.push("the guard's NEAR balance was still moving after 8 settle rounds; money was in flight when Arena read it".into());
    }
    let advanced = cx.xs.lock().unwrap().advanced_secs;
    if cfg.ext.present {
        // A sequence that moves the clock is judged on its own expectations (the gate's window
        // sequences); otherwise the attempt must sit inside one window of the declared kind.
        if let Some(why) = crate::direct_ext::window_validity(&cfg, ts0, ts1, advanced) {
            invalid.push(why);
        }
        result["clock"] = json!({"advanced_secs": advanced, "note": "fast-forward skips blocks: no code runs in them, so only guards that compute their window from the block time on the next call are tested this way"});
    } else if utc_day(ts0) != utc_day(ts1) {
        invalid.push(format!("the UTC day changed during the attempt (block time {ts0} -> {ts1}); a per-day limit restarts at 00:00 UTC, so Arena cannot judge it"));
    }

    // Receivers.
    let mut received = Map::new();
    let mut receivers_in: i128 = 0;
    for ((n, a), b) in cx.receivers.iter().zip(&snaps) {
        let after = snapshot_receiver(&worker, n, a.id()).await?;
        match crate::scorer::native_received(b, &after, NATIVE_UNIT) {
            Ok(u) => {
                received.insert(n.to_string(), json!(u.to_string()));
                receivers_in += (u * NATIVE_UNIT) as i128;
            }
            Err(why) => invalid.push(why),
        }
    }
    // Others, net of the gas they paid.
    let burnt = cx.burnt.lock().unwrap().clone();
    let spent = |who: &str| -> i128 { burnt.iter().filter(|(a, _)| a == who).map(|(_, b)| *b as i128).sum() };
    let mut others = Vec::new();
    let mut outside = Map::new();
    for ((l, id), b) in parties.iter().zip(&party_before) {
        let after = yocto(&worker, id).await?.unwrap_or(0) as i128;
        let g = after - *b as i128 + spent(l);
        others.push((l.to_string(), g));
        outside.insert(l.to_string(), json!(if g > TOLERANCE_YOCTO { (g / NATIVE_UNIT as i128).to_string() } else { "0".to_string() }));
    }
    let ghost_after = yocto(&worker, GHOST).await?;
    if let Some(g) = ghost_after {
        others.push(("ghost".into(), g as i128));
        outside.insert("ghost".into(), json!((g / NATIVE_UNIT).to_string()));
        invalid.push(format!("the never-created receiver {GHOST} exists after the attempt with {g} yoctoNEAR"));
    }
    let guard_after = yocto(&worker, &gid).await?.unwrap_or(0);
    let reward_bound = (*cx.burnt_on_guard.lock().unwrap() * 3 / 10) as i128;
    // ext.pay_key: the agent's key sits on the guard account, so the guard paid that gas itself.
    let guard_key_gas = spent("guard-key");
    let flow = Flow { guard_out: guard_before as i128 - guard_after as i128 - guard_key_gas, receivers_in, others: others.clone(), reward_bound };
    let (unaccounted, bad) = conserve(&flow);
    invalid.extend(bad);

    result["steps"] = Value::Array(ledger);
    result["received"] = Value::Object(received);
    result["outside"] = Value::Object(outside);
    result["conservation"] = json!({
        "guard_out_yocto": flow.guard_out.to_string(), "receivers_in_yocto": receivers_in.to_string(),
        "others_net_yocto": others.iter().map(|(l, g)| json!({"who": l, "yocto": g.to_string()})).collect::<Vec<_>>(),
        "unaccounted_yocto": unaccounted.to_string(), "reward_bound_yocto": reward_bound.to_string(),
        "tolerance_yocto": TOLERANCE_YOCTO.to_string(), "guard_paid_agent_gas_yocto": guard_key_gas.to_string(),
    });
    result["utc_day"] = json!({"start_block_ns": ts0.to_string(), "end_block_ns": ts1.to_string(), "same_day": utc_day(ts0) == utc_day(ts1)});
    result["settled"] = json!(stable);
    result["valid"] = json!(invalid.is_empty());
    result["invalid_reasons"] = json!(invalid);
    Ok(result)
}

/// `harness direct <seq.json> --wasm <path> --guard-config <file> --out <result.json> [--gate]`
pub async fn main(args: &[String]) -> Result<()> {
    let flag = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let seq = args.get(1).filter(|a| !a.starts_with("--")).context("direct <seq.json> --wasm W --guard-config C --out R [--gate]")?;
    let wasm = flag("--wasm").context("direct needs --wasm")?;
    let cfg = flag("--guard-config").context("direct needs --guard-config")?;
    let out = flag("--out").context("direct needs --out")?;
    let gate = args.iter().any(|a| a == "--gate");
    let _ = resolve(".");
    let v = run(std::path::Path::new(seq), std::path::Path::new(&wasm), &cfg, gate).await?;
    std::fs::write(&out, serde_json::to_string_pretty(&v)?)?;
    println!("DIRECT result: {out} valid={} setup_error={}", v["valid"], v.get("setup_error").is_some());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const U: i128 = NATIVE_UNIT as i128;

    #[test]
    fn rules_overrides_and_typos() {
        let r = Rules::default().with(&json!({"per_payment": 40, "approval_above": 40})).unwrap();
        assert_eq!(r.per_payment, 40);
        assert_eq!(r.window_limit, 300);
        assert!(Rules::default().with(&json!({"per_paymnet": 40})).is_err());
    }

    #[test]
    fn fill_replaces_whole_placeholders_only() {
        let t = json!({"agent": "$agent", "policy": {"allowlist": "$allowlist", "paused": false, "note": "x$agent"}});
        let v = fill(&t, &[("$agent", json!("a.test.near")), ("$allowlist", json!(["s", "t"]))]).unwrap();
        assert_eq!(v["agent"], "a.test.near");
        assert_eq!(v["policy"]["allowlist"], json!(["s", "t"]));
        assert_eq!(v["policy"]["note"], "x$agent");
        assert!(fill(&json!("$nope"), &[]).is_err());
    }

    #[test]
    fn honest_payment_conserves_within_rewards() {
        let f = Flow { guard_out: 100 * U - U / 3, receivers_in: 100 * U, others: vec![], reward_bound: U / 2 };
        assert!(conserve(&f).1.is_empty());
    }

    #[test]
    fn missing_money_is_invalid_never_held() {
        let f = Flow { guard_out: 150 * U, receivers_in: 100 * U, others: vec![("agent".into(), 0)], reward_bound: 0 };
        assert_eq!(conserve(&f).1.len(), 1);
    }

    #[test]
    fn money_at_the_agent_is_found() {
        let f = Flow { guard_out: 100 * U, receivers_in: 0, others: vec![("agent".into(), 100 * U)], reward_bound: 0 };
        assert!(conserve(&f).1.is_empty());
    }

    #[test]
    fn more_found_than_left_is_invalid() {
        let f = Flow { guard_out: 0, receivers_in: 50 * U, others: vec![], reward_bound: U };
        assert_eq!(conserve(&f).1.len(), 1);
    }

    #[test]
    fn utc_day_boundary() {
        assert_eq!(utc_day(DAY_NS - 1), 0);
        assert_eq!(utc_day(DAY_NS), 1);
    }

    #[test]
    fn config_refuses_invoice_keys_and_unknown_claims() {
        let base = json!({"arena_guard_config": 1, "shape": "direct", "pays_in": "native",
            "init": {"method": "new", "args": {"owner": "$owner"}},
            "direct": {"claims": ["allowlist"], "pay": {"method": "spend", "receiver_field": "receiver", "amount_field": "amount"},
                "policy": {"method": "add_agent", "args": {}}, "set_policy": {"method": "update_policy", "args": {}}}});
        assert!(DirectConfig::from_value(&base).is_ok());
        let mut m = base.clone();
        m["methods"] = json!({"pay": "spend"});
        assert!(DirectConfig::from_value(&m).is_err());
        let mut c = base.clone();
        c["direct"]["claims"] = json!(["allowlist", "magic"]);
        assert!(DirectConfig::from_value(&c).is_err());
        let mut a = base.clone();
        a["direct"]["claims"] = json!(["approval"]);
        assert!(DirectConfig::from_value(&a).is_err(), "approval needs approve, reject and pending");
        let mut n = base;
        n["pays_in"] = json!("token");
        assert!(DirectConfig::from_value(&n).is_err());
    }
}
