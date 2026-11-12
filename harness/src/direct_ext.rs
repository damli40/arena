//! Extended direct mode: config capabilities that let guards with other shapes run through the
//! same gate and attacks as `direct.rs` (docs/CHECK-YOUR-GUARD.md, "Extended direct mode").
//!
//! Everything here is declared in an optional `"ext"` block inside the config's `"direct"` block.
//! A config without it behaves exactly as before. Each field is closed (unknown keys refused) and
//! the gate must prove it by behaviour before any attack counts:
//!
//! - `pay_key`: the agent is a function-call key on the GUARD's own account, not a separate
//!   account. Arena generates the key. `"installed_by": "arena"` adds it with the guard account's
//!   own key, limited to the pay method; `"installed_by": "guard"` means an owner setup call
//!   installs it (the call gets the key through `$agent_public_key`). After setup Arena reads the
//!   key back from the chain and refuses to start unless it exists and may only call the guard.
//!   The agent's gas is then paid by the guard account, and conservation subtracts it.
//! - `setup`: more owner calls after `policy`, in order. `"each": "allowlist"` repeats a call once
//!   per allowlisted account (`$each` is that account). `"returns_as": "$name"` keeps what the
//!   call returned (for example a vault id) as a placeholder for later calls.
//! - `set_policy_calls`: the owner's change of policy as several calls (replaces `set_policy`).
//!   `"each"` may be `"allowlist"`, `"added"` (on the new list, not on setup's) or `"removed"`.
//! - `deposits`: exact yoctoNEAR to attach to the owner's calls, by role (`policy`, `set_policy`,
//!   `approve`, `reject`). Only setup calls may attach more than 1 yoctoNEAR.
//! - `window`: the window's real kind and length (`window_rolling`, `window_anchored`,
//!   `window_lifetime` claims). Validated by a time-travel gate sequence per kind.
//! - `pay_args`: the whole pay argument object as a template (`$receiver`, `$amount`, `$nonce`,
//!   `$expires_at_ms`, `$expires_at_ns`, `$signature`), for guards whose pay args are nested.
//! - `sign`: Arena generates a signer key (`$signer_public_key`, for the guard's init) and signs
//!   each payment over a declared message template. This tests the guard's on-chain checks of a
//!   signature, never the real off-chain service.
//! - `nonce`: `"counter"` (1, 2, 3, ... per sandbox) or `{"view": {method, args}}` (read the
//!   guard's current nonce before each payment).
//! - `pending_bare_id`: a held payment returns the bare id (a string or number), not an object.
//! - `approve_args` / `reject_args`: extra arguments for approve / reject (for example a vault id).
use anyhow::{bail, Context, Result};
use near_workspaces::types::SecretKey;
use serde_json::{json, Map, Value};

pub const WINDOW_CLAIMS: [&str; 3] = ["window_rolling", "window_anchored", "window_lifetime"];
const EXT_KEYS: [&str; 13] = [
    "pay_key", "policy_returns_as", "setup", "set_policy_calls", "deposits", "window", "pay_args", "sign", "nonce",
    "pending_bare_id", "approve_args", "reject_args", "notes",
];
/// The most a gate-time owner call may attach: 1 yoctoNEAR (the NEAR "confirm with a full key" idiom).
pub const MAX_GATE_DEPOSIT: u128 = 1;
/// The most a setup call may attach (storage or funding of a vault on the guard's own account).
pub const MAX_SETUP_DEPOSIT: u128 = 60 * 10u128.pow(24);

#[derive(Clone, Debug, PartialEq)]
pub enum KeyInstall {
    Arena,
    Guard,
}

#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub args: Value,
    pub deposit: u128,
    pub each: Option<String>,
    pub returns_as: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Sign {
    pub message: String,
    pub hash: String,
    pub consts: Map<String, Value>,
}

#[derive(Clone, Debug, Default)]
pub struct Ext {
    pub present: bool,
    pub pay_key: Option<KeyInstall>,
    pub setup: Vec<Call>,
    pub set_policy_calls: Vec<Call>,
    pub dep_policy: u128,
    pub dep_set_policy: u128,
    pub dep_approve: u128,
    pub dep_reject: u128,
    /// (claim, seconds); for a lifetime budget the seconds are the test horizon (how long Arena
    /// moves the clock to show the total does not restart; it proves nothing beyond that)
    pub window: Option<(String, u64)>,
    pub pay_args: Option<Value>,
    pub sign: Option<Sign>,
    /// None = no nonce; Some(None) = counter; Some(Some((method, args))) = read from a view
    pub nonce: Option<Option<(String, Value)>>,
    pub pending_bare_id: bool,
    pub approve_args: Map<String, Value>,
    pub reject_args: Map<String, Value>,
    /// keep what the `policy` call returned (for example a vault id) as this placeholder
    pub policy_returns_as: Option<String>,
}

fn closed(v: &Value, keys: &[&str], what: &str) -> Result<()> {
    for k in v.as_object().with_context(|| format!("{what} must be an object"))?.keys() {
        if !keys.contains(&k.as_str()) {
            bail!("{what}: unknown key {k:?} (allowed: {keys:?})");
        }
    }
    Ok(())
}

fn yocto(v: Option<&Value>, what: &str) -> Result<u128> {
    match v {
        None | Some(Value::Null) => Ok(0),
        Some(Value::String(s)) => s.parse::<u128>().with_context(|| format!("{what}: deposit must be a yoctoNEAR decimal string")),
        Some(_) => bail!("{what}: deposit must be a yoctoNEAR decimal string such as \"1\""),
    }
}

fn call(v: &Value, what: &str, eaches: &[&str], max_dep: u128) -> Result<Call> {
    closed(v, &["method", "args", "deposit", "each", "returns_as"], what)?;
    let c = Call {
        method: v.get("method").and_then(|x| x.as_str()).with_context(|| format!("{what}: needs a method"))?.to_string(),
        args: v.get("args").cloned().unwrap_or(json!({})),
        deposit: yocto(v.get("deposit"), what)?,
        each: v.get("each").and_then(|x| x.as_str()).map(|s| s.to_string()),
        returns_as: v.get("returns_as").and_then(|x| x.as_str()).map(|s| s.to_string()),
    };
    if let Some(e) = &c.each {
        if !eaches.contains(&e.as_str()) {
            bail!("{what}: each {e:?} is not allowed here (allowed: {eaches:?})");
        }
    }
    if let Some(r) = &c.returns_as {
        if !r.starts_with('$') || r.len() < 2 || !r[1..].chars().all(|x| x.is_ascii_lowercase() || x == '_') || RESERVED.contains(&r.as_str()) {
            bail!("{what}: returns_as must be a new placeholder such as \"$vault_id\", got {r:?}");
        }
    }
    if c.deposit > max_dep {
        bail!("{what}: deposit {} yoctoNEAR is above the {} allowed for this role", c.deposit, max_dep);
    }
    Ok(c)
}

/// Placeholders Arena fills itself; a setup call may not capture into one of them.
pub const RESERVED: [&str; 18] = [
    "$owner", "$agent", "$allowlist", "$per_payment", "$window_limit", "$approval_above", "$approval_above_next",
    "$agent_public_key", "$signer_public_key", "$each", "$receiver", "$amount", "$nonce", "$expires_at_ms",
    "$expires_at_ns", "$signature", "$policy_version", "$guard",
];

impl Ext {
    pub fn from_direct(d: &Value) -> Result<Ext> {
        let e = match d.get("ext") {
            None | Some(Value::Null) => return Ok(Ext::default()),
            Some(e) => e,
        };
        closed(e, &EXT_KEYS, "direct.ext")?;
        let mut x = Ext { present: true, ..Default::default() };
        if let Some(pk) = e.get("pay_key") {
            closed(pk, &["on", "installed_by"], "ext.pay_key")?;
            if pk.get("on").and_then(|v| v.as_str()) != Some("guard") {
                bail!("ext.pay_key.on must be \"guard\" (the agent is a key on the guard's own account)");
            }
            x.pay_key = Some(match pk.get("installed_by").and_then(|v| v.as_str()) {
                Some("arena") => KeyInstall::Arena,
                Some("guard") => KeyInstall::Guard,
                o => bail!("ext.pay_key.installed_by must be \"arena\" or \"guard\", got {o:?}"),
            });
        }
        for (i, c) in e.get("setup").and_then(|v| v.as_array()).cloned().unwrap_or_default().iter().enumerate() {
            x.setup.push(call(c, &format!("ext.setup[{i}]"), &["allowlist"], MAX_SETUP_DEPOSIT)?);
        }
        for (i, c) in e.get("set_policy_calls").and_then(|v| v.as_array()).cloned().unwrap_or_default().iter().enumerate() {
            let c = call(c, &format!("ext.set_policy_calls[{i}]"), &["allowlist", "added", "removed"], MAX_GATE_DEPOSIT)?;
            if c.returns_as.is_some() {
                bail!("ext.set_policy_calls[{i}]: returns_as is only for setup calls");
            }
            x.set_policy_calls.push(c);
        }
        if let Some(dp) = e.get("deposits") {
            closed(dp, &["policy", "set_policy", "approve", "reject"], "ext.deposits")?;
            x.dep_policy = yocto(dp.get("policy"), "ext.deposits.policy")?;
            x.dep_set_policy = yocto(dp.get("set_policy"), "ext.deposits.set_policy")?;
            x.dep_approve = yocto(dp.get("approve"), "ext.deposits.approve")?;
            x.dep_reject = yocto(dp.get("reject"), "ext.deposits.reject")?;
            if x.dep_policy > MAX_SETUP_DEPOSIT {
                bail!("ext.deposits.policy is above the setup limit");
            }
            for (n, v) in [("set_policy", x.dep_set_policy), ("approve", x.dep_approve), ("reject", x.dep_reject)] {
                if v > MAX_GATE_DEPOSIT {
                    bail!("ext.deposits.{n}: {v} yoctoNEAR; a gate-time owner call may attach at most {MAX_GATE_DEPOSIT}");
                }
            }
        }
        if let Some(w) = e.get("window") {
            closed(w, &["claim", "hours", "secs"], "ext.window")?;
            let claim = w.get("claim").and_then(|v| v.as_str()).context("ext.window needs a claim")?.to_string();
            if !WINDOW_CLAIMS.contains(&claim.as_str()) {
                bail!("ext.window.claim must be one of {WINDOW_CLAIMS:?} (window_utc_day needs no ext.window)");
            }
            let secs = match (w.get("hours").and_then(|v| v.as_u64()), w.get("secs").and_then(|v| v.as_u64())) {
                (Some(h), None) => h * 3600,
                (None, Some(s)) => s,
                _ => bail!("ext.window needs exactly one of hours or secs (for window_lifetime: how long Arena waits to show it never restarts)"),
            };
            if !(300..=7 * 86_400).contains(&secs) {
                bail!("ext.window: {secs} s is outside what Arena can test (5 minutes to 7 days)");
            }
            x.window = Some((claim, secs));
        }
        x.pay_args = e.get("pay_args").cloned();
        if let Some(pa) = &x.pay_args {
            let t = pa.to_string();
            if !t.contains("\"$receiver\"") && !t.contains("$receiver\"]") || !t.contains("\"$amount\"") {
                bail!("ext.pay_args must use both $receiver and $amount");
            }
        }
        if let Some(s) = e.get("sign") {
            closed(s, &["message", "hash", "consts"], "ext.sign")?;
            let message = s.get("message").and_then(|v| v.as_str()).context("ext.sign needs a message template")?.to_string();
            let hash = s.get("hash").and_then(|v| v.as_str()).unwrap_or("none").to_string();
            if !["none", "sha256"].contains(&hash.as_str()) {
                bail!("ext.sign.hash must be none or sha256");
            }
            let consts = s.get("consts").and_then(|v| v.as_object()).cloned().unwrap_or_default();
            for k in consts.keys() {
                if MSG_VARS.contains(&k.as_str()) {
                    bail!("ext.sign.consts: {k:?} is filled by Arena");
                }
            }
            for name in braces(&message) {
                if !MSG_VARS.contains(&name.as_str()) && !consts.contains_key(&name) {
                    bail!("ext.sign.message: unknown field {{{name}}} (Arena fills {MSG_VARS:?}; others go in consts)");
                }
            }
            if !message.contains("{receiver}") || !message.contains("{amount}") {
                bail!("ext.sign.message must bind {{receiver}} and {{amount}}");
            }
            x.sign = Some(Sign { message, hash, consts });
        }
        x.nonce = match e.get("nonce") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s == "counter" => Some(None),
            Some(v) if v.get("view").is_some() => {
                let vw = &v["view"];
                closed(vw, &["method", "args"], "ext.nonce.view")?;
                Some(Some((vw.get("method").and_then(|m| m.as_str()).context("ext.nonce.view.method")?.to_string(), vw.get("args").cloned().unwrap_or(json!({})))))
            }
            Some(o) => bail!("ext.nonce must be \"counter\" or {{\"view\": {{method, args}}}}, got {o}"),
        };
        if let Some(r) = e.get("policy_returns_as") {
            let probe = json!({"method": "policy", "returns_as": r});
            x.policy_returns_as = call(&probe, "ext.policy_returns_as", &[], 0)?.returns_as;
        }
        x.pending_bare_id = e.get("pending_bare_id").and_then(|v| v.as_bool()).unwrap_or(false);
        x.approve_args = e.get("approve_args").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        x.reject_args = e.get("reject_args").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        if x.sign.is_some() && x.nonce.is_none() {
            bail!("ext.sign needs ext.nonce (a signature without a nonce could be replayed)");
        }
        Ok(x)
    }

    /// Every method name the extension adds (for G0 and the name check).
    pub fn methods(&self) -> Vec<String> {
        let mut m: Vec<String> = self.setup.iter().chain(&self.set_policy_calls).map(|c| c.method.clone()).collect();
        if let Some(Some((v, _))) = &self.nonce {
            m.push(v.clone());
        }
        m
    }

    pub fn window_claim(&self) -> Option<&str> {
        self.window.as_ref().map(|(c, _)| c.as_str())
    }
}

/// Fields Arena fills in a signed message.
pub const MSG_VARS: [&str; 8] = ["guard", "agent", "receiver", "amount", "nonce", "expires_at_ms", "expires_at_ns", "policy_version"];

fn braces(t: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        let after = &rest[i + 1..];
        match after.find('}') {
            Some(j) => {
                out.push(after[..j].to_string());
                rest = &after[j + 1..];
            }
            None => break,
        }
    }
    out
}

/// The message Arena signs for one payment: the template with every {field} replaced.
pub fn message(s: &Sign, fields: &[(&str, String)]) -> Result<String> {
    let mut m = s.message.clone();
    for name in braces(&s.message) {
        let v = match fields.iter().find(|(k, _)| *k == name) {
            Some((_, v)) => v.clone(),
            None => match s.consts.get(&name) {
                Some(Value::String(x)) => x.clone(),
                Some(o) => o.to_string(),
                None => bail!("signed message field {{{name}}} has no value"),
            },
        };
        m = m.replacen(&format!("{{{name}}}"), &v, 1);
    }
    Ok(m)
}

/// Sign `msg` (optionally sha256 first) with an ed25519 key; returns the 64-byte signature, base64.
pub fn sign_b64(sk: &SecretKey, msg: &[u8], hash: &str) -> Result<String> {
    use base64::Engine;
    let k: near_crypto::SecretKey = sk.to_string().parse().map_err(|e| anyhow::anyhow!("signer key: {e:?}"))?;
    let bytes: Vec<u8> = if hash == "sha256" {
        use sha2::Digest;
        sha2::Sha256::digest(msg).to_vec()
    } else {
        msg.to_vec()
    };
    match k.sign(&bytes) {
        near_crypto::Signature::ED25519(sig) => Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())),
        _ => bail!("signer key is not ed25519"),
    }
}

/// Template operators on top of `direct::fill`: `{"$concat": [..]}` joins strings and
/// `{"$prefix_each": "$allowlist", "prefix": "near:"}` prefixes each entry of a list.
pub fn expand(t: &Value, vars: &[(&str, Value)]) -> Result<Value> {
    Ok(match t {
        Value::Object(o) if o.len() == 1 && o.contains_key("$concat") => {
            let parts = o["$concat"].as_array().context("$concat takes a list")?;
            let mut s = String::new();
            for p in parts {
                match expand(p, vars)? {
                    Value::String(x) => s.push_str(&x),
                    Value::Number(n) => s.push_str(&n.to_string()),
                    other => bail!("$concat: {other} is not a string or number"),
                }
            }
            Value::String(s)
        }
        Value::Object(o) if o.contains_key("$prefix_each") => {
            let list = expand(&o["$prefix_each"], vars)?;
            let pre = o.get("prefix").and_then(|v| v.as_str()).context("$prefix_each needs a prefix")?;
            Value::Array(list.as_array().context("$prefix_each takes a list placeholder")?.iter()
                .map(|x| x.as_str().map(|s| json!(format!("{pre}{s}"))).context("$prefix_each entries are strings"))
                .collect::<Result<_>>()?)
        }
        Value::Object(o) => {
            let mut m = Map::new();
            for (k, v) in o {
                m.insert(k.clone(), expand(v, vars)?);
            }
            Value::Object(m)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| expand(x, vars)).collect::<Result<_>>()?),
        other => crate::direct::fill(other, vars)?,
    })
}

/// Which accounts a repeated set-policy call runs for.
pub fn each_list(each: &str, new: &[String], setup: &[String]) -> Vec<String> {
    match each {
        "added" => new.iter().filter(|a| !setup.contains(a)).cloned().collect(),
        "removed" => setup.iter().filter(|a| !new.contains(a)).cloned().collect(),
        _ => new.to_vec(),
    }
}

/// Seconds to advance for one `advance` step: {"windows": f, "plus_secs": n} or
/// {"to_next_utc_midnight": true, "plus_secs": n}. `win_secs` is the declared window (the test horizon for
/// a lifetime budget, which has no window).
pub fn advance_secs(a: &Value, now_ns: u64, win_secs: u64) -> Result<u64> {
    closed(a, &["windows", "plus_secs", "to_next_utc_midnight"], "advance")?;
    let plus = a.get("plus_secs").and_then(|v| v.as_i64()).unwrap_or(0);
    let base: i64 = if a.get("to_next_utc_midnight").and_then(|v| v.as_bool()) == Some(true) {
        let day = 86_400_000_000_000u64;
        (((now_ns / day + 1) * day - now_ns) / 1_000_000_000) as i64
    } else {
        let f = a.get("windows").and_then(|v| v.as_f64()).context("advance needs windows or to_next_utc_midnight")?;
        (f * win_secs as f64) as i64
    };
    let s = base + plus;
    if s <= 0 {
        bail!("advance of {s} s is not forward");
    }
    Ok(s as u64)
}

/// Per-sandbox state of the extended mode.
#[derive(Debug, Default)]
pub struct State {
    pub nonce_counter: u64,
    pub view_nonce: Option<Value>,
    pub now_ns: u64,
    /// placeholders captured from setup calls (`returns_as`)
    pub captures: Vec<(&'static str, Value)>,
    /// how many set-policy changes succeeded (for guards whose policy object needs a fresh id)
    pub policy_version: u64,
    pub advanced_secs: u64,
}

impl State {
    pub fn captures_from(&mut self, _x: &Ext, name: Option<&str>, r: &near_workspaces::result::ExecutionFinalResult) {
        if let Some(n) = name {
            let v: Value = r.clone().json().unwrap_or(Value::Null);
            let n: &'static str = Box::leak(n.to_string().into_boxed_str());
            self.captures.retain(|(k, _)| *k != n);
            self.captures.push((n, v));
        }
    }
}

/// The placeholders the extended mode adds to every template.
pub fn vars(guard: &str, approval_yocto: u128, agent_pk: Option<&str>, signer: Option<&SecretKey>, st: &State) -> Vec<(&'static str, Value)> {
    let mut v = vec![
        ("$guard", json!(guard)),
        // a guard that holds "at or above" X behaves as "strictly above" X when given X + 1 yocto
        ("$approval_above_next", json!((approval_yocto + 1).to_string())),
        ("$policy_version", json!(st.policy_version)),
    ];
    if let Some(pk) = agent_pk {
        v.push(("$agent_public_key", json!(pk)));
    }
    if let Some(sk) = signer {
        v.push(("$signer_public_key", json!(sk.public_key().to_string())));
    }
    v.extend(st.captures.iter().cloned());
    v
}

/// The pay call's arguments for an ext config: nonce, expiry and signature filled in.
pub fn pay_args(cfg: &crate::direct::DirectConfig, base: &[(&'static str, Value)], receiver: &str, amount_yocto: u128, signer: Option<&SecretKey>, st: &mut State) -> Result<Value> {
    let x = &cfg.ext;
    let mut vars: Vec<(&str, Value)> = base.to_vec();
    let nonce = match &x.nonce {
        Some(None) => {
            st.nonce_counter += 1;
            Some(json!(st.nonce_counter.to_string()))
        }
        Some(Some(_)) => Some(st.view_nonce.clone().context("the guard's nonce view returned nothing")?),
        None => None,
    };
    let exp_ns = st.now_ns + 3_600_000_000_000;
    vars.push(("$receiver", json!(receiver)));
    vars.push(("$amount", json!(amount_yocto.to_string())));
    vars.push(("$expires_at_ns", json!(exp_ns.to_string())));
    vars.push(("$expires_at_ms", json!((exp_ns / 1_000_000).to_string())));
    if let Some(n) = &nonce {
        vars.push(("$nonce", n.clone()));
    }
    if let Some(sg) = &x.sign {
        let plain = |v: &Value| match v {
            Value::String(s) => s.clone(),
            o => o.to_string(),
        };
        let fields = [
            ("guard", plain(&base.iter().find(|(k, _)| *k == "$guard").map(|(_, v)| v.clone()).unwrap_or_default())),
            ("agent", plain(&base.iter().find(|(k, _)| *k == "$agent").map(|(_, v)| v.clone()).unwrap_or_default())),
            ("receiver", receiver.to_string()),
            ("amount", amount_yocto.to_string()),
            ("nonce", nonce.as_ref().map(plain).unwrap_or_default()),
            ("expires_at_ms", (exp_ns / 1_000_000).to_string()),
            ("expires_at_ns", exp_ns.to_string()),
            ("policy_version", st.policy_version.to_string()),
        ];
        let msg = message(sg, &fields)?;
        let sk = signer.context("ext.sign: no signer key")?;
        vars.push(("$signature", json!(sign_b64(sk, msg.as_bytes(), &sg.hash)?)));
    }
    match &x.pay_args {
        Some(t) => expand(t, &vars),
        None => {
            let mut a = match expand(&Value::Object(cfg.extra_args.clone()), &vars)? {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            a.insert(cfg.receiver_field.clone(), json!(receiver));
            a.insert(cfg.amount_field.clone(), json!(amount_yocto.to_string()));
            Ok(Value::Object(a))
        }
    }
}

/// Before every step: read the block time (for expiries) and, if declared, the guard's nonce.
pub async fn before_step(w: &near_workspaces::Worker<near_workspaces::network::Sandbox>, guard: &near_workspaces::AccountId, cfg: &crate::direct::DirectConfig, st: &mut State) -> Result<()> {
    st.now_ns = w.view_block().await?.timestamp();
    if let Some(Some((m, a))) = &cfg.ext.nonce {
        let vars: Vec<(&str, Value)> = st.captures.iter().map(|(k, v)| (*k, v.clone())).collect();
        let args = expand(a, &vars)?;
        let r = w.view(guard, m).args_json(args).await.with_context(|| format!("nonce view {m} failed"))?;
        st.view_nonce = Some(r.json::<Value>()?);
    }
    Ok(())
}

/// The sandbox for one sequence. A sequence that moves the clock (an `advance` step) gets a sandbox
/// whose `max_block_production_delay` is longer, because fast-forward moves the clock by
/// (min + max block-production delay) / 2 per skipped block: about 0.31 s with the defaults
/// (0.12 s and 0.5 s), so a 24 h window would need about 300,000 skipped blocks. With the max set
/// to `ARENA_FF_MAX_DELAY_SECS` (default 20 s) a skipped block moves about 10 s. Every other
/// sequence keeps near-workspaces' own sandbox. Same sandbox binary either way (no new download).
pub async fn sandbox(advances: bool) -> Result<(near_workspaces::Worker<near_workspaces::network::Sandbox>, Option<near_sandbox::Sandbox>)> {
    if !advances {
        return Ok((near_workspaces::sandbox().await?, None));
    }
    let max_s: f64 = std::env::var("ARENA_FF_MAX_DELAY_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(20.0);
    if !(0.5..=120.0).contains(&max_s) {
        bail!("ARENA_FF_MAX_DELAY_SECS must be between 0.5 and 120 (got {max_s})");
    }
    let (secs, nanos) = (max_s.trunc() as u64, ((max_s.fract()) * 1e9) as u64);
    let cfg = near_sandbox::SandboxConfig {
        additional_accounts: vec![near_sandbox::GenesisAccount::default_with_name("registrar".parse()?)],
        additional_config: Some(json!({"consensus": {"max_block_production_delay": {"secs": secs, "nanos": nanos}}})),
        ..Default::default()
    };
    let sb = near_sandbox::Sandbox::start_sandbox_with_config_and_version(cfg, near_sandbox::DEFAULT_NEAR_SANDBOX_VERSION)
        .await
        .map_err(|e| anyhow::anyhow!("could not start the window-proof sandbox: {e}"))?;
    let w = near_workspaces::sandbox()
        .rpc_addr(&sb.rpc_addr)
        .validator_key(near_workspaces::network::ValidatorKey::HomeDir(sb.home_dir.path().to_path_buf()))
        .await?;
    Ok((w, Some(sb)))
}

/// Move the sandbox clock forward by at least `secs` with fast-forward, in chunks, and return
/// (seconds the clock really moved, blocks skipped). Skipped blocks do not exist: no code runs
/// in them, so this only tests windows the guard computes from the block time on its next call.
pub async fn advance(w: &near_workspaces::Worker<near_workspaces::network::Sandbox>, secs: u64) -> Result<(u64, u64)> {
    let t0 = w.view_block().await?.timestamp();
    let target = t0 + secs * 1_000_000_000;
    // The clock gained per skipped block varies (0.3 to 0.5 s measured). Approach the target from
    // below: assume the fastest rate seen so far (start at 1 s per block) and cover at most 80% of
    // what is left per round, so the last rounds are a few blocks and the overshoot stays small.
    // At most 500 blocks per fast-forward call: measured, one call of about 2,000 blocks took
    // 24 s but one of about 2,900 took 360 s, so many small calls are much faster than one big one.
    // The first round skips 1 block to measure the rate (it depends on the sandbox's block
    // production delays, see `sandbox`), so the first real jump does not overshoot.
    let mut fastest_ns: f64 = 0.0;
    let mut skipped = 0u64;
    for _ in 0..400 {
        let b0 = w.view_block().await?;
        let now = b0.timestamp();
        if now >= target {
            return Ok(((now - t0) / 1_000_000_000, skipped));
        }
        let n = if fastest_ns <= 0.0 { 1 } else { ((0.8 * (target - now) as f64 / fastest_ns).floor() as u64).clamp(1, 500) };
        w.fast_forward(n).await?;
        let b = w.view_block().await?;
        skipped += b.height().saturating_sub(b0.height());
        if b.timestamp() > now {
            fastest_ns = fastest_ns.max((b.timestamp() - now) as f64 / n as f64);
        }
        if std::env::var_os("ARENA_FF_DEBUG").is_some() {
            eprintln!("ff-debug n={n} blocks={} clock_gain_s={} at={:?}", b.height().saturating_sub(b0.height()), (b.timestamp().saturating_sub(now)) / 1_000_000_000, std::time::SystemTime::now());
        }
    }
    bail!("advance: the clock did not reach +{secs} s after 400 fast-forward rounds")
}

/// One `advance` step of a sequence.
pub async fn advance_step(w: &near_workspaces::Worker<near_workspaces::network::Sandbox>, cfg: &crate::direct::DirectConfig, a: &Value, i: usize, st: &mut State) -> Result<Value> {
    let now = w.view_block().await?.timestamp();
    let win = match &cfg.ext.window {
        Some((_, s)) => *s,
        None => 86_400,
    };
    let secs = advance_secs(a, now, win)?;
    let (moved, skipped) = advance(w, secs).await?;
    st.advanced_secs += moved;
    let e = json!({"step": i, "kind": "advance", "asked_secs": secs, "clock_moved_secs": moved, "blocks_skipped": skipped,
        "note": "fast-forward: the skipped blocks do not exist and no code ran in them"});
    println!("  step {i} {e}");
    Ok(e)
}

/// The extra owner setup calls, in order. Ok(Ok(record)) when all succeeded, Ok(Err(why)) when one
/// failed (setup error: nothing is scored).
pub async fn setup_calls<'a, V, F>(owner: &near_workspaces::Account, guard: &near_workspaces::AccountId, x: &Ext, allow_ids: &[String], vars: V, fill: F, st: &std::sync::Mutex<State>) -> Result<std::result::Result<Value, String>>
where
    V: Fn(Vec<(&'static str, Value)>) -> Result<Vec<(&'static str, Value)>>,
    F: Fn(&Value, &[(&str, Value)]) -> Result<Value>,
{
    let mut done = Vec::new();
    for (ci, c) in x.setup.iter().enumerate() {
        let each: Vec<Option<String>> = if c.each.is_some() { allow_ids.iter().cloned().map(Some).collect() } else { vec![None] };
        for a in each {
            let extra = a.as_ref().map(|a| vec![("$each", json!(a))]).unwrap_or_default();
            let args = fill(&c.args, &vars(extra)?)?;
            let r = owner
                .call(guard, &c.method)
                .args_json(args.clone())
                .gas(near_workspaces::types::Gas::from_tgas(150))
                .deposit(near_workspaces::types::NearToken::from_yoctonear(c.deposit))
                .transact()
                .await?;
            if !r.is_success() {
                let t = format!("{:?}", r.clone().into_result().err());
                let from = t.find("Smart contract panicked").or_else(|| t.find("ExecutionError")).unwrap_or(0);
                return Ok(Err(format!("setup call {ci} `{}`({args}) failed: {}", c.method, t[from..].chars().take(300).collect::<String>())));
            }
            st.lock().unwrap().captures_from(x, c.returns_as.as_deref(), &r);
            println!("DIRECT setup (ext): owner {}({args}) deposit {}", c.method, c.deposit);
            done.push(json!({"method": c.method, "args": args, "deposit_yocto": c.deposit.to_string(), "returned": r.clone().json::<Value>().unwrap_or(Value::Null)}));
        }
    }
    Ok(Ok(Value::Array(done)))
}

/// After setup: the agent's key must be on the guard account, as a function-call key whose
/// receiver is the guard. Returns Ok(Err(why)) to stop the attempt as a setup error.
pub async fn check_pay_key(w: &near_workspaces::Worker<near_workspaces::network::Sandbox>, guard: &near_workspaces::AccountId, pk: &near_workspaces::types::PublicKey, pay: &str) -> Result<std::result::Result<Value, String>> {
    use near_workspaces::types::AccessKeyPermission;
    let k = match w.view_access_key(guard, pk).await {
        Ok(k) => k,
        Err(_) => return Ok(Err("the agent's pay key is not on the guard account after setup (the mapping said the guard's setup installs it)".into())),
    };
    match k.permission {
        AccessKeyPermission::FullAccess => Ok(Err("the agent's key on the guard account has FULL access: the agent could do anything as the guard, so Arena will not test through it".into())),
        AccessKeyPermission::FunctionCall(p) => {
            if p.receiver_id != guard.as_str() {
                return Ok(Err(format!("the agent's key on the guard account may call {}, not the guard", p.receiver_id)));
            }
            if !p.method_names.is_empty() && !p.method_names.iter().any(|m| m == pay) {
                return Ok(Err(format!("the agent's key on the guard account may not call the pay method {pay} (it may call {:?})", p.method_names)));
            }
            Ok(Ok(json!({"permission": "function call", "receiver": p.receiver_id, "methods": p.method_names,
                "any_method": p.method_names.is_empty()})))
        }
    }
}

/// Is an attempt with no clock moves inside one window of the declared kind? `None` = valid.
pub fn window_validity(cfg: &crate::direct::DirectConfig, ts0: u64, ts1: u64, advanced: u64) -> Option<String> {
    if advanced > 0 {
        return None;
    }
    match &cfg.ext.window {
        Some((c, _)) if c == "window_lifetime" => None,
        Some((c, secs)) => {
            // Setup sits just before ts0 and an anchored period starts there; allow it 120 s.
            let el = (ts1.saturating_sub(ts0)) / 1_000_000_000;
            (el + 120 >= *secs).then(|| format!("the attempt took {el} s, too close to the {c} length of {secs} s to be sure it sat inside one window"))
        }
        None => (crate::direct::utc_day(ts0) != crate::direct::utc_day(ts1)).then(|| {
            format!("the UTC day changed during the attempt (block time {ts0} -> {ts1}); a per-day limit restarts at 00:00 UTC, so Arena cannot judge it")
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(ext: Value) -> Value {
        json!({"ext": ext})
    }

    #[test]
    fn no_ext_is_default() {
        let x = Ext::from_direct(&json!({})).unwrap();
        assert!(!x.present && x.pay_key.is_none() && x.setup.is_empty());
    }

    #[test]
    fn refuses_unknown_and_unsafe_fields() {
        assert!(Ext::from_direct(&d(json!({"magic": 1}))).is_err());
        assert!(Ext::from_direct(&d(json!({"pay_key": {"on": "agent"}}))).is_err());
        assert!(Ext::from_direct(&d(json!({"pay_key": {"on": "guard", "installed_by": "owner"}}))).is_err());
        assert!(Ext::from_direct(&d(json!({"setup": [{"method": "add", "each": "removed"}]}))).is_err(), "removed only in set_policy_calls");
        assert!(Ext::from_direct(&d(json!({"setup": [{"method": "add", "returns_as": "$owner"}]}))).is_err());
        assert!(Ext::from_direct(&d(json!({"deposits": {"approve": "2"}}))).is_err(), "gate calls attach at most 1 yocto");
        assert!(Ext::from_direct(&d(json!({"set_policy_calls": [{"method": "x", "deposit": "1000"}]}))).is_err());
        assert!(Ext::from_direct(&d(json!({"window": {"claim": "window_utc_day"}}))).is_err());
        assert!(Ext::from_direct(&d(json!({"window": {"claim": "window_rolling"}}))).is_err(), "rolling needs a length");
        assert!(Ext::from_direct(&d(json!({"window": {"claim": "window_lifetime", "secs": 900}}))).is_ok());
        assert!(Ext::from_direct(&d(json!({"window": {"claim": "window_rolling", "secs": 5}}))).is_err());
        assert!(Ext::from_direct(&d(json!({"sign": {"message": "{receiver}|{amount}"}}))).is_err(), "sign needs a nonce");
        assert!(Ext::from_direct(&d(json!({"sign": {"message": "{receiver}|{amount}|{secret}"}, "nonce": "counter"}))).is_err());
        assert!(Ext::from_direct(&d(json!({"sign": {"message": "{receiver}"}, "nonce": "counter"}))).is_err(), "must bind amount");
        assert!(Ext::from_direct(&d(json!({"pay_args": {"to": "$receiver"}}))).is_err(), "must use $amount");
    }

    #[test]
    fn accepts_a_full_ext() {
        let x = Ext::from_direct(&d(json!({
            "pay_key": {"on": "guard", "installed_by": "guard"},
            "setup": [{"method": "add_payee", "args": {"account": "$each"}, "each": "allowlist", "deposit": "1"}],
            "set_policy_calls": [{"method": "remove_payee", "args": {"account": "$each"}, "each": "removed"}],
            "deposits": {"policy": "1", "approve": "1"},
            "window": {"claim": "window_rolling", "hours": 24},
            "sign": {"message": "p:v1|{guard}|{receiver}|{amount}|{nonce}|{m}", "consts": {"m": "x"}},
            "nonce": "counter"}))).unwrap();
        assert_eq!(x.pay_key, Some(KeyInstall::Guard));
        assert_eq!(x.window, Some(("window_rolling".into(), 86_400)));
        assert_eq!(x.methods(), vec!["add_payee", "remove_payee"]);
    }

    #[test]
    fn message_fills_fields_and_consts() {
        let s = Sign { message: "a:v1|{guard}|{receiver}|{amount}|{nonce}|{m}".into(), hash: "none".into(), consts: json!({"m": "z"}).as_object().unwrap().clone() };
        let m = message(&s, &[("guard", "g".into()), ("receiver", "r".into()), ("amount", "5".into()), ("nonce", "1".into())]).unwrap();
        assert_eq!(m, "a:v1|g|r|5|1|z");
    }

    #[test]
    fn expand_concat_and_prefix() {
        let vars = [("$receiver", json!("sam.near")), ("$allowlist", json!(["a", "b"])), ("$policy_version", json!(2))];
        assert_eq!(expand(&json!({"$concat": ["near:", "$receiver"]}), &vars).unwrap(), json!("near:sam.near"));
        assert_eq!(expand(&json!({"$concat": ["m-", "$policy_version"]}), &vars).unwrap(), json!("m-2"));
        assert_eq!(expand(&json!({"l": {"$prefix_each": "$allowlist", "prefix": "near:"}}), &vars).unwrap(), json!({"l": ["near:a", "near:b"]}));
    }

    #[test]
    fn each_lists() {
        let setup: Vec<String> = ["sam", "ada", "mo"].iter().map(|s| s.to_string()).collect();
        let new: Vec<String> = ["ada", "mo", "lin"].iter().map(|s| s.to_string()).collect();
        assert_eq!(each_list("removed", &new, &setup), vec!["sam"]);
        assert_eq!(each_list("added", &new, &setup), vec!["lin"]);
        assert_eq!(each_list("allowlist", &new, &setup), new);
    }

    #[test]
    fn advance_math() {
        let day = 86_400_000_000_000u64;
        assert_eq!(advance_secs(&json!({"to_next_utc_midnight": true, "plus_secs": 600}), day * 5 + 3_600_000_000_000, 0).unwrap(), 82_800 + 600);
        assert_eq!(advance_secs(&json!({"windows": 0.5}), 0, 86_400).unwrap(), 43_200);
        assert!(advance_secs(&json!({"windows": 0.5, "plus_secs": -50000}), 0, 86_400).is_err());
    }

    #[test]
    fn signature_verifies() {
        use near_workspaces::types::KeyType;
        let sk = SecretKey::from_random(KeyType::ED25519);
        let b = sign_b64(&sk, b"hello", "none").unwrap();
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD.decode(b).unwrap();
        assert_eq!(raw.len(), 64);
        let k: near_crypto::SecretKey = sk.to_string().parse().unwrap();
        let sig = near_crypto::Signature::from_parts(near_crypto::KeyType::ED25519, &raw).unwrap();
        assert!(sig.verify(b"hello", &k.public_key()));
    }
}
