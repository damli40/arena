//! The fixed "wrapper" for guards whose method names or argument shapes differ from
//! targets/vault-a/INTERFACE.md (`arena check`, 2026-11-11).
//!
//! It is NOT a contract. It is this hand-written translation layer: when the harness sends a
//! call to the guard, it swaps the interface's method name for the guard's own name and renames
//! a few argument fields. Every call still goes straight from the agent's (or owner's) own key
//! to the guard, so the guard sees the real caller and no extra hop changes the race timing.
//!
//! What may be filled in comes from ONE data file (`--guard-config <file.json>`), written by
//! `tools/check/check.py` and checked again here:
//! - method names: `^[a-z_][a-z0-9_]{0,63}$`, one guard method per role at most;
//! - every other field: one value from a closed list (see `CHOICES`);
//! - init args: a placeholder from a closed list (`$owner`, `$agent`, `$token`, `$daily_cap`,
//!   `$daily_cap_number`) or a short literal (string <= 64 chars, number, bool).
//! Nothing in the file is compiled or executed. Unknown keys are refused.
//!
//! Without `--guard-config` none of this runs, and the harness behaves exactly as before.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Roles a guard method can play (the interface's own names).
pub const ROLES: [&str; 11] = [
    "pay",
    "approve_invoice",
    "add_payee",
    "remove_payee",
    "cancel_invoice",
    "set_daily_cap",
    "set_agent",
    "get_invoice",
    "get_config",
    "is_payee",
    "paid_today",
];

/// Owner methods whose attached deposit can be chosen (0 or 1 yoctoNEAR).
pub const DEPOSIT_ROLES: [&str; 5] = ["approve_invoice", "add_payee", "remove_payee", "cancel_invoice", "set_daily_cap"];

/// Closed lists for the argument-shape choices. The first value is the interface's own.
pub const CHOICES: [(&str, &[&str]); 9] = [
    ("invoice_id_field", &["id", "invoice_id"]),
    ("receiver_field", &["receiver", "receiver_id", "account_id"]),
    ("payee_field", &["account", "account_id", "payee"]),
    ("expiry_field", &["expires_at_ns", "expires_at", "expiry"]),
    ("expiry_unit", &["ns", "ms", "s"]),
    ("amount_encoding", &["u128_string", "number"]),
    ("daily_cap_field", &["daily_cap", "cap", "limit"]),
    ("status_field", &["status", "state"]),
    ("paid_value", &["Paid", "paid", "PAID"]),
];

pub const PLACEHOLDERS: [&str; 8] = ["$owner", "$agent", "$token", "$daily_cap", "$daily_cap_number", "$intents", "$bridge", "$foreign_destinations"];

/// `"intents": {"pays_by": ...}` (2026-11-11, withdraw.rs): "deposit" = the guard deposits into NEAR
/// Intents for the receiver (the default); "ft_withdraw" = the guard's money is a credit inside
/// Intents and it pays by withdrawing toward a foreign destination through a bridge account.
/// Mirrored in tools/check/guard_config.py (PAYS_BY).
pub const PAYS_BY: [&str; 2] = ["deposit", "ft_withdraw"];

/// `"pays_in": "intents"` (2026-11-11): how the guard pays into NEAR Intents. Closed lists only.
/// Mirrored in tools/check/guard_config.py (INTENTS_KEYS, BENEFICIARY_IN_MSG).
pub const BENEFICIARY_IN_MSG: [&str; 2] = ["account_id", "json_receiver_id"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentsCfg {
    /// which `msg` shape the guard writes on `ft_transfer_call` (declared, printed; scoring reads
    /// Intents' own ledger whatever the guard writes)
    pub beneficiary_in_msg: String,
    /// money credited to the guard's OWN account inside Intents is accepted as "parked" (not moved)
    /// only when this is true AND the guard has no key registered inside Intents. Default false:
    /// money parked there makes the attempt not finish.
    pub may_park_in_intents: bool,
    /// "deposit" or "ft_withdraw" (PAYS_BY)
    pub pays_by: String,
}

impl IntentsCfg {
    /// The guard pays by `ft_withdraw` toward another chain (withdraw.rs).
    pub fn withdraws(&self) -> bool {
        self.pays_by == "ft_withdraw"
    }
}

/// Rules the guard claims. A rule it does not claim is not scored, and the starting invoices
/// that need it are never created (they authorise nothing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Features {
    pub payees: bool,
    pub cancel: bool,
    pub expiry: bool,
    pub daily_cap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardConfig {
    pub file: String,
    pub init_method: String,
    /// placeholder or literal per init arg
    pub init_args: BTreeMap<String, Value>,
    pub features: Features,
    /// role -> the guard's method name
    pub methods: BTreeMap<String, String>,
    /// choice name -> chosen value
    pub shapes: BTreeMap<String, String>,
    /// owner role -> yoctoNEAR to attach (0 or 1)
    pub deposits: BTreeMap<String, u8>,
    /// `"pays_in": "native"` (2026-11-11): the guard pays receivers in plain NEAR, not NEP-141
    /// tokens. Amounts it is given are then yoctoNEAR (`setup::NATIVE_UNIT` per Arena unit), and
    /// it is scored from receivers' native balances (scorer.rs). Default false ("token").
    pub native: bool,
    /// `"pays_in": "intents"`: the guard pays by depositing test tokens into the NEAR Intents
    /// contract (setup deploys the pinned release wasm) crediting the receiver there. Scored from
    /// token balances PLUS each account's credit inside Intents (`mt_balance_of`). None otherwise.
    pub intents: Option<IntentsCfg>,
}

/// The values `pays_in` may take. Mirrored in tools/check/guard_config.py (PAYS_IN).
pub const PAYS_IN: [&str; 3] = ["token", "native", "intents"];

fn method_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn obj<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    v.as_object().with_context(|| format!("{what} must be a JSON object"))
}

fn no_unknown(m: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<()> {
    for k in m.keys() {
        if !allowed.contains(&k.as_str()) {
            bail!("{what}: unknown key {k:?} (allowed: {allowed:?})");
        }
    }
    Ok(())
}

impl GuardConfig {
    /// The interface's own shape (INTERFACE.md): identity names, its deposits, all four rules.
    pub fn vault_a_default(file: &str) -> Self {
        let methods = ROLES.iter().map(|r| (r.to_string(), r.to_string())).collect();
        let shapes = CHOICES.iter().map(|(k, v)| (k.to_string(), v[0].to_string())).collect();
        let deposits = [("approve_invoice", 1u8), ("add_payee", 1), ("remove_payee", 0), ("cancel_invoice", 0), ("set_daily_cap", 1)]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        let init_args = [("owner", "$owner"), ("agent", "$agent"), ("token", "$token"), ("daily_cap", "$daily_cap")]
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();
        GuardConfig {
            file: file.to_string(),
            init_method: "new".to_string(),
            init_args,
            features: Features { payees: true, cancel: true, expiry: true, daily_cap: true },
            methods,
            shapes,
            deposits,
            native: false,
            intents: None,
        }
    }

    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("--guard-config {path}: cannot read"))?;
        if text.len() > 64 * 1024 {
            bail!("--guard-config {path}: larger than 64 KiB");
        }
        let v: Value = serde_json::from_str(&text).with_context(|| format!("--guard-config {path}: not JSON"))?;
        Self::from_value(path, &v)
    }

    /// Parse and check. Every missing field keeps the interface's default.
    pub fn from_value(file: &str, v: &Value) -> Result<Self> {
        let mut c = Self::vault_a_default(file);
        let top = obj(v, "guard config")?;
        no_unknown(top, &["arena_guard_config", "pays_in", "intents", "init", "features", "methods", "shapes", "deposits"], "guard config")?;
        if top.get("arena_guard_config") != Some(&json!(1)) {
            bail!("guard config: \"arena_guard_config\": 1 is required");
        }
        c.native = match top.get("pays_in") {
            None => false,
            Some(Value::String(s)) if PAYS_IN.contains(&s.as_str()) => s == "native",
            Some(other) => bail!("pays_in: {other} is not allowed; use \"token\", \"native\" or \"intents\""),
        };
        let pays_intents = top.get("pays_in").and_then(|v| v.as_str()) == Some("intents");
        match top.get("intents") {
            Some(_) if !pays_intents => bail!("intents: this block is only allowed with \"pays_in\": \"intents\""),
            Some(b) => {
                let b = obj(b, "intents")?;
                no_unknown(b, &["beneficiary_in_msg", "may_park_in_intents", "pays_by"], "intents")?;
                let pays_by = match b.get("pays_by") {
                    None => "deposit".to_string(),
                    Some(Value::String(s)) if PAYS_BY.contains(&s.as_str()) => s.clone(),
                    Some(other) => bail!("intents.pays_by: {other} is not one of {PAYS_BY:?}"),
                };
                if pays_by == "ft_withdraw" && (b.contains_key("beneficiary_in_msg") || b.contains_key("may_park_in_intents")) {
                    bail!("intents: beneficiary_in_msg and may_park_in_intents describe deposits; a guard with \"pays_by\": \"ft_withdraw\" takes neither");
                }
                let ben = match b.get("beneficiary_in_msg") {
                    None => "account_id".to_string(),
                    Some(Value::String(s)) if BENEFICIARY_IN_MSG.contains(&s.as_str()) => s.clone(),
                    Some(other) => bail!("intents.beneficiary_in_msg: {other} is not one of {BENEFICIARY_IN_MSG:?}"),
                };
                let park = match b.get("may_park_in_intents") {
                    None => false,
                    Some(Value::Bool(x)) => *x,
                    Some(_) => bail!("intents.may_park_in_intents must be true or false"),
                };
                c.intents = Some(IntentsCfg { beneficiary_in_msg: ben, may_park_in_intents: park, pays_by });
            }
            None if pays_intents => {
                c.intents = Some(IntentsCfg { beneficiary_in_msg: "account_id".to_string(), may_park_in_intents: false, pays_by: "deposit".to_string() })
            }
            None => {}
        }
        if let Some(init) = top.get("init") {
            let init = obj(init, "init")?;
            no_unknown(init, &["method", "args"], "init")?;
            if let Some(m) = init.get("method") {
                let m = m.as_str().context("init.method must be a string")?;
                if !method_name_ok(m) {
                    bail!("init.method {m:?} is not a valid method name");
                }
                c.init_method = m.to_string();
            }
            if let Some(a) = init.get("args") {
                let a = obj(a, "init.args")?;
                if a.len() > 16 {
                    bail!("init.args: at most 16 arguments");
                }
                let mut out = BTreeMap::new();
                for (k, val) in a {
                    if !method_name_ok(k) {
                        bail!("init.args: argument name {k:?} must match ^[a-z_][a-z0-9_]{{0,63}}$");
                    }
                    match val {
                        Value::String(s) if s.starts_with('$') => {
                            if !PLACEHOLDERS.contains(&s.as_str()) {
                                bail!("init.args.{k}: unknown placeholder {s:?} (allowed: {PLACEHOLDERS:?})");
                            }
                        }
                        Value::String(s) if s.len() <= 64 => {}
                        Value::String(_) => bail!("init.args.{k}: literal strings are at most 64 characters"),
                        Value::Number(_) | Value::Bool(_) => {}
                        _ => bail!("init.args.{k}: must be a placeholder, a short string, a number or a bool"),
                    }
                    out.insert(k.clone(), val.clone());
                }
                c.init_args = out;
            }
        }
        if let Some(f) = top.get("features") {
            let f = obj(f, "features")?;
            no_unknown(f, &["payees", "cancel", "expiry", "daily_cap"], "features")?;
            let get = |k: &str, d: bool| -> Result<bool> {
                match f.get(k) {
                    None => Ok(d),
                    Some(Value::Bool(b)) => Ok(*b),
                    Some(_) => bail!("features.{k} must be true or false"),
                }
            };
            c.features = Features {
                payees: get("payees", true)?,
                cancel: get("cancel", true)?,
                expiry: get("expiry", true)?,
                daily_cap: get("daily_cap", true)?,
            };
        }
        // A guard that claims the daily cap is scored against Arena's cap (500). Its init must
        // take that cap from Arena (`$daily_cap` / `$daily_cap_number`); a literal cap in the
        // config would be scored against 500 while the guard enforces something else.
        if c.features.daily_cap
            && !c.init_args.values().any(|v| matches!(v.as_str(), Some("$daily_cap") | Some("$daily_cap_number")))
        {
            bail!("init.args: the guard claims the daily cap, so its init must take Arena's cap through \"$daily_cap\" or \"$daily_cap_number\"");
        }
        let uses_intents = c.init_args.values().any(|v| v.as_str() == Some("$intents"));
        if uses_intents && c.intents.is_none() {
            bail!("init.args: \"$intents\" is only filled in with \"pays_in\": \"intents\"");
        }
        if c.intents.is_some() && !uses_intents {
            bail!("init.args: a guard that pays into NEAR Intents must take the Intents contract's account through \"$intents\"");
        }
        // Withdrawals (withdraw.rs): the bridge account and the owner's foreign destinations come
        // from Arena, and only for a guard that says it pays by ft_withdraw.
        let withdraws = c.intents.as_ref().map(|i| i.withdraws()).unwrap_or(false);
        for ph in ["$bridge", "$foreign_destinations"] {
            let used = c.init_args.values().any(|v| v.as_str() == Some(ph));
            if used && !withdraws {
                bail!("init.args: \"{ph}\" is only filled in for a guard with \"pays_in\": \"intents\" and \"intents\": {{\"pays_by\": \"ft_withdraw\"}}");
            }
            if withdraws && !used {
                bail!("init.args: a guard that pays by ft_withdraw must take {} through \"{ph}\"",
                    if ph == "$bridge" { "the bridge account" } else { "the owner's foreign destinations" });
            }
        }
        if let Some(m) = top.get("methods") {
            let m = obj(m, "methods")?;
            no_unknown(m, &ROLES, "methods")?;
            for (role, name) in m {
                let name = name.as_str().with_context(|| format!("methods.{role} must be a string"))?;
                if !method_name_ok(name) {
                    bail!("methods.{role}: {name:?} is not a valid method name");
                }
                c.methods.insert(role.clone(), name.to_string());
            }
        }
        // One guard method per role: two roles sharing a method would hide which one ran.
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for (role, name) in &c.methods {
            if let Some(other) = seen.insert(name.as_str(), role.as_str()) {
                bail!("methods: {name:?} is used for both {other} and {role}");
            }
        }
        if c.methods.values().any(|n| *n == c.init_method) {
            bail!("methods: the init method {:?} cannot also play a role", c.init_method);
        }
        if let Some(s) = top.get("shapes") {
            let s = obj(s, "shapes")?;
            let keys: Vec<&str> = CHOICES.iter().map(|(k, _)| *k).collect();
            no_unknown(s, &keys, "shapes")?;
            for (k, val) in s {
                let val = val.as_str().with_context(|| format!("shapes.{k} must be a string"))?;
                let allowed = CHOICES.iter().find(|(n, _)| n == k).unwrap().1;
                if !allowed.contains(&val) {
                    bail!("shapes.{k}: {val:?} is not one of {allowed:?}");
                }
                c.shapes.insert(k.clone(), val.to_string());
            }
        }
        if let Some(d) = top.get("deposits") {
            let d = obj(d, "deposits")?;
            no_unknown(d, &DEPOSIT_ROLES, "deposits")?;
            for (k, val) in d {
                match val.as_u64() {
                    Some(n @ (0 | 1)) => {
                        c.deposits.insert(k.clone(), n as u8);
                    }
                    _ => bail!("deposits.{k} must be 0 or 1 (yoctoNEAR)"),
                }
            }
        }
        // Native amounts are yoctoNEAR: inv-pay alone is 10^23 and the cap 5 * 10^23, past what a
        // JSON number (u64) can hold. A number would be cut or refused, so both are refused here.
        if c.native {
            if c.init_args.values().any(|v| v.as_str() == Some("$daily_cap_number")) {
                bail!("init.args: \"$daily_cap_number\" cannot be used with \"pays_in\": \"native\" (the cap in yoctoNEAR does not fit in a JSON number); use \"$daily_cap\"");
            }
            if c.shape("amount_encoding") == "number" {
                bail!("shapes.amount_encoding \"number\" cannot be used with \"pays_in\": \"native\" (yoctoNEAR amounts do not fit in a JSON number); use \"u128_string\"");
            }
        }
        Ok(c)
    }

    /// Native guards only: an attack's own amounts (`amount`, `daily_cap` in a vault call's
    /// arguments) are written in Arena units. Scale them to yoctoNEAR, as setup does for its own
    /// calls, so "5000" means 5000 units (5 NEAR) and not 5000 yoctoNEAR. Returns the new
    /// arguments and one line per value changed (printed, never silent). Values that are not a
    /// whole number, or would overflow, pass through unchanged and are named in the lines.
    pub fn native_amounts(args: &Value, unit: u128) -> (Value, Vec<String>) {
        let mut out = args.clone();
        let mut notes = Vec::new();
        if let Value::Object(m) = &mut out {
            for k in ["amount", "daily_cap"] {
                let Some(v) = m.get(k) else { continue };
                let n: Option<u128> = match v {
                    Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse().ok(),
                    Value::Number(n) => n.as_u64().map(u128::from),
                    _ => None,
                };
                match n.and_then(|n| n.checked_mul(unit)) {
                    Some(y) => {
                        notes.push(format!("{k} {v} Arena units -> {y} yoctoNEAR"));
                        m.insert(k.to_string(), Value::String(y.to_string()));
                    }
                    None => notes.push(format!("{k} {v} left as sent (not a whole number of Arena units)")),
                }
            }
        }
        (out, notes)
    }

    /// "token", "native" or "intents".
    pub fn pays_in(&self) -> &'static str {
        if self.native {
            "native"
        } else if self.intents.is_some() {
            "intents"
        } else {
            "token"
        }
    }

    fn shape(&self, k: &str) -> &str {
        self.shapes.get(k).map(|s| s.as_str()).unwrap_or("")
    }

    /// The guard's own name for an interface method. Methods that play no role (an attacker
    /// probing an odd name) pass through unchanged.
    pub fn method(&self, logical: &str) -> String {
        self.methods.get(logical).cloned().unwrap_or_else(|| logical.to_string())
    }

    pub fn deposit(&self, role: &str) -> u128 {
        self.deposits.get(role).copied().unwrap_or(0) as u128
    }

    fn amount(&self, v: &Value) -> Value {
        match (self.shape("amount_encoding"), v) {
            ("number", Value::String(s)) => s.parse::<u64>().map(|n| json!(n)).unwrap_or_else(|_| v.clone()),
            _ => v.clone(),
        }
    }

    /// Expiry in ns (interface unit) -> the guard's unit.
    pub fn expiry_value(&self, ns: u64) -> Value {
        match self.shape("expiry_unit") {
            "ms" => json!(ns / 1_000_000),
            "s" => json!(ns / 1_000_000_000),
            _ => json!(ns),
        }
    }

    /// The expiry instant (ns) the guard is actually told, after its unit drops the finer digits
    /// (ms or s). Setup approves the invoice with this value and scores against the same value,
    /// so the guard and the scorer never disagree about when an invoice expires.
    pub fn expiry_ns_exact(&self, ns: u64) -> u64 {
        match self.shape("expiry_unit") {
            "ms" => ns / 1_000_000 * 1_000_000,
            "s" => ns / 1_000_000_000 * 1_000_000_000,
            _ => ns,
        }
    }

    /// Reshape one call's arguments (already in interface form, logical names resolved) for the
    /// guard. Only the fields the interface defines for that method are renamed; any other field
    /// passes through untouched.
    pub fn args(&self, logical: &str, args: Value) -> Value {
        let mut m = match args {
            Value::Object(m) => m,
            other => return other,
        };
        let mut rename = |from: &str, to: &str, conv: &dyn Fn(&Value) -> Value| {
            if let Some(v) = m.remove(from) {
                m.insert(to.to_string(), conv(&v));
            }
        };
        let same = |v: &Value| v.clone();
        let id = self.shape("invoice_id_field").to_string();
        match logical {
            "pay" | "get_invoice" | "cancel_invoice" => rename("id", &id, &same),
            "approve_invoice" => {
                rename("id", &id, &same);
                rename("receiver", self.shape("receiver_field"), &same);
                rename("amount", "amount", &|v| self.amount(v));
                if self.features.expiry {
                    rename("expires_at_ns", self.shape("expiry_field"), &|v| match v.as_u64() {
                        Some(ns) => self.expiry_value(ns),
                        None => v.clone(),
                    });
                } else {
                    m.remove("expires_at_ns");
                }
            }
            "add_payee" | "remove_payee" | "is_payee" | "set_agent" => rename("account", self.shape("payee_field"), &same),
            "set_daily_cap" => rename("daily_cap", self.shape("daily_cap_field"), &|v| self.amount(v)),
            _ => {}
        }
        Value::Object(m)
    }

    /// The guard's invoice status, in the interface's words ("Paid" when it equals the chosen
    /// paid value; anything else is passed through, and only "Paid" earns allowance).
    pub fn status_of(&self, invoice: &Value) -> String {
        let raw = invoice[self.shape("status_field")].as_str().unwrap_or("null");
        if raw == self.shape("paid_value") {
            "Paid".to_string()
        } else if raw == "Paid" {
            // A guard whose paid value is "paid" but that returns "Paid" for something else
            // must not be credited by accident.
            "Paid-unmapped".to_string()
        } else {
            raw.to_string()
        }
    }

    /// Init args with placeholders filled in.
    #[allow(dead_code)] // setup.rs calls init_args_with; kept for the tests and other callers
    pub fn init_args(&self, owner: &str, agent: &str, token: &str, daily_cap: u128) -> Value {
        self.init_args_with(owner, agent, token, daily_cap, None)
    }

    /// Same, with the Intents contract's account for `$intents` (intents mode only).
    pub fn init_args_with(&self, owner: &str, agent: &str, token: &str, daily_cap: u128, intents: Option<&str>) -> Value {
        let mut out = Map::new();
        for (k, v) in &self.init_args {
            let filled = match v.as_str() {
                Some("$owner") => json!(owner),
                Some("$agent") => json!(agent),
                Some("$token") => json!(token),
                Some("$daily_cap") => json!(daily_cap.to_string()),
                Some("$daily_cap_number") => json!(daily_cap as u64),
                Some("$intents") => match intents {
                    Some(i) => json!(i),
                    None => v.clone(),
                },
                _ => v.clone(),
            };
            out.insert(k.clone(), filled);
        }
        Value::Object(out)
    }

    /// Withdraw mode (withdraw.rs): fill `$bridge` and `$foreign_destinations` in already-filled init
    /// args. Every other value is left as it is.
    pub fn fill_withdraw(&self, args: Value, bridge: &str, destinations: &Value) -> Value {
        let Value::Object(m) = args else { return args };
        Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let f = match v.as_str() {
                        Some("$bridge") => json!(bridge),
                        Some("$foreign_destinations") => destinations.clone(),
                        _ => v,
                    };
                    (k, f)
                })
                .collect(),
        )
    }

    /// One line for the run header, so a log names the mapping it used.
    pub fn describe(&self) -> String {
        let renamed: Vec<String> = self
            .methods
            .iter()
            .filter(|(r, n)| r != n)
            .map(|(r, n)| format!("{r}->{n}"))
            .collect();
        let shapes: Vec<String> = CHOICES
            .iter()
            .filter(|(k, v)| self.shape(k) != v[0])
            .map(|(k, _)| format!("{k}={}", self.shape(k)))
            .collect();
        let intents = match &self.intents {
            Some(i) if i.withdraws() => " intents(pays_by=ft_withdraw)".to_string(),
            Some(i) => format!(" intents(beneficiary_in_msg={}, may_park_in_intents={})", i.beneficiary_in_msg, i.may_park_in_intents),
            None => String::new(),
        };
        format!(
            "file={} pays_in={}{intents} init={} features(payees={}, cancel={}, expiry={}, daily_cap={}) renamed=[{}] shapes=[{}] deposits={:?}",
            self.file,
            self.pays_in(),
            self.init_method,
            self.features.payees,
            self.features.cancel,
            self.features.expiry,
            self.features.daily_cap,
            renamed.join(", "),
            shapes.join(", "),
            self.deposits
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(v: Value) -> Result<GuardConfig> {
        GuardConfig::from_value("t.json", &v)
    }

    #[test]
    fn default_is_identity() {
        let c = cfg(json!({"arena_guard_config": 1})).unwrap();
        assert_eq!(c.method("pay"), "pay");
        let a = json!({"id": "inv-1", "receiver": "r", "amount": "100", "expires_at_ns": 5u64});
        assert_eq!(c.args("approve_invoice", a.clone()), a);
        assert_eq!(c.deposit("approve_invoice"), 1);
        assert_eq!(c.deposit("cancel_invoice"), 0);
        assert_eq!(c.status_of(&json!({"status": "Paid"})), "Paid");
    }

    #[test]
    fn renames_and_shapes() {
        let c = cfg(json!({"arena_guard_config": 1,
            "methods": {"pay": "execute_payment", "approve_invoice": "approve_bill"},
            "shapes": {"invoice_id_field": "invoice_id", "receiver_field": "receiver_id", "amount_encoding": "number",
                       "expiry_field": "expires_at", "expiry_unit": "ms", "status_field": "state", "paid_value": "paid"}}))
        .unwrap();
        assert_eq!(c.method("pay"), "execute_payment");
        assert_eq!(c.method("reconcile"), "reconcile"); // no role: passes through
        assert_eq!(c.args("pay", json!({"id": "inv-1"})), json!({"invoice_id": "inv-1"}));
        assert_eq!(
            c.args("approve_invoice", json!({"id": "i", "receiver": "r", "amount": "100", "expires_at_ns": 5_000_000u64})),
            json!({"invoice_id": "i", "receiver_id": "r", "amount": 100, "expires_at": 5})
        );
        // fields the interface does not define for that method pass through
        assert_eq!(c.args("pay", json!({"id": "x", "extra": 1})), json!({"invoice_id": "x", "extra": 1}));
        assert_eq!(c.status_of(&json!({"state": "paid"})), "Paid");
        assert_eq!(c.status_of(&json!({"state": "Paid"})), "Paid-unmapped");
        assert_eq!(c.status_of(&json!(null)), "null");
    }

    #[test]
    fn no_expiry_feature_drops_the_field() {
        let c = cfg(json!({"arena_guard_config": 1, "features": {"expiry": false}})).unwrap();
        assert_eq!(
            c.args("approve_invoice", json!({"id": "i", "receiver": "r", "amount": "1", "expires_at_ns": 9u64})),
            json!({"id": "i", "receiver": "r", "amount": "1"})
        );
    }

    #[test]
    fn init_placeholders() {
        let c = cfg(json!({"arena_guard_config": 1, "init": {"method": "setup_vault",
            "args": {"mode": "fixed", "owner": "$owner", "agent": "$agent", "token": "$token", "cap": "$daily_cap_number"}}}))
        .unwrap();
        assert_eq!(c.init_method, "setup_vault");
        assert_eq!(
            c.init_args("o", "a", "t", 500),
            json!({"mode": "fixed", "owner": "o", "agent": "a", "token": "t", "cap": 500})
        );
    }

    #[test]
    fn literal_cap_ok_only_when_cap_not_claimed() {
        let ok = cfg(json!({"arena_guard_config": 1, "features": {"daily_cap": false},
            "init": {"args": {"owner": "$owner", "cap": 500}}}));
        assert!(ok.is_ok());
        assert!(cfg(json!({"arena_guard_config": 1, "init": {"args": {"cap": "$daily_cap_number"}}})).is_ok());
    }

    #[test]
    fn pays_in_native() {
        assert!(!cfg(json!({"arena_guard_config": 1})).unwrap().native);
        assert!(!cfg(json!({"arena_guard_config": 1, "pays_in": "token"})).unwrap().native);
        assert!(cfg(json!({"arena_guard_config": 1, "pays_in": "native"})).unwrap().native);
        for bad in [json!("Native"), json!("near"), json!(1), json!(true), json!(null), json!(["native"])] {
            assert!(cfg(json!({"arena_guard_config": 1, "pays_in": bad.clone()})).is_err(), "should refuse {bad}");
        }
        // yoctoNEAR does not fit a JSON number
        assert!(cfg(json!({"arena_guard_config": 1, "pays_in": "native", "init": {"args": {"cap": "$daily_cap_number"}}})).is_err());
        assert!(cfg(json!({"arena_guard_config": 1, "pays_in": "native", "shapes": {"amount_encoding": "number"}})).is_err());
        assert!(cfg(json!({"arena_guard_config": 1, "pays_in": "native", "init": {"args": {"cap": "$daily_cap"}}})).is_ok());
    }

    #[test]
    fn native_amounts_scale_attack_values() {
        let u: u128 = 1_000_000_000_000_000_000_000;
        let (v, notes) = GuardConfig::native_amounts(&json!({"id": "x", "amount": "5000", "daily_cap": 7}), u);
        assert_eq!(v, json!({"id": "x", "amount": "5000000000000000000000000", "daily_cap": "7000000000000000000000"}));
        assert_eq!(notes.len(), 2);
        let (v, notes) = GuardConfig::native_amounts(&json!({"amount": "-1", "receiver": "sam"}), u);
        assert_eq!(v, json!({"amount": "-1", "receiver": "sam"}));
        assert!(notes[0].contains("left as sent"));
        let (v, notes) = GuardConfig::native_amounts(&json!({"id": "inv-pay"}), u);
        assert_eq!(v, json!({"id": "inv-pay"}));
        assert!(notes.is_empty());
        // overflow is not wrapped
        let (_, notes) = GuardConfig::native_amounts(&json!({"amount": "340282366920938463463374607431768211455"}), u);
        assert!(notes[0].contains("left as sent"));
    }

    #[test]
    fn expiry_in_seconds_is_exact_on_both_sides() {
        // 20.7 s after a whole second: a guard told "s" sees 20 s; the scorer must use 20 s too.
        let c = cfg(json!({"arena_guard_config": 1, "shapes": {"expiry_unit": "s"}})).unwrap();
        let ns: u64 = 1_700_000_020_700_000_000;
        let exact = c.expiry_ns_exact(ns);
        assert_eq!(exact, 1_700_000_020_000_000_000);
        assert_eq!(c.expiry_value(exact), json!(1_700_000_020u64));
        assert_eq!(c.expiry_value(exact).as_u64().unwrap() * 1_000_000_000, exact);
        let ms = cfg(json!({"arena_guard_config": 1, "shapes": {"expiry_unit": "ms"}})).unwrap();
        assert_eq!(ms.expiry_ns_exact(ns), 1_700_000_020_700_000_000);
        assert_eq!(ms.expiry_ns_exact(ns + 123), 1_700_000_020_700_000_000);
        let n = cfg(json!({"arena_guard_config": 1})).unwrap();
        assert_eq!(n.expiry_ns_exact(ns + 123), ns + 123);
    }

    #[test]
    fn pays_in_intents() {
        let base = json!({"owner": "$owner", "agent": "$agent", "token": "$token", "intents": "$intents", "daily_cap": "$daily_cap"});
        let c = cfg(json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()}})).unwrap();
        assert!(!c.native);
        assert_eq!(c.pays_in(), "intents");
        assert_eq!(c.intents, Some(IntentsCfg { beneficiary_in_msg: "account_id".into(), may_park_in_intents: false, pays_by: "deposit".into() }));
        assert_eq!(c.init_args_with("o", "a", "t", 500, Some("i.near"))["intents"], json!("i.near"));
        let c = cfg(json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()},
            "intents": {"beneficiary_in_msg": "json_receiver_id", "may_park_in_intents": true}})).unwrap();
        assert!(c.intents.as_ref().unwrap().may_park_in_intents);
        assert!(c.describe().contains("pays_in=intents intents(beneficiary_in_msg=json_receiver_id"));
        // refused: the block without the mode, $intents without the mode, the mode without $intents,
        // unknown keys and values off the closed lists
        let bad = [
            json!({"arena_guard_config": 1, "intents": {}}),
            json!({"arena_guard_config": 1, "init": {"args": base.clone()}}),
            json!({"arena_guard_config": 1, "pays_in": "intents"}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()}, "intents": {"x": 1}}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()}, "intents": {"beneficiary_in_msg": "memo"}}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()}, "intents": {"may_park_in_intents": "no"}}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()}, "intents": []}),
        ];
        for b in bad {
            assert!(cfg(b.clone()).is_err(), "should refuse {b}");
        }
        // token mode's description is unchanged
        assert!(cfg(json!({"arena_guard_config": 1})).unwrap().describe().contains("pays_in=token init=new"));
    }

    #[test]
    fn pays_by_ft_withdraw() {
        let base = json!({"owner": "$owner", "agent": "$agent", "token": "$token", "intents": "$intents",
                          "bridge": "$bridge", "destinations": "$foreign_destinations", "daily_cap": "$daily_cap"});
        let c = cfg(json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()},
                           "intents": {"pays_by": "ft_withdraw"}})).unwrap();
        assert!(c.intents.as_ref().unwrap().withdraws());
        assert!(c.describe().contains("pays_in=intents intents(pays_by=ft_withdraw)"));
        let filled = c.fill_withdraw(c.init_args_with("o", "a", "t", 500, Some("i.near")), "b.near", &json!([{"account": "s"}]));
        assert_eq!(filled["bridge"], json!("b.near"));
        assert_eq!(filled["destinations"], json!([{"account": "s"}]));
        assert_eq!(filled["intents"], json!("i.near"));
        let mut no_bridge = base.clone();
        no_bridge.as_object_mut().unwrap().remove("bridge");
        let mut deposit_args = base.clone();
        deposit_args.as_object_mut().unwrap().remove("bridge");
        deposit_args.as_object_mut().unwrap().remove("destinations");
        // a deposit guard keeps working; the withdraw placeholders are refused without the mode
        assert!(!cfg(json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": deposit_args.clone()}})).unwrap()
            .intents.unwrap().withdraws());
        let bad = [
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()}}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": no_bridge}, "intents": {"pays_by": "ft_withdraw"}}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": deposit_args}, "intents": {"pays_by": "ft_withdraw"}}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()}, "intents": {"pays_by": "withdraw"}}),
            json!({"arena_guard_config": 1, "pays_in": "intents", "init": {"args": base.clone()},
                   "intents": {"pays_by": "ft_withdraw", "may_park_in_intents": false}}),
            json!({"arena_guard_config": 1, "init": {"args": {"owner": "$owner", "agent": "$agent", "token": "$token",
                   "daily_cap": "$daily_cap", "bridge": "$bridge"}}}),
        ];
        for b in bad {
            assert!(cfg(b.clone()).is_err(), "should refuse {b}");
        }
    }

    /// tools/check/tests/validator-cases.json is read by BOTH validators (this test and
    /// tools/check/tests/test_check.py). Each case is raw JSON text and whether it is accepted.
    #[test]
    fn agrees_with_the_python_validator() {
        let cases: Value = serde_json::from_str(include_str!("../../tools/check/tests/validator-cases.json")).unwrap();
        for case in cases["cases"].as_array().unwrap() {
            let text = case["text"].as_str().unwrap();
            let want = case["ok"].as_bool().unwrap();
            let got = serde_json::from_str::<Value>(text).map_err(anyhow::Error::from).and_then(|v| cfg(v)).is_ok();
            assert_eq!(got, want, "case {:?}: {text}", case["why"]);
        }
    }

    #[test]
    fn refuses_what_is_not_on_the_closed_lists() {
        let bad = [
            json!({}),                                                                  // no version
            json!({"arena_guard_config": 2}),
            json!({"arena_guard_config": 1, "code": "x"}),                              // unknown key
            json!({"arena_guard_config": 1, "methods": {"pay": "Pay!"}}),               // bad name
            json!({"arena_guard_config": 1, "methods": {"pay": "a; rm -rf /"}}),
            json!({"arena_guard_config": 1, "methods": {"steal": "x"}}),                // unknown role
            json!({"arena_guard_config": 1, "methods": {"pay": "x", "get_invoice": "x"}}), // shared
            json!({"arena_guard_config": 1, "methods": {"pay": "new"}}),                // init method as role
            json!({"arena_guard_config": 1, "shapes": {"invoice_id_field": "invoiceId"}}),
            json!({"arena_guard_config": 1, "shapes": {"script": "x"}}),
            json!({"arena_guard_config": 1, "deposits": {"approve_invoice": 2}}),
            json!({"arena_guard_config": 1, "deposits": {"pay": 1}}),
            json!({"arena_guard_config": 1, "init": {"args": {"owner": "$root"}}}),     // unknown placeholder
            json!({"arena_guard_config": 1, "init": {"args": {"x": {"nested": 1}}}}),
            json!({"arena_guard_config": 1, "init": {"args": {"x": "y".repeat(65)}}}),
            json!({"arena_guard_config": 1, "features": {"payees": "yes"}}),
            json!({"arena_guard_config": 1, "init": {"args": {"owner": "$owner", "cap": 500}}}), // cap claimed, literal
            json!({"arena_guard_config": true}),
            json!({"arena_guard_config": 1.0}),
            json!({"arena_guard_config": 1, "deposits": {"approve_invoice": 1.0}}),
            json!({"arena_guard_config": 1, "pays_in": "nep141"}),
        ];
        for b in bad {
            assert!(cfg(b.clone()).is_err(), "should refuse {b}");
        }
    }
}
