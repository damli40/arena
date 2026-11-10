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

pub const PLACEHOLDERS: [&str; 5] = ["$owner", "$agent", "$token", "$daily_cap", "$daily_cap_number"];

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
}

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
        no_unknown(top, &["arena_guard_config", "init", "features", "methods", "shapes", "deposits"], "guard config")?;
        if top.get("arena_guard_config") != Some(&json!(1)) {
            bail!("guard config: \"arena_guard_config\": 1 is required");
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
        Ok(c)
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
    pub fn init_args(&self, owner: &str, agent: &str, token: &str, daily_cap: u128) -> Value {
        let mut out = Map::new();
        for (k, v) in &self.init_args {
            let filled = match v.as_str() {
                Some("$owner") => json!(owner),
                Some("$agent") => json!(agent),
                Some("$token") => json!(token),
                Some("$daily_cap") => json!(daily_cap.to_string()),
                Some("$daily_cap_number") => json!(daily_cap as u64),
                _ => v.clone(),
            };
            out.insert(k.clone(), filled);
        }
        Value::Object(out)
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
        format!(
            "file={} init={} features(payees={}, cancel={}, expiry={}, daily_cap={}) renamed=[{}] shapes=[{}] deposits={:?}",
            self.file,
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
        ];
        for b in bad {
            assert!(cfg(b.clone()).is_err(), "should refuse {b}");
        }
    }
}
