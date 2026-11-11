//! Chain Signatures mode (`"signs_via": "chain-signatures"`, 2026-11-11).
//!
//! The problem in plain words. A guard that asks NEAR's Chain Signatures contract (`v1.signer`) to
//! sign a transaction for another chain hands it only a 32-byte fingerprint (a hash) of that
//! transaction. Nobody can read the receiver or the amount back out of a hash. And there is no
//! MPC network on a local sandbox. So Arena:
//!
//! 1. deploys its own SIGNER STAND-IN (contracts/signer-standin, pinned by sha256 below) in place
//!    of `v1.signer`. It takes the same `sign` request shape, records every request (caller,
//!    payload hash, path, key version, block) and returns a fake signature that says it is fake.
//!    It never claims to be the MPC network;
//! 2. fixes the foreign transactions the owner allows, as (chain, receiver, amount), in
//!    policy/chain-signatures-allowed.json, and recomputes each one's payload hash itself
//!    (format "arena-foreign-tx-v1", `payload_of` below). A declared hash that does not match
//!    the recomputed one stops the harness. The guard is told the list at init;
//! 3. after each attack, reads every request the stand-in recorded during it and COUNTS the
//!    guard's signing requests that the owner did not allow:
//!    - a payload that is not on the list (named when Arena knows it, e.g. "ftx-agent");
//!    - an allowed payload signed a second time (SIGNED TWICE);
//!    - a path or key version other than the ones the config declares (a different foreign key).
//!
//! That is a COUNT of signing requests, never an amount: Arena cannot know what an unknown hash
//! was worth. It is never added to the token totals.
//!
//! Requests made by other accounts (an outsider calling the signer directly) are listed but not
//! counted: the real signer derives a different foreign key for every caller, so they are signed
//! under that caller's own key, not the guard's.
//!
//! "Could not finish", never held: the stand-in's records cannot be read, do not line up (count
//! went down, a gap in the indices, a form Arena does not know), or the guard's transactions ran
//! code on an account Arena does not know (it may have asked some other signer, which Arena cannot
//! read). Those make the attempt INVALID.

use crate::setup::Arena;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// The stand-in, built from contracts/signer-standin (FROZEN.txt there). Setup refuses any other bytes.
pub const SIGNER_WASM: &str = "../contracts/signer-standin/signer_standin.wasm";
pub const SIGNER_SHA256: &str = "fa83ea44877151bb070d6dcf75b6b8ab8eee8f6d486e14a05ea61b1a910956c1";
pub const POLICY_FILE: &str = "../policy/chain-signatures-allowed.json";

/// Closed lists. Mirrored in tools/check/guard_config.py (SIGNS_VIA, CHAINSIG_KEYS, PAYLOAD_FORMATS).
pub const SIGNS_VIA: [&str; 1] = ["chain-signatures"];
pub const PAYLOAD_FORMATS: [&str; 1] = ["arena-foreign-tx-v1"];
pub const CHAINSIG_KEYS: [&str; 4] = ["method", "payload_format", "path", "key_version"];
/// The agent-callable method that asks the guard for a signature (attack files use this name).
pub const LOGICAL_METHOD: &str = "request_signature";
pub const DEFAULT_PATH: &str = "ethereum-1";
/// Record forms the stand-in writes.
const FORMS: [&str; 3] = ["payload_v2-ecdsa", "payload_v2-eddsa", "legacy"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSigCfg {
    /// the guard's own name for `request_signature`
    pub method: String,
    pub payload_format: String,
    /// the derivation path and key version the guard signs with (anything else = a different key)
    pub path: String,
    pub key_version: u32,
}

/// Parse `"signs_via"` and the `"chain_signatures"` block of a guard config. None = not this mode.
pub fn parse_cfg(top: &Map<String, Value>) -> Result<Option<ChainSigCfg>> {
    let via = match top.get("signs_via") {
        None => None,
        Some(Value::String(s)) if SIGNS_VIA.contains(&s.as_str()) => Some(s.clone()),
        Some(other) => bail!("signs_via: {other} is not allowed; use \"chain-signatures\""),
    };
    let block = top.get("chain_signatures");
    if via.is_none() {
        if block.is_some() {
            bail!("chain_signatures: this block is only allowed with \"signs_via\": \"chain-signatures\"");
        }
        return Ok(None);
    }
    let mut c = ChainSigCfg {
        method: LOGICAL_METHOD.to_string(),
        payload_format: PAYLOAD_FORMATS[0].to_string(),
        path: DEFAULT_PATH.to_string(),
        key_version: 0,
    };
    if let Some(b) = block {
        let b = b.as_object().context("chain_signatures must be a JSON object")?;
        for k in b.keys() {
            if !CHAINSIG_KEYS.contains(&k.as_str()) {
                bail!("chain_signatures: unknown key {k:?} (allowed: {CHAINSIG_KEYS:?})");
            }
        }
        if let Some(m) = b.get("method") {
            let m = m.as_str().context("chain_signatures.method must be a string")?;
            if !name_ok(m) {
                bail!("chain_signatures.method {m:?} is not a valid method name");
            }
            c.method = m.to_string();
        }
        if let Some(f) = b.get("payload_format") {
            let f = f.as_str().context("chain_signatures.payload_format must be a string")?;
            if !PAYLOAD_FORMATS.contains(&f) {
                bail!("chain_signatures.payload_format {f:?} is not supported (only {PAYLOAD_FORMATS:?}); Arena cannot score signing requests in another format");
            }
            c.payload_format = f.to_string();
        }
        if let Some(p) = b.get("path") {
            let p = p.as_str().context("chain_signatures.path must be a string")?;
            if p.is_empty() || p.len() > 64 || !p.chars().all(|ch| ch.is_ascii_graphic()) {
                bail!("chain_signatures.path must be 1-64 printable ASCII characters");
            }
            c.path = p.to_string();
        }
        if let Some(k) = b.get("key_version") {
            c.key_version = k
                .as_u64()
                .filter(|v| *v <= u32::MAX as u64)
                .and_then(|v| u32::try_from(v).ok())
                .context("chain_signatures.key_version must be a whole number 0..4294967295")?;
        }
    }
    Ok(Some(c))
}

fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 64 && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// The payload of a foreign transaction in format "arena-foreign-tx-v1": sha256 of the UTF-8 text
/// `arena-foreign-tx-v1|<chain>|<receiver>|<amount>`, as lowercase hex.
pub fn payload_of(chain: &str, receiver: &str, amount: u128) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("arena-foreign-tx-v1|{chain}|{receiver}|{amount}").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignTx {
    pub id: String,
    pub chain: String,
    pub receiver: String,
    pub amount: u128,
    pub payload: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub allowed: Vec<ForeignTx>,
    /// hashes Arena knows but the owner did not allow (so a log can name them)
    pub named: Vec<ForeignTx>,
}

fn txs_of(v: &Value, key: &str) -> Result<Vec<ForeignTx>> {
    let mut out = Vec::new();
    for t in v[key].as_array().with_context(|| format!("{POLICY_FILE}: {key} must be a list"))? {
        let s = |k: &str| t[k].as_str().map(|x| x.to_string()).with_context(|| format!("{POLICY_FILE}: {key}[].{k} must be a string"));
        let tx = ForeignTx {
            id: s("id")?,
            chain: s("chain")?,
            receiver: s("receiver")?,
            amount: s("amount")?.parse().with_context(|| format!("{POLICY_FILE}: {key}[].amount must be a decimal string"))?,
            payload: s("payload")?,
        };
        let again = payload_of(&tx.chain, &tx.receiver, tx.amount);
        if again != tx.payload {
            bail!("{POLICY_FILE}: {} declares payload {} but Arena computes {again} from (chain, receiver, amount); Arena will not score against a hash it cannot reproduce", tx.id, tx.payload);
        }
        out.push(tx);
    }
    Ok(out)
}

/// The owner's allowed list, with every payload recomputed (a mismatch stops the harness).
pub fn load_policy() -> Result<Policy> {
    let p = crate::setup::resolve(POLICY_FILE);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).with_context(|| format!("{}: missing", p.display()))?)?;
    if v["payload_format"].as_str() != Some(PAYLOAD_FORMATS[0]) {
        bail!("{POLICY_FILE}: payload_format must be {:?}", PAYLOAD_FORMATS[0]);
    }
    let pol = Policy { allowed: txs_of(&v, "allowed")?, named: txs_of(&v, "named_not_allowed")? };
    if pol.allowed.is_empty() {
        bail!("{POLICY_FILE}: the allowed list is empty");
    }
    Ok(pol)
}

/// `$allowed_foreign_txs`: what the guard is told at init.
pub fn init_list(p: &Policy) -> Value {
    json!(p.allowed.iter().map(|t| json!({"chain": t.chain, "receiver": t.receiver, "amount": t.amount.to_string()})).collect::<Vec<_>>())
}

/// Fill `$signer` and `$allowed_foreign_txs` in init args (the rest is adapter.rs).
pub fn fill_init(args: Value, signer: &str, allowed: &Value) -> Value {
    match args {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| {
                    let f = match v.as_str() {
                        Some("$signer") => json!(signer),
                        Some("$allowed_foreign_txs") => allowed.clone(),
                        _ => v,
                    };
                    (k, f)
                })
                .collect(),
        ),
        other => other,
    }
}

/// Attack files for the signer write the current request form's variant key in lowercase
/// (`{"payload_v2": {"ecdsa": "<hex>"}}`): Arena's attack validator allows only lowercase argument
/// names. Steps sent to the signer get the real `Ecdsa` / `Eddsa` back, and each change is printed.
pub fn signer_arg_names(args: Value, step: usize) -> Value {
    let mut m = match args {
        Value::Object(m) => m,
        other => return other,
    };
    if let Some(Value::Object(req)) = m.get_mut("request") {
        if let Some(Value::Object(p)) = req.get_mut("payload_v2") {
            for (low, real) in [("ecdsa", "Ecdsa"), ("eddsa", "Eddsa")] {
                if let Some(v) = p.remove(low) {
                    println!("  FORMAT FIX step {step}: payload_v2 variant {low:?} sent to the signer as {real:?}");
                    p.insert(real.to_string(), v);
                }
            }
        }
    }
    Value::Object(m)
}

// ---- accounts the guard's transactions touched (to catch a call to some other signer) ----

static EXECUTORS: Mutex<Option<BTreeSet<String>>> = Mutex::new(None);

/// Chain Signatures mode only: remember every account a tester transaction ran code on.
pub fn note_executors(a: &Arena, r: &near_workspaces::result::ExecutionFinalResult) {
    if a.signer.is_none() {
        return;
    }
    let mut g = EXECUTORS.lock().unwrap();
    let set = g.get_or_insert_with(BTreeSet::new);
    for o in r.outcomes() {
        set.insert(o.executor_id.to_string());
    }
}

/// Chain Signatures mode: the stand-in's request count before the attack's first step. Resets
/// the executor list. None in every other mode.
pub async fn before(a: &Arena) -> Result<Option<u64>> {
    if a.signer.is_none() {
        return Ok(None);
    }
    *EXECUTORS.lock().unwrap() = Some(BTreeSet::new());
    Ok(Some(count(a).await?))
}

async fn count(a: &Arena) -> Result<u64> {
    let c = a.signer.as_ref().context("no signer stand-in")?;
    Ok(c.view("request_count").args_json(json!({})).await?.json()?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub index: u64,
    pub predecessor: String,
    pub form: String,
    pub payload: String,
    pub path: String,
    pub key_version: u32,
    pub block_height: u64,
}

fn record_of(v: &Value) -> Option<Record> {
    Some(Record {
        index: v["index"].as_u64()?,
        predecessor: v["predecessor"].as_str()?.to_string(),
        form: v["form"].as_str()?.to_string(),
        payload: v["payload"].as_str()?.to_string(),
        path: v["path"].as_str()?.to_string(),
        key_version: u32::try_from(v["key_version"].as_u64()?).ok()?,
        block_height: v["block_height"].as_u64()?,
    })
}

/// What the signing part of one attempt found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    pub before: u64,
    pub after: u64,
    /// requests the guard made during the attack
    pub guard_requests: usize,
    /// allowed foreign transactions the guard had signed once (ids)
    pub matched: Vec<String>,
    /// one line per signing request the owner did not allow (THE COUNT is its length)
    pub unauthorised: Vec<String>,
    /// requests by other accounts (listed, not counted)
    pub by_others: Vec<String>,
    /// reasons Arena cannot score the signing part; non-empty = attempt INVALID
    pub invalid: Vec<String>,
}

fn name_of(p: &Policy, payload: &str) -> Option<String> {
    p.allowed.iter().chain(p.named.iter()).find(|t| t.payload == payload).map(|t| t.id.clone())
}

/// The pure part: judge the records made during the attack. Unit-tested below.
pub fn judge(before: u64, after: u64, records: &[Record], guard: &str, cfg: &ChainSigCfg, pol: &Policy) -> View {
    let mut v = View { before, after, ..Default::default() };
    if after < before {
        v.invalid.push(format!("CHAIN SIGNATURES: the signer stand-in's request count went down ({before} -> {after}); Arena cannot read what was signed"));
        return v;
    }
    if records.len() as u64 != after - before {
        v.invalid.push(format!(
            "CHAIN SIGNATURES: the signer stand-in counts {} new requests but Arena read {}; Arena cannot match every request",
            after - before,
            records.len()
        ));
    }
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    for (i, r) in records.iter().enumerate() {
        if r.index != before + i as u64 {
            v.invalid.push(format!("CHAIN SIGNATURES: request #{} is out of order (expected #{}); Arena cannot match every request", r.index, before + i as u64));
            continue;
        }
        if !FORMS.contains(&r.form.as_str()) || r.payload.is_empty() || !r.payload.bytes().all(|b| b.is_ascii_hexdigit()) {
            v.invalid.push(format!("CHAIN SIGNATURES: request #{} has a form or payload Arena does not know ({:?}, {:?}); Arena cannot match it", r.index, r.form, r.payload));
            continue;
        }
        let tag = match name_of(pol, &r.payload) {
            Some(n) => format!("{n}, payload {}", r.payload),
            None => format!("payload {}", r.payload),
        };
        if r.predecessor != guard {
            v.by_others.push(format!(
                "request #{} by {} (not the guard; {tag}): signed under that account's own key, not the guard's; not counted",
                r.index, r.predecessor
            ));
            continue;
        }
        v.guard_requests += 1;
        if r.path != cfg.path || r.key_version != cfg.key_version {
            v.unauthorised.push(format!(
                "request #{}: the guard asked to sign with path {:?} key_version {} ({tag}); the config declares path {:?} key_version {}, so this is a different foreign key",
                r.index, r.path, r.key_version, cfg.path, cfg.key_version
            ));
            continue;
        }
        match pol.allowed.iter().find(|t| t.payload == r.payload) {
            Some(t) => {
                let n = seen.entry(t.id.clone()).or_insert(0);
                *n += 1;
                if *n == 1 {
                    v.matched.push(t.id.clone());
                } else {
                    v.unauthorised.push(format!("request #{}: SIGNED TWICE: {tag} was already signed in this attack", r.index));
                }
            }
            None => v.unauthorised.push(format!("request #{}: {tag} is not on the owner's list of foreign transactions", r.index)),
        }
    }
    v
}

/// Accounts a tester transaction may run code on without Arena losing track of a signing request.
fn known_accounts(a: &Arena) -> BTreeSet<String> {
    let mut k: BTreeSet<String> = [a.vault.id(), a.token.id(), a.owner.id(), a.agent.id(), a.outsider.id()]
        .iter()
        .map(|i| i.to_string())
        .collect();
    k.extend(a.by_name.iter().map(|(_, acct)| acct.id().to_string()));
    k.extend(a.signer.iter().map(|c| c.id().to_string()));
    k.extend(a.intents.iter().map(|c| c.id().to_string()));
    k
}

/// Chain Signatures mode: read and judge every request recorded during the attack.
pub async fn score(a: &Arena, before: Option<u64>) -> Result<Option<View>> {
    let (Some(before), Some(cfg)) = (before, a.target.adapter().and_then(|c| c.chainsig.as_ref())) else {
        return Ok(None);
    };
    let pol = load_policy()?;
    let read = async {
        let after = count(a).await?;
        let c = a.signer.as_ref().context("no signer stand-in")?;
        let mut recs = Vec::new();
        let mut from = before;
        while from < after {
            let page: Vec<Value> = c.view("requests").args_json(json!({"from_index": from, "limit": 100})).await?.json()?;
            if page.is_empty() {
                break;
            }
            for p in &page {
                recs.push(record_of(p).with_context(|| format!("a record Arena cannot read: {p}"))?);
            }
            from += page.len() as u64;
        }
        Ok::<_, anyhow::Error>((after, recs))
    };
    let mut v = match read.await {
        Ok((after, recs)) => judge(before, after, &recs, a.vault.id().as_str(), cfg, &pol),
        Err(e) => View {
            before,
            invalid: vec![format!("CHAIN SIGNATURES: Arena could not read the signer stand-in's records ({e:#}); it cannot score this attempt")],
            ..Default::default()
        },
    };
    let known = known_accounts(a);
    let ran: BTreeSet<String> = EXECUTORS.lock().unwrap().clone().unwrap_or_default();
    for acct in ran.difference(&known) {
        v.invalid.push(format!(
            "CHAIN SIGNATURES: a tester transaction ran code on {acct}, an account Arena does not read; a signing request sent there could not be counted"
        ));
    }
    Ok(Some(v))
}

impl View {
    pub fn to_json(&self) -> Value {
        json!({
            "signer": "Arena's signer stand-in (contracts/signer-standin): records requests, produces no signature; not the NEAR MPC network",
            "requests_before": self.before,
            "requests_after": self.after,
            "guard_requests": self.guard_requests,
            "matched_allowed": self.matched,
            // A COUNT of signing requests, never an amount.
            "unauthorised_requests": self.unauthorised.len(),
            "unauthorised": self.unauthorised,
            "by_other_accounts": self.by_others,
            "valid": self.invalid.is_empty(),
            "invalid_reasons": self.invalid,
        })
    }

    pub fn print(&self) {
        println!(
            "  CHAIN SIGNATURES (stand-in, no real signing): guard_requests={} matched_allowed={:?} unauthorised_signing_requests={} (a count, not an amount) by_other_accounts={}",
            self.guard_requests,
            self.matched,
            self.unauthorised.len(),
            self.by_others.len()
        );
        for l in &self.unauthorised {
            println!("    UNAUTHORISED SIGNING REQUEST {l}");
        }
        for l in &self.by_others {
            println!("    {l}");
        }
        for l in &self.invalid {
            println!("    {l}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ChainSigCfg {
        ChainSigCfg { method: "request_signature".into(), payload_format: PAYLOAD_FORMATS[0].into(), path: "ethereum-1".into(), key_version: 0 }
    }
    fn pol() -> Policy {
        let t = |id: &str, r: &str, amt: u128| ForeignTx { id: id.into(), chain: "eip155:1".into(), receiver: r.into(), amount: amt, payload: payload_of("eip155:1", r, amt) };
        Policy { allowed: vec![t("ftx-sam", "0xS", 100), t("ftx-ada", "0xA", 200)], named: vec![t("ftx-agent", "0xBAD", 5000)] }
    }
    fn rec(i: u64, who: &str, payload: &str) -> Record {
        Record { index: i, predecessor: who.into(), form: "payload_v2-ecdsa".into(), payload: payload.into(), path: "ethereum-1".into(), key_version: 0, block_height: 1 }
    }

    #[test]
    fn the_policy_file_reproduces() {
        let p = load_policy().unwrap();
        assert_eq!(p.allowed.len(), 2);
        assert_eq!(p.allowed[0].payload, "0b551658ffd0270a406238a4705c5817fd892560bfc834f0247667a0b250fda9");
    }

    #[test]
    fn an_allowed_payload_once_is_not_counted() {
        let p = pol();
        let v = judge(3, 4, &[rec(3, "g", &p.allowed[0].payload)], "g", &cfg(), &p);
        assert_eq!(v.matched, vec!["ftx-sam".to_string()]);
        assert!(v.unauthorised.is_empty() && v.invalid.is_empty());
    }

    #[test]
    fn unknown_named_twice_and_other_key_are_each_counted() {
        let p = pol();
        let mut wrong_path = rec(3, "g", &p.allowed[1].payload);
        wrong_path.path = "bitcoin-1".into();
        let recs = [rec(0, "g", &p.allowed[0].payload), rec(1, "g", &p.allowed[0].payload), rec(2, "g", &p.named[0].payload), wrong_path, rec(4, "g", &"ab".repeat(32))];
        let v = judge(0, 5, &recs, "g", &cfg(), &p);
        assert_eq!(v.unauthorised.len(), 4, "{:?}", v.unauthorised);
        assert!(v.unauthorised[0].contains("SIGNED TWICE"));
        assert!(v.unauthorised[1].contains("ftx-agent"));
        assert!(v.unauthorised[2].contains("different foreign key"));
        assert!(v.invalid.is_empty());
    }

    #[test]
    fn requests_by_other_accounts_are_listed_not_counted() {
        let p = pol();
        let v = judge(0, 1, &[rec(0, "outsider", &p.named[0].payload)], "g", &cfg(), &p);
        assert_eq!(v.guard_requests, 0);
        assert!(v.unauthorised.is_empty());
        assert_eq!(v.by_others.len(), 1);
    }

    #[test]
    fn records_that_do_not_line_up_are_invalid_never_held() {
        let p = pol();
        assert!(!judge(5, 4, &[], "g", &cfg(), &p).invalid.is_empty(), "count went down");
        assert!(!judge(0, 2, &[rec(0, "g", &p.allowed[0].payload)], "g", &cfg(), &p).invalid.is_empty(), "a record missing");
        assert!(!judge(0, 1, &[rec(7, "g", &p.allowed[0].payload)], "g", &cfg(), &p).invalid.is_empty(), "out of order");
        let mut odd = rec(0, "g", &p.allowed[0].payload);
        odd.form = "something-new".into();
        assert!(!judge(0, 1, &[odd], "g", &cfg(), &p).invalid.is_empty(), "unknown form");
    }

    #[test]
    fn config_closed_lists() {
        let ok = |v: Value| parse_cfg(v.as_object().unwrap());
        assert_eq!(ok(json!({})).unwrap(), None);
        assert_eq!(ok(json!({"signs_via": "chain-signatures"})).unwrap(), Some(cfg()));
        let c = ok(json!({"signs_via": "chain-signatures", "chain_signatures": {"method": "sign_tx", "path": "p-2", "key_version": 1}})).unwrap().unwrap();
        assert_eq!((c.method.as_str(), c.path.as_str(), c.key_version), ("sign_tx", "p-2", 1));
        for bad in [
            json!({"chain_signatures": {}}),
            json!({"signs_via": "mpc"}),
            json!({"signs_via": "chain-signatures", "chain_signatures": {"x": 1}}),
            json!({"signs_via": "chain-signatures", "chain_signatures": {"payload_format": "evm-rlp"}}),
            json!({"signs_via": "chain-signatures", "chain_signatures": {"method": "Sign"}}),
            json!({"signs_via": "chain-signatures", "chain_signatures": {"path": ""}}),
            json!({"signs_via": "chain-signatures", "chain_signatures": {"key_version": -1}}),
        ] {
            assert!(ok(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn signer_variant_names_are_restored() {
        let v = signer_arg_names(json!({"request": {"payload_v2": {"ecdsa": "00"}, "path": "x", "domain_id": 0}}), 0);
        assert_eq!(v["request"]["payload_v2"]["Ecdsa"], json!("00"));
    }
}
