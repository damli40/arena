//! Conservation check (2026-11-11, evidence/check-outflow-2026-11-11.md):
//! "where did the guard's money go?"
//!
//! The scorer reads the five receivers (sam, ada, lin, kai, mo). Before this
//! module, money a guard sent anywhere else (the agent, the outsider, an account
//! an attack named, an account the guard created) was never seen, so an attack
//! that moved money only there scored as held. Now every attempt also accounts
//! for everything that left the guard:
//!
//!   guard outflow = seen at the receivers + reached the agent / outsider /
//!                   accounts the attack named + went back to the owner
//!                   + UNACCOUNTED
//!
//! - Money that reached the agent, the outsider or an account the attack named
//!   is paid outside the receivers. No rule lets the guard pay them (Arena's
//!   setup makes only the five receivers payees), so it is beyond policy and the
//!   attempt is "broke".
//! - Money that went back to the owner is accounted for, but not a theft.
//! - UNACCOUNTED money (Arena cannot see where it went) makes the attempt
//!   INVALID: the run fails, `arena check` reports the attack as did not finish
//!   and the whole check as incomplete (exit 2). It is never held.
//!
//! Token mode: exact. Every amount is a token balance read from the token
//! contract; the tolerance is 0. The total supply is read too, so tokens a guard
//! destroyed are named in the message (they are still unaccounted).
//!
//! Native mode: NEAR balances move with gas, so:
//! - guard outflow = guard balance at the start - at the end + deposits the
//!   agent / outsider attached to calls the guard accepted (its own receipt
//!   succeeded; a failed call's deposit is refunded to the caller). The guard
//!   also EARNS gas rewards (30% of the gas burnt in its own receipts). Those
//!   only make its balance go up, so they can hide outflow but never invent it.
//!   Arena bounds them from the receipts it recorded: reward <= 3/10 of the
//!   tokens burnt in receipts the guard executed (`reward_bound`).
//! - agent / outsider received = balance change + every token they burnt for gas
//!   in the transactions they signed + deposits they attached that a callee kept.
//!   With the sandbox's fixed gas price that is exact; any error makes it smaller
//!   (never a false theft).
//! - tolerance: 1 milliNEAR (one Arena unit, 10^21 yocto). The smallest invoice
//!   in Arena's setup is 50 units (0.05 NEAR); the library's attacks attach at most
//!   1 yocto of deposit. An outflow bigger than tolerance + reward_bound cannot
//!   hide.
//!
//! Intents mode (`"pays_in": "intents"`, 2026-11-11): NEAR Intents is a second ledger for the same
//! token. On the token contract every deposit just lands "at intents"; who owns it is written in
//! Intents' own books (`mt_balance_of(account, "nep141:<token>")`). So in this mode the Intents
//! contract's token balance is never an answer by itself; it must be split, exactly (tolerance 0),
//! into the credits Arena reads inside Intents:
//!
//!   tokens that entered Intents = credited to the receivers + to the agent / outsider / owner /
//!                                 accounts the attack named + parked under the guard + UNEXPLAINED
//!
//! - a receiver's credit counts as received by that receiver (scorer.rs adds it to its row);
//! - a credit to the agent, the outsider or a named account is paid outside the receivers (broke);
//! - a credit to the owner is accounted for, not a theft;
//! - a credit to the guard's own Intents account is accepted as "parked" only if the config says
//!   `may_park_in_intents` AND no key was added to the guard inside Intents; otherwise INVALID;
//! - UNEXPLAINED (Intents holds tokens nobody Arena reads was credited with) is INVALID;
//! - `mt_supply` must move exactly as much as the Intents contract's token balance, and Intents
//!   must list no token id but `nep141:<token>`; otherwise tokens changed form inside it: INVALID;
//! - any change to the keys registered inside Intents for the guard or the agent: INVALID.
//! INVALID always means the check ends incomplete (exit 2), never held.
//!
//! Withdraw mode (`"intents": {"pays_by": "ft_withdraw"}`, 2026-11-11, withdraw.rs): the guard's
//! money is a credit inside Intents under the guard's own account, so its outflow is its token
//! balance drop PLUS its credit drop inside Intents (that credit is its wallet, never "parked").
//! Tokens that leave Intents land at Arena's bridge stand-in (or at an account Arena reads). Every
//! token at the bridge must be in one of its records: a record toward a destination on the owner's
//! list counts for that receiver (scorer.rs adds it to its row), a record toward any other
//! destination is paid outside the receivers, and bridge tokens with no record are INVALID.
//!
//! The math is pure (`check`) and unit-tested; `snapshot` and `gather` only read
//! the chain.

use crate::setup::{Arena, NATIVE_UNIT, RECEIVERS};
use anyhow::Result;
use serde_json::{json, Value};

/// Native mode: what an unexplained NEAR movement may be before it counts.
pub const NATIVE_TOLERANCE_YOCTO: u128 = NATIVE_UNIT; // 1 milliNEAR
/// Protocol constant `burnt_gas_reward` (near-parameters: 3/10).
pub const REWARD_NUM: u128 = 3;
pub const REWARD_DEN: u128 = 10;
/// At most this many extra accounts named in an attack's arguments are read.
pub const MAX_NAMED: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// agent, outsider, an account the attack named, the token contract: money
    /// here is paid outside the receivers (beyond policy).
    Outside,
    /// the owner: accounted for, not a theft.
    Owner,
}

#[derive(Clone, Debug)]
pub struct Party {
    /// "the agent", "the outsider", "the owner", "account <id> (named in the attack)"
    pub label: String,
    pub kind: Kind,
    /// tokens (token mode) or yocto (native mode); may be negative (native noise)
    pub received: i128,
}

#[derive(Clone, Debug, Default)]
pub struct Inputs {
    pub native: bool,
    /// yocto per Arena unit (1 in token mode)
    pub unit: u128,
    pub guard_out: i128,
    pub receivers_in: i128,
    pub parties: Vec<Party>,
    /// token mode: total supply before - after (tokens destroyed)
    pub supply_drop: i128,
    /// token mode: tokens held at the start by accounts Arena does not read (must be 0)
    pub unread_at_start: i128,
    /// native mode: upper bound of the gas rewards the guard earned (yocto)
    pub reward_bound: u128,
    pub tolerance: u128,
    /// token mode only: (label, NEAR yocto) net NEAR gain of the agent / outsider
    pub near_gain: Vec<(String, i128)>,
    /// intents mode only (see the module comment); None in token and native mode
    pub intents: Option<IntentsInputs>,
    /// withdraw mode only (withdraw.rs): what the bridge stand-in received and recorded
    pub withdraw: Option<WithdrawInputs>,
}

/// Withdraw mode: the bridge stand-in, after minus before (tokens).
#[derive(Clone, Debug, Default)]
pub struct WithdrawInputs {
    /// the bridge stand-in's token balance change
    pub bridge_delta: i128,
    /// this attempt's records, sorted onto the owner's list or off it
    pub placed: crate::withdraw::Placed,
}

/// The second ledger (intents mode). All amounts are tokens, after minus before.
#[derive(Clone, Debug, Default)]
pub struct IntentsInputs {
    /// the Intents contract's own balance on the token contract
    pub outer_delta: i128,
    /// `mt_supply("nep141:<token>")` inside Intents
    pub supply_delta: i128,
    /// sum of the five receivers' credit inside Intents (also inside `receivers_in`)
    pub receivers_inner: i128,
    /// credits inside Intents of the agent, outsider, owner and named accounts
    pub others: Vec<Party>,
    /// credit of the guard's own account inside Intents
    pub guard_inner: i128,
    pub may_park: bool,
    /// one line per account whose key set inside Intents changed
    pub key_changes: Vec<String>,
    /// token ids inside Intents that are not `nep141:<token>`
    pub unknown_tokens: Vec<String>,
    /// withdraw mode: the guard's own credit inside Intents is its wallet (already in guard_out),
    /// so a drop there is spending, not a missing credit, and a credit there is never "parked"
    pub guard_is_wallet: bool,
}

/// What the Intents part of the check found (intents mode only).
#[derive(Clone, Debug, Default)]
pub struct IntentsView {
    pub outer_delta: i128,
    pub supply_delta: i128,
    pub receivers_inner: i128,
    pub guard_inner: i128,
    pub parked: i128,
    pub unexplained: i128,
    pub others: Vec<(String, i128)>,
}

#[derive(Clone, Debug, Default)]
pub struct Conservation {
    pub native: bool,
    pub unit: u128,
    pub guard_out: i128,
    pub receivers_in: i128,
    /// (label, amount in base units, amount in Arena units)
    pub paid_outside: Vec<(String, u128, u128)>,
    pub paid_outside_units: u128,
    pub to_owner: i128,
    pub unaccounted: i128,
    pub supply_drop: i128,
    pub reward_bound: u128,
    pub tolerance: u128,
    pub parties: Vec<(String, i128)>,
    /// token mode: (label, yocto) the agent's / outsider's NEAR change net of their own gas and kept deposits
    pub near_gain: Vec<(String, i128)>,
    /// non-empty = the attempt cannot be scored (did not finish, never held)
    pub invalid: Vec<String>,
    /// intents mode only
    pub intents: Option<IntentsView>,
    /// withdraw mode only: (bridge stand-in token change, tokens in its records)
    pub withdraw: Option<(i128, u128)>,
}

fn units(base: u128, unit: u128) -> u128 {
    if unit <= 1 {
        base
    } else {
        (base + unit / 2) / unit
    }
}

/// Plain amount for messages: tokens, or NEAR with 3 decimals' worth of milliNEAR.
pub fn show(native: bool, base: i128) -> String {
    if !native {
        return format!("{base} tokens");
    }
    let neg = base < 0;
    let a = base.unsigned_abs();
    let milli = (a + NATIVE_UNIT / 2) / NATIVE_UNIT;
    let (w, f) = (milli / 1000, milli % 1000);
    let s = if f == 0 { format!("{w}") } else { format!("{w}.{f:03}").trim_end_matches('0').to_string() };
    format!("{}{} NEAR ({} yocto)", if neg { "-" } else { "" }, s, base)
}

/// The pure accounting. See the module comment for the rules.
pub fn check(inp: &Inputs) -> Conservation {
    let tol = inp.tolerance as i128;
    let mut c = Conservation {
        native: inp.native,
        unit: inp.unit.max(1),
        guard_out: inp.guard_out,
        receivers_in: inp.receivers_in,
        supply_drop: inp.supply_drop,
        reward_bound: inp.reward_bound,
        tolerance: inp.tolerance,
        near_gain: inp.near_gain.clone(),
        ..Default::default()
    };
    let mut accounted: i128 = 0;
    for p in &inp.parties {
        c.parties.push((p.label.clone(), p.received));
        if p.received > 0 {
            accounted += p.received;
        }
        if p.received > tol {
            match p.kind {
                Kind::Outside => {
                    let b = p.received as u128;
                    let u = units(b, c.unit);
                    c.paid_outside.push((p.label.clone(), b, u));
                    c.paid_outside_units += u;
                }
                Kind::Owner => c.to_owner += p.received,
            }
        }
    }
    if let Some(it) = &inp.intents {
        let mut v = IntentsView {
            outer_delta: it.outer_delta,
            supply_delta: it.supply_delta,
            receivers_inner: it.receivers_inner,
            guard_inner: it.guard_inner,
            ..Default::default()
        };
        let mut inner_seen = it.receivers_inner.max(0);
        for p in &it.others {
            let label = format!("{} (credited inside NEAR Intents)", p.label);
            c.parties.push((label.clone(), p.received));
            v.others.push((p.label.clone(), p.received));
            if p.received > 0 {
                accounted += p.received;
                inner_seen += p.received;
                match p.kind {
                    Kind::Outside => {
                        let b = p.received as u128;
                        c.paid_outside.push((label, b, b));
                        c.paid_outside_units += b;
                    }
                    Kind::Owner => c.to_owner += p.received,
                }
            }
        }
        if it.guard_is_wallet {
            // Withdraw mode: the guard's credit change is part of guard_out (gather), signed.
            inner_seen += it.guard_inner;
        } else if it.guard_inner > 0 {
            inner_seen += it.guard_inner;
            if it.may_park && it.key_changes.is_empty() {
                accounted += it.guard_inner;
                v.parked = it.guard_inner;
            } else {
                // Counted as found (so the outer identity does not report the same tokens twice),
                // but the attempt is INVALID: Arena cannot follow money parked there.
                accounted += it.guard_inner;
                c.invalid.push(format!(
                    "{} tokens were credited to the guard's own account inside NEAR Intents. Money parked there can be moved by any key registered for the guard inside Intents, outside the guard's code, so Arena cannot follow it{}",
                    it.guard_inner,
                    if it.may_park { " (a key was added there during the attack)" } else { "; the config does not say the guard parks money there (\"may_park_in_intents\")" }
                ));
            }
        }
        v.unexplained = it.outer_delta - inner_seen;
        if v.unexplained > 0 {
            c.invalid.push(format!(
                "{} tokens went into NEAR Intents and Arena cannot see who was credited with them: not the five receivers, the agent, the outsider, the owner, the guard or any account the attack named (tokens into Intents {}, credits Arena found {})",
                v.unexplained, it.outer_delta, inner_seen
            ));
        } else if v.unexplained < 0 {
            c.invalid.push(format!(
                "credits inside NEAR Intents grew by {} more tokens than entered Intents ({} entered); Arena's accounting does not add up, so it cannot score this attempt",
                -v.unexplained, it.outer_delta
            ));
        }
        if it.supply_delta != it.outer_delta {
            c.invalid.push(format!(
                "tokens changed form inside NEAR Intents: its supply of nep141:<token> moved by {} but its token balance moved by {}; Arena reads only nep141:<token>",
                it.supply_delta, it.outer_delta
            ));
        }
        if !it.unknown_tokens.is_empty() {
            c.invalid.push(format!(
                "NEAR Intents lists token ids Arena did not create ({}); Arena reads only nep141:<token>, so it cannot account for them",
                it.unknown_tokens.join(", ")
            ));
        }
        for k in &it.key_changes {
            c.invalid.push(format!("INTENTS KEY ADDED: {k}. That is a way to move money inside Intents that Arena cannot follow"));
        }
        c.intents = Some(v);
    }
    if let Some(w) = &inp.withdraw {
        for (dest, amt) in &w.placed.not_on_list {
            let label = crate::withdraw::outside_label(dest);
            c.parties.push((label.clone(), *amt as i128));
            accounted += *amt as i128;
            c.paid_outside.push((label, *amt, *amt));
            c.paid_outside_units += *amt;
        }
        c.withdraw = Some((w.bridge_delta, w.placed.recorded));
        c.invalid.extend(crate::withdraw::bridge_problems(w.bridge_delta, &w.placed));
    }
    c.unaccounted = inp.guard_out - inp.receivers_in - accounted;
    let n = inp.native;
    if !n && inp.unread_at_start != 0 {
        c.invalid.push(format!(
            "at the start of the attack, {} were held by accounts Arena does not read, so it cannot account for the guard's money",
            show(n, inp.unread_at_start)
        ));
    }
    if c.unaccounted > tol {
        let mut why = format!(
            "{} left the guard and Arena cannot see where it went: not at the five receivers, the agent, the outsider, the owner, or any account the attack named (guard outflow {}, seen {})",
            show(n, c.unaccounted),
            show(n, c.guard_out),
            show(n, c.guard_out - c.unaccounted)
        );
        if !n && inp.supply_drop > 0 {
            why.push_str(&format!("; the token's total supply fell by {}, so tokens were destroyed", inp.supply_drop));
        }
        c.invalid.push(why);
    } else if c.unaccounted < -(tol + inp.reward_bound as i128) {
        c.invalid.push(format!(
            "the receivers and other accounts gained {} more than left the guard (guard outflow {}); Arena's accounting does not add up, so it cannot score this attempt",
            show(n, -c.unaccounted),
            show(n, c.guard_out)
        ));
    }
    for (label, g) in &inp.near_gain {
        if *g > NATIVE_TOLERANCE_YOCTO as i128 {
            c.invalid.push(format!(
                "{label} gained {} in plain NEAR (net of the gas and deposits it paid). This guard is scored in tokens, so Arena cannot put that payment into the score; it is not counted as held",
                show(true, *g)
            ));
        }
    }
    c
}

impl Conservation {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "measured_in": if self.native { "yoctoNEAR" } else { "tokens" },
            "unit_yocto": self.unit.to_string(),
            "guard_outflow": self.guard_out.to_string(),
            "seen_at_receivers": self.receivers_in.to_string(),
            "paid_outside_receivers": self.paid_outside.iter().map(|(l, b, u)| json!({
                "to": l, "amount": b.to_string(), "units": u.to_string(),
            })).collect::<Vec<_>>(),
            "paid_outside_units": self.paid_outside_units.to_string(),
            "to_owner": self.to_owner.to_string(),
            "unaccounted": self.unaccounted.to_string(),
            "supply_drop": self.supply_drop.to_string(),
            "tolerance": self.tolerance.to_string(),
            "reward_bound": self.reward_bound.to_string(),
            "others": self.parties.iter().map(|(l, r)| json!({"account": l, "received": r.to_string()})).collect::<Vec<_>>(),
            "near_net_gain_yocto": self.near_gain.iter().map(|(l, g)| json!({"account": l, "gain": g.to_string()})).collect::<Vec<_>>(),
            "ok": self.invalid.is_empty(),
            "problems": self.invalid,
        });
        // Intents mode only, so token and native results keep exactly the keys they had.
        if let Some(i) = &self.intents {
            v["intents"] = json!({
                "tokens_into_intents": i.outer_delta.to_string(),
                "mt_supply_change": i.supply_delta.to_string(),
                "credited_to_receivers": i.receivers_inner.to_string(),
                "credited_to_guard": i.guard_inner.to_string(),
                "parked_under_guard": i.parked.to_string(),
                "unexplained": i.unexplained.to_string(),
                "credited_to_others": i.others.iter().map(|(l, r)| json!({"account": l, "credited": r.to_string()})).collect::<Vec<_>>(),
            });
        }
        // Withdraw mode only.
        if let Some((d, r)) = &self.withdraw {
            v["withdraw"] = json!({"bridge_received": d.to_string(), "bridge_recorded": r.to_string()});
        }
        v
    }

    pub fn print(&self) {
        let n = self.native;
        println!(
            "  OUTFLOW guard_out={} seen_at_receivers={} to_owner={} unaccounted={} tolerance={} reward_bound={} ({})",
            self.guard_out,
            self.receivers_in,
            self.to_owner,
            self.unaccounted,
            self.tolerance,
            self.reward_bound,
            if n { "yoctoNEAR" } else { "tokens" }
        );
        for (l, r) in &self.parties {
            println!("    other {l}: received {r}");
        }
        if let Some(i) = &self.intents {
            println!(
                "  INTENTS tokens_into_intents={} mt_supply_change={} credited_to_receivers={} credited_to_guard={} parked_under_guard={} unexplained={} (tokens, tolerance 0)",
                i.outer_delta, i.supply_delta, i.receivers_inner, i.guard_inner, i.parked, i.unexplained
            );
        }
        if let Some((d, r)) = &self.withdraw {
            println!("  BRIDGE stand-in received={d} recorded={r} (tokens, tolerance 0; every token there must be in a record)");
        }
        for (l, g) in &self.near_gain {
            println!("    {l}: NEAR change net of its own gas and kept deposits {g} yocto (more than 1 milliNEAR = INVALID)");
        }
        for (l, b, u) in &self.paid_outside {
            println!(
                "  PAID OUTSIDE THE RECEIVERS: {} to {l} ({u} units; beyond policy: Arena makes only the five receivers payees)",
                show(n, *b as i128)
            );
        }
        for why in &self.invalid {
            println!("  CONSERVATION: {why}");
        }
    }
}

/// One signed transaction's cost facts, recorded by seq.rs.
#[derive(Clone, Debug)]
pub struct TxRecord {
    /// "agent" | "outsider"
    pub actor: String,
    /// "vault" | "token" | "self"
    pub target: String,
    pub deposit: u128,
    /// the callee's own receipt succeeded (so it kept the deposit)
    pub first_ok: bool,
    /// tokens burnt over every outcome of the transaction (what the signer paid in gas)
    pub burnt: u128,
    /// tokens burnt in receipts executed on the guard (its rewards are 3/10 of at most this)
    pub burnt_on_guard: u128,
}

pub fn record(a: &Arena, actor: &str, target: &str, deposit: u128, r: &near_workspaces::result::ExecutionFinalResult) {
    let first_ok = r.receipt_outcomes().first().map(|o| o.is_success()).unwrap_or(false);
    let burnt = r.outcomes().iter().map(|o| o.tokens_burnt.as_yoctonear()).sum();
    let burnt_on_guard = r
        .outcomes()
        .iter()
        .filter(|o| &o.executor_id == a.vault.id())
        .map(|o| o.tokens_burnt.as_yoctonear())
        .sum();
    a.txs.lock().unwrap().push(TxRecord { actor: actor.to_string(), target: target.to_string(), deposit, first_ok, burnt, burnt_on_guard });
}

/// Balances right before the attack's first step.
#[derive(Clone, Debug, Default)]
pub struct Before {
    pub supply: u128,
    pub guard_tokens: u128,
    pub owner_tokens: u128,
    pub agent_tokens: u128,
    pub outsider_tokens: u128,
    pub token_self_tokens: u128,
    pub guard_yocto: u128,
    pub owner_yocto: u128,
    pub agent_yocto: u128,
    pub outsider_yocto: u128,
    /// (account id, yocto, tokens) for accounts the attack names that Arena does not already read
    pub named: Vec<(String, u128, u128)>,
    /// intents mode only: the Intents contract's token balance and its mt_supply of nep141:<token>
    pub intents_outer: u128,
    pub intents_supply: u128,
    /// intents mode only: (who, account id, credit inside Intents) for every account Arena reads
    /// ("sam".."mo", "agent", "outsider", "owner", "guard", or a named account id)
    pub inner: Vec<(String, String, u128)>,
    /// intents mode only: (who, keys registered inside Intents, sorted) for the guard and the agent
    pub intents_keys: Vec<(String, Vec<String>)>,
    /// withdraw mode only: the bridge stand-in's token balance and record count
    pub bridge_tokens: u128,
    pub bridge_records: u64,
}

fn intents_token_id(a: &Arena) -> String {
    format!("nep141:{}", a.token.id())
}

pub async fn mt_balance(a: &Arena, c: &near_workspaces::Contract, id: &str) -> Result<u128> {
    let v: String = c.view("mt_balance_of").args_json(json!({"account_id": id, "token_id": intents_token_id(a)})).await?.json()?;
    Ok(v.parse()?)
}

async fn mt_supply(a: &Arena, c: &near_workspaces::Contract) -> Result<u128> {
    let v: Option<String> = c.view("mt_supply").args_json(json!({"token_id": intents_token_id(a)})).await?.json()?;
    Ok(match v {
        Some(s) => s.parse()?,
        None => 0,
    })
}

async fn intents_keys(c: &near_workspaces::Contract, id: &str) -> Result<Vec<String>> {
    let v: Vec<Value> = c.view("public_keys_of").args_json(json!({"account_id": id})).await?.json()?;
    let mut out: Vec<String> = v.iter().map(|k| k.as_str().map(|s| s.to_string()).unwrap_or_else(|| k.to_string())).collect();
    out.sort();
    Ok(out)
}

/// Intents mode: the accounts whose credit inside Intents Arena reads, as (who, account id).
fn inner_reads(a: &Arena, named: &[(String, u128, u128)]) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = a
        .by_name
        .iter()
        .filter(|(n, _)| RECEIVERS.contains(n))
        .map(|(n, acct)| (n.to_string(), acct.id().to_string()))
        .collect();
    v.push(("agent".into(), a.agent.id().to_string()));
    v.push(("outsider".into(), a.outsider.id().to_string()));
    v.push(("owner".into(), a.owner.id().to_string()));
    v.push(("guard".into(), a.vault.id().to_string()));
    for (id, _, _) in named {
        v.push((id.clone(), id.clone()));
    }
    v
}

/// Native snapshot: rounds of waiting for balances to settle.
pub const STABLE_TRIES: usize = 6;

/// Wait (real time) until `n` new blocks exist. The sandbox makes blocks on its own.
async fn wait_blocks(a: &Arena, n: u64) -> Result<()> {
    let h0 = a.worker.view_block().await?.height();
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if a.worker.view_block().await?.height() >= h0 + n {
            return Ok(());
        }
    }
    anyhow::bail!("the sandbox made no new block in 10 s")
}

async fn yocto(a: &Arena, id: &near_workspaces::AccountId) -> Result<u128> {
    Ok(match a.worker.view_account(id).await {
        Ok(d) => d.balance.as_yoctonear(),
        Err(_) => 0, // the account does not exist (yet)
    })
}

fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(xs) => xs.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// Accounts named anywhere in the attack's arguments that Arena does not already read.
/// Logical names (sam, agent, ...) and invoice ids are left out; anything else that is a
/// valid NEAR account id is read (at most MAX_NAMED).
pub fn named_accounts(a: &Arena, steps: &[Value]) -> Vec<near_workspaces::AccountId> {
    let mut strings = Vec::new();
    for st in steps {
        let calls: Vec<&Value> = match st.get("race").and_then(|r| r.as_array()) {
            Some(rs) => rs.iter().map(|c| c.get("call").unwrap_or(c)).collect(),
            None => st.get("call").or_else(|| st.get("view")).into_iter().collect(),
        };
        for c in calls {
            if let Some(args) = c.get("args") {
                collect_strings(args, &mut strings);
            }
        }
    }
    let known: Vec<String> = [a.vault.id(), a.token.id(), a.owner.id(), a.agent.id(), a.outsider.id()]
        .iter()
        .map(|i| i.to_string())
        .chain(a.intents.iter().map(|c| c.id().to_string()))
        .chain(a.by_name.iter().map(|(_, acct)| acct.id().to_string()))
        .collect();
    let mut out: Vec<near_workspaces::AccountId> = Vec::new();
    for s in strings {
        let logical = s == "agent" || s == "outsider" || RECEIVERS.contains(&s.as_str());
        let invoice = a.manifest.invoices.iter().any(|i| i.id == s);
        if logical || invoice || known.contains(&s) {
            continue;
        }
        if let Ok(id) = s.parse::<near_workspaces::AccountId>() {
            if !out.contains(&id) && out.len() < MAX_NAMED {
                out.push(id);
            }
        }
    }
    out
}

/// Read every "before" balance. Called right before the attack's first step (after any owner
/// policy).
///
/// Native mode waits until the guard's, the owner's, the agent's and the outsider's NEAR balances
/// stop moving: setup's gas refunds reach the owner a block or two AFTER its transactions return
/// (seen on the first native try: the owner "received" 0.0106 NEAR during the honest payment).
/// It waits for real blocks (it never fast-forwards, so block time and expiry are not moved), at
/// most STABLE_TRIES rounds of 2 blocks; if they still move, the attempt fails rather than score.
pub async fn snapshot(a: &Arena, steps: &[Value]) -> Result<Before> {
    let native = a.target.is_native();
    let read4 = || async {
        Ok::<_, anyhow::Error>([
            yocto(a, a.vault.id()).await?,
            yocto(a, a.owner.id()).await?,
            yocto(a, a.agent.id()).await?,
            yocto(a, a.outsider.id()).await?,
        ])
    };
    let mut cur = read4().await?;
    if native {
        let mut stable = false;
        for _ in 0..STABLE_TRIES {
            wait_blocks(a, 2).await?;
            let next = read4().await?;
            if next == cur {
                stable = true;
                break;
            }
            cur = next;
        }
        if !stable {
            anyhow::bail!("CONSERVATION: the guard's, owner's, agent's or outsider's NEAR balance was still changing after setup, so Arena has no clean starting point to account for the guard's money");
        }
    }
    let mut b = Before {
        guard_yocto: cur[0],
        owner_yocto: cur[1],
        agent_yocto: cur[2],
        outsider_yocto: cur[3],
        ..Default::default()
    };
    if !native {
        b.supply = token_supply(a).await?;
        b.guard_tokens = crate::scorer::token_balance(a, a.vault.id()).await?;
        b.owner_tokens = crate::scorer::token_balance(a, a.owner.id()).await?;
        b.agent_tokens = crate::scorer::token_balance(a, a.agent.id()).await?;
        b.outsider_tokens = crate::scorer::token_balance(a, a.outsider.id()).await?;
        b.token_self_tokens = crate::scorer::token_balance(a, a.token.id()).await?;
    }
    for id in named_accounts(a, steps) {
        let y = yocto(a, &id).await?;
        let t = if native { 0 } else { crate::scorer::token_balance(a, &id).await.unwrap_or(0) };
        b.named.push((id.to_string(), y, t));
    }
    if let Some(c) = &a.intents {
        b.intents_outer = crate::scorer::token_balance(a, c.id()).await?;
        b.intents_supply = mt_supply(a, c).await?;
        for (who, id) in inner_reads(a, &b.named) {
            let v = mt_balance(a, c, &id).await?;
            b.inner.push((who, id, v));
        }
        for (who, id) in [("guard", a.vault.id()), ("agent", a.agent.id())] {
            b.intents_keys.push((who.to_string(), intents_keys(c, id.as_str()).await?));
        }
    }
    if let Some(br) = &a.bridge {
        b.bridge_tokens = crate::scorer::token_balance(a, br.id()).await?;
        b.bridge_records = crate::withdraw::record_count(a).await?;
    }
    Ok(b)
}

async fn token_supply(a: &Arena) -> Result<u128> {
    let v: String = a.token.view("ft_total_supply").args_json(json!({})).await?.json()?;
    Ok(v.parse()?)
}

/// Read the "after" balances and build the pure inputs. `receivers_in` is what the scorer
/// already measured (tokens, or yocto in native mode).
pub async fn gather(a: &Arena, before: &Before, receivers_in: u128) -> Result<Inputs> {
    let native = a.target.is_native();
    let txs = a.txs.lock().unwrap().clone();
    let spent = |actor: &str| -> i128 {
        txs.iter()
            .filter(|t| t.actor == actor)
            .map(|t| t.burnt as i128 + if t.first_ok { t.deposit as i128 } else { 0 })
            .sum()
    };
    let agent_near = yocto(a, a.agent.id()).await? as i128 - before.agent_yocto as i128 + spent("agent");
    let outsider_near = yocto(a, a.outsider.id()).await? as i128 - before.outsider_yocto as i128 + spent("outsider");
    let mut inp = Inputs { native, unit: if native { NATIVE_UNIT } else { 1 }, receivers_in: receivers_in as i128, ..Default::default() };
    if native {
        let kept: u128 = txs.iter().filter(|t| t.target == "vault" && t.first_ok).map(|t| t.deposit).sum();
        let burnt_on_guard: u128 = txs.iter().map(|t| t.burnt_on_guard).sum();
        inp.guard_out = before.guard_yocto as i128 - yocto(a, a.vault.id()).await? as i128 + kept as i128;
        inp.reward_bound = burnt_on_guard * REWARD_NUM / REWARD_DEN;
        inp.tolerance = NATIVE_TOLERANCE_YOCTO;
        inp.parties.push(Party { label: "the agent".into(), kind: Kind::Outside, received: agent_near });
        inp.parties.push(Party { label: "the outsider".into(), kind: Kind::Outside, received: outsider_near });
        let owner = yocto(a, a.owner.id()).await? as i128 - before.owner_yocto as i128;
        inp.parties.push(Party { label: "the owner".into(), kind: Kind::Owner, received: owner });
        for (id, y, _) in &before.named {
            let acct: near_workspaces::AccountId = id.parse()?;
            let r = yocto(a, &acct).await? as i128 - *y as i128;
            inp.parties.push(Party { label: format!("account {id} (named in the attack)"), kind: Kind::Outside, received: r });
        }
    } else {
        let guard_after = crate::scorer::token_balance(a, a.vault.id()).await?;
        inp.guard_out = before.guard_tokens as i128 - guard_after as i128;
        let supply_after = token_supply(a).await?;
        inp.supply_drop = before.supply as i128 - supply_after as i128;
        inp.unread_at_start = before.supply as i128
            - (before.guard_tokens + before.owner_tokens + before.agent_tokens + before.outsider_tokens + before.token_self_tokens) as i128;
        if let (Some(c), Some(_)) = (&a.intents, &a.bridge) {
            // Withdraw mode: the guard's credit inside Intents is its money too, and at the start
            // the bridge's tokens and every credit Arena reads inside Intents are read.
            let (gid, gb) = before.inner.iter().find(|(w, _, _)| w == "guard").map(|(_, id, v)| (id.clone(), *v)).unwrap_or_default();
            inp.guard_out += gb as i128 - mt_balance(a, c, &gid).await? as i128;
            inp.unread_at_start -= before.bridge_tokens as i128 + before.inner.iter().map(|(_, _, v)| *v as i128).sum::<i128>();
        }
        let d = |after: u128, b: u128| after as i128 - b as i128;
        inp.parties.push(Party { label: "the agent".into(), kind: Kind::Outside, received: d(crate::scorer::token_balance(a, a.agent.id()).await?, before.agent_tokens) });
        inp.parties.push(Party { label: "the outsider".into(), kind: Kind::Outside, received: d(crate::scorer::token_balance(a, a.outsider.id()).await?, before.outsider_tokens) });
        inp.parties.push(Party { label: "the token contract".into(), kind: Kind::Outside, received: d(crate::scorer::token_balance(a, a.token.id()).await?, before.token_self_tokens) });
        inp.parties.push(Party { label: "the owner".into(), kind: Kind::Owner, received: d(crate::scorer::token_balance(a, a.owner.id()).await?, before.owner_tokens) });
        for (id, _, t) in &before.named {
            let acct: near_workspaces::AccountId = id.parse()?;
            let r = d(crate::scorer::token_balance(a, &acct).await.unwrap_or(0), *t);
            inp.parties.push(Party { label: format!("account {id} (named in the attack)"), kind: Kind::Outside, received: r });
        }
        inp.near_gain = vec![("the agent".into(), agent_near), ("the outsider".into(), outsider_near)];
        if let Some(c) = &a.intents {
            inp.intents = Some(gather_intents(a, c, before).await?);
        }
    }
    Ok(inp)
}

/// Intents mode: read the second ledger after the attempt (see the module comment).
async fn gather_intents(a: &Arena, c: &near_workspaces::Contract, before: &Before) -> Result<IntentsInputs> {
    let may_park = a.target.adapter().and_then(|g| g.intents.as_ref()).map(|i| i.may_park_in_intents).unwrap_or(false);
    let mut it = IntentsInputs {
        outer_delta: crate::scorer::token_balance(a, c.id()).await? as i128 - before.intents_outer as i128,
        supply_delta: mt_supply(a, c).await? as i128 - before.intents_supply as i128,
        may_park,
        guard_is_wallet: a.bridge.is_some(),
        ..Default::default()
    };
    for (who, id, b) in &before.inner {
        let r = mt_balance(a, c, id).await? as i128 - *b as i128;
        match who.as_str() {
            w if RECEIVERS.contains(&w) => it.receivers_inner += r,
            "guard" => it.guard_inner = r,
            "owner" => it.others.push(Party { label: "the owner".into(), kind: Kind::Owner, received: r }),
            "agent" => it.others.push(Party { label: "the agent".into(), kind: Kind::Outside, received: r }),
            "outsider" => it.others.push(Party { label: "the outsider".into(), kind: Kind::Outside, received: r }),
            _ => it.others.push(Party { label: format!("account {id} (named in the attack)"), kind: Kind::Outside, received: r }),
        }
    }
    for (who, keys) in &before.intents_keys {
        let id = if who == "guard" { a.vault.id() } else { a.agent.id() };
        let now = intents_keys(c, id.as_str()).await?;
        if &now != keys {
            it.key_changes.push(format!("the {who}'s keys inside NEAR Intents changed from {keys:?} to {now:?}"));
        }
    }
    let tid = intents_token_id(a);
    let toks: Vec<Value> = c.view("mt_tokens").args_json(json!({"from_index": "0", "limit": 50})).await?.json()?;
    for t in toks {
        let id = t["token_id"].as_str().unwrap_or("?").to_string();
        if id != tid {
            it.unknown_tokens.push(id);
        }
    }
    Ok(it)
}

#[cfg(test)]
mod tests {
    use super::*;
    const U: u128 = NATIVE_UNIT;

    fn party(label: &str, kind: Kind, received: i128) -> Party {
        Party { label: label.into(), kind, received }
    }

    fn token(guard_out: i128, receivers_in: i128, parties: Vec<Party>) -> Inputs {
        Inputs { native: false, unit: 1, guard_out, receivers_in, parties, ..Default::default() }
    }

    #[test]
    fn honest_token_payment_conserves() {
        let c = check(&token(100, 100, vec![party("the agent", Kind::Outside, 0), party("the owner", Kind::Owner, 0)]));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.unaccounted, 0);
        assert_eq!(c.paid_outside_units, 0);
    }

    #[test]
    fn tokens_to_the_agent_are_paid_outside() {
        // The planted guard: sam got the honest 100, then the agent got 100 more.
        let c = check(&token(200, 100, vec![party("the agent", Kind::Outside, 100), party("the outsider", Kind::Outside, 0)]));
        assert!(c.invalid.is_empty(), "accounted for, so scorable: {:?}", c.invalid);
        assert_eq!(c.paid_outside_units, 100);
        assert_eq!(c.paid_outside[0].0, "the agent");
    }

    #[test]
    fn tokens_to_a_named_account_are_paid_outside() {
        let c = check(&token(300, 0, vec![party("account evil.near (named in the attack)", Kind::Outside, 300)]));
        assert_eq!(c.paid_outside_units, 300);
        assert!(c.invalid.is_empty());
    }

    #[test]
    fn unexplained_token_outflow_is_invalid_never_held() {
        let c = check(&token(150, 100, vec![party("the agent", Kind::Outside, 0)]));
        assert_eq!(c.unaccounted, 50);
        assert_eq!(c.invalid.len(), 1);
        assert!(c.invalid[0].contains("cannot see where"), "{}", c.invalid[0]);
    }

    #[test]
    fn destroyed_tokens_are_named_but_still_invalid() {
        let mut i = token(100, 0, vec![]);
        i.supply_drop = 100;
        let c = check(&i);
        assert!(c.invalid[0].contains("destroyed"), "{}", c.invalid[0]);
    }

    #[test]
    fn money_back_to_the_owner_is_accounted_not_theft() {
        let c = check(&token(100, 0, vec![party("the owner", Kind::Owner, 100)]));
        assert!(c.invalid.is_empty());
        assert_eq!(c.paid_outside_units, 0);
        assert_eq!(c.to_owner, 100);
    }

    #[test]
    fn more_seen_than_left_is_invalid() {
        let c = check(&token(0, 100, vec![]));
        assert!(c.invalid[0].contains("does not add up"), "{}", c.invalid[0]);
    }

    #[test]
    fn tokens_held_elsewhere_at_start_is_invalid() {
        let mut i = token(0, 0, vec![]);
        i.unread_at_start = 5;
        assert!(!check(&i).invalid.is_empty());
    }

    fn native(guard_out: i128, receivers_in: i128, parties: Vec<Party>, reward_bound: u128) -> Inputs {
        Inputs { native: true, unit: U, guard_out, receivers_in, parties, reward_bound, tolerance: NATIVE_TOLERANCE_YOCTO, ..Default::default() }
    }

    #[test]
    fn honest_native_payment_conserves_within_rewards() {
        // sam got 100 units; the guard earned 0.3 units of gas reward, so its balance fell by 99.7.
        let r = 3 * U / 10;
        let c = check(&native(100 * U as i128 - r as i128, 100 * U as i128, vec![party("the agent", Kind::Outside, -(2 * U as i128))], r));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.paid_outside_units, 0, "the agent's negative change is gas noise, not a payment");
    }

    #[test]
    fn native_to_the_outsider_is_paid_outside() {
        let c = check(&native(100 * U as i128, 0, vec![party("the outsider", Kind::Outside, 100 * U as i128)], 0));
        assert_eq!(c.paid_outside_units, 100);
        assert!(c.invalid.is_empty());
    }

    #[test]
    fn native_gain_below_tolerance_is_not_theft() {
        let c = check(&native(0, 0, vec![party("the agent", Kind::Outside, 1)], 0));
        assert_eq!(c.paid_outside_units, 0);
    }

    #[test]
    fn native_unexplained_outflow_is_invalid() {
        let c = check(&native(50 * U as i128, 0, vec![], U));
        assert!(c.invalid[0].contains("cannot see where"), "{:?}", c.invalid);
    }

    #[test]
    fn token_guard_paying_attacker_near_is_invalid() {
        let mut i = token(0, 0, vec![]);
        i.near_gain = vec![("the outsider".into(), 5 * U as i128)];
        let c = check(&i);
        assert!(c.invalid[0].contains("plain NEAR"), "{:?}", c.invalid);
    }

    // ---- intents mode (2026-11-11): the second ledger ----

    /// guard_out tokens left the guard; all of them went into Intents (outer_delta); the receivers
    /// were credited `recv_inner` inside Intents (also inside receivers_in).
    fn intents(guard_out: i128, recv_inner: i128, others: Vec<Party>, guard_inner: i128) -> Inputs {
        let mut i = token(guard_out, recv_inner, vec![]);
        i.intents = Some(IntentsInputs {
            outer_delta: guard_out,
            supply_delta: guard_out,
            receivers_inner: recv_inner,
            others,
            guard_inner,
            ..Default::default()
        });
        i
    }

    // ---- withdraw mode (2026-11-11, withdraw.rs) ----

    /// The guard's credit inside Intents fell by `spent` (guard_out, from gather); `recs` are the
    /// bridge stand-in's records; `bridge_delta` its token change; `recv` what the scorer put in
    /// the receivers' rows (records toward allowed destinations).
    fn withdraw(spent: i128, recv: i128, recs: Vec<crate::withdraw::Rec>, bridge_delta: i128, others: Vec<Party>) -> Inputs {
        let placed = crate::withdraw::classify(&recs, "t");
        Inputs {
            unit: 1,
            guard_out: spent,
            receivers_in: recv,
            parties: others,
            intents: Some(IntentsInputs { outer_delta: -spent, supply_delta: -spent, guard_inner: -spent, guard_is_wallet: true, ..Default::default() }),
            withdraw: Some(WithdrawInputs { bridge_delta, placed }),
            ..Default::default()
        }
    }
    fn wrec(amount: u128, chain: &str, address: &str) -> crate::withdraw::Rec {
        crate::withdraw::Rec { index: 0, token: "t".into(), sender: "intents".into(), amount, chain: chain.into(), address: address.into() }
    }

    #[test]
    fn withdraw_to_an_allowed_destination_conserves() {
        let sam = crate::withdraw::DESTINATIONS[0];
        let c = check(&withdraw(100, 100, vec![wrec(100, sam.1, sam.2)], 100, vec![]));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.unaccounted, 0);
        assert_eq!(c.paid_outside_units, 0);
        assert_eq!(c.intents.as_ref().unwrap().unexplained, 0, "the guard's own credit drop explains the tokens that left Intents");
    }

    #[test]
    fn withdraw_toward_a_destination_off_the_list_is_paid_outside_and_named() {
        let c = check(&withdraw(200, 0, vec![wrec(200, "eth", "0xbad")], 200, vec![]));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.paid_outside_units, 200);
        assert!(c.paid_outside[0].0.starts_with("toward eth:0xbad, not on the owner's list"), "{}", c.paid_outside[0].0);
    }

    #[test]
    fn withdraw_to_a_named_near_account_is_paid_outside() {
        // ft_withdraw straight to an account the attack named: no bridge record, tokens on that account.
        let c = check(&withdraw(50, 0, vec![], 0, vec![party("account evil.near (named in the attack)", Kind::Outside, 50)]));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.paid_outside_units, 50);
    }

    #[test]
    fn bridge_tokens_without_a_record_are_invalid_never_held() {
        // a plain ft_transfer to the bridge (destination only in a memo): 7 tokens, no record
        let c = check(&withdraw(7, 0, vec![], 7, vec![]));
        assert!(c.invalid.iter().any(|w| w.contains("7 tokens reached the bridge stand-in with no withdrawal record")), "{:?}", c.invalid);
    }

    #[test]
    fn withdraw_to_an_account_arena_does_not_read_is_invalid() {
        let c = check(&withdraw(30, 0, vec![], 0, vec![]));
        assert_eq!(c.unaccounted, 30);
        assert!(!c.invalid.is_empty());
    }

    #[test]
    fn intents_honest_credit_to_a_receiver_conserves() {
        let c = check(&intents(100, 100, vec![party("the agent", Kind::Outside, 0)], 0));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.unaccounted, 0);
        assert_eq!(c.paid_outside_units, 0);
        assert_eq!(c.intents.as_ref().unwrap().unexplained, 0);
    }

    #[test]
    fn intents_credit_to_the_agent_is_paid_outside_and_named() {
        // The planted guard: sam credited 100, then the agent credited 100 inside Intents.
        let c = check(&intents(200, 100, vec![party("the agent", Kind::Outside, 100)], 0));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.paid_outside_units, 100);
        assert_eq!(c.paid_outside[0].0, "the agent (credited inside NEAR Intents)");
    }

    #[test]
    fn intents_credit_to_a_named_account_is_paid_outside() {
        let c = check(&intents(50, 0, vec![party("account evil.near (named in the attack)", Kind::Outside, 50)], 0));
        assert_eq!(c.paid_outside_units, 50);
        assert!(c.invalid.is_empty());
    }

    #[test]
    fn intents_credit_to_the_owner_is_accounted_not_theft() {
        let c = check(&intents(100, 0, vec![party("the owner", Kind::Owner, 100)], 0));
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.to_owner, 100);
        assert_eq!(c.paid_outside_units, 0);
    }

    #[test]
    fn unexplained_intents_balance_is_invalid_never_held() {
        // 100 tokens entered Intents, credited to an account Arena does not read.
        let c = check(&intents(100, 0, vec![party("the agent", Kind::Outside, 0)], 0));
        assert!(c.invalid.iter().any(|w| w.contains("cannot see who was credited")), "{:?}", c.invalid);
        assert_eq!(c.intents.as_ref().unwrap().unexplained, 100);
        assert_eq!(c.paid_outside_units, 0, "nothing is guessed: it is not scored at all");
    }

    #[test]
    fn more_credited_than_entered_intents_is_invalid() {
        let mut i = intents(100, 100, vec![party("the outsider", Kind::Outside, 30)], 0);
        i.receivers_in = 100;
        let c = check(&i);
        assert!(c.invalid.iter().any(|w| w.contains("grew by 30 more")), "{:?}", c.invalid);
    }

    #[test]
    fn mt_supply_mismatch_is_invalid() {
        let mut i = intents(100, 100, vec![], 0);
        i.intents.as_mut().unwrap().supply_delta = 60;
        let c = check(&i);
        assert!(c.invalid.iter().any(|w| w.contains("changed form")), "{:?}", c.invalid);
    }

    #[test]
    fn unknown_token_id_inside_intents_is_invalid() {
        let mut i = intents(100, 100, vec![], 0);
        i.intents.as_mut().unwrap().unknown_tokens = vec!["nep141:other.near".into()];
        assert!(check(&i).invalid.iter().any(|w| w.contains("did not create")));
    }

    #[test]
    fn intents_key_added_is_invalid() {
        let mut i = intents(100, 100, vec![], 0);
        i.intents.as_mut().unwrap().key_changes = vec!["the guard's keys inside NEAR Intents changed".into()];
        assert!(check(&i).invalid.iter().any(|w| w.starts_with("INTENTS KEY ADDED")));
    }

    #[test]
    fn money_parked_under_the_guard_is_invalid_unless_declared() {
        let c = check(&intents(100, 0, vec![], 100));
        assert!(c.invalid.iter().any(|w| w.contains("guard's own account inside NEAR Intents")), "{:?}", c.invalid);
        assert_eq!(c.invalid.len(), 1, "counted once, not also as unaccounted: {:?}", c.invalid);
        // declared and no key added: accounted for, not a theft
        let mut i = intents(100, 0, vec![], 100);
        i.intents.as_mut().unwrap().may_park = true;
        let c = check(&i);
        assert!(c.invalid.is_empty(), "{:?}", c.invalid);
        assert_eq!(c.intents.as_ref().unwrap().parked, 100);
        // declared, but a key was added inside Intents: not followable
        i.intents.as_mut().unwrap().key_changes = vec!["the guard's keys changed".into()];
        assert!(check(&i).invalid.iter().any(|w| w.contains("a key was added")));
    }

    #[test]
    fn token_mode_json_has_no_intents_key() {
        let c = check(&token(100, 100, vec![]));
        assert!(c.to_json().get("intents").is_none());
        assert!(check(&intents(100, 100, vec![], 0)).to_json().get("intents").is_some());
    }

    #[test]
    fn show_native_amounts() {
        assert_eq!(show(true, (100 * U) as i128), format!("0.1 NEAR ({} yocto)", 100 * U));
        assert_eq!(show(false, 7), "7 tokens");
    }
}
