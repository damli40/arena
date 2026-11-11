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
        json!({
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
        })
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
    }
    Ok(inp)
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

    #[test]
    fn show_native_amounts() {
        assert_eq!(show(true, (100 * U) as i128), format!("0.1 NEAR ({} yocto)", 100 * U));
        assert_eq!(show(false, 7), "7 tokens");
    }
}
