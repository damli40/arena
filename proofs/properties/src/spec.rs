//! The five properties, as plain functions over a ledger of payments.
//!
//! A harness (yours) records every payment your guard actually sent, read from the
//! receipts your contract created, never from the guard's own counters. Each property
//! then reads only that ledger and the policy you declared. `Ok(())` = kept.

use std::collections::{BTreeMap, BTreeSet};

/// One payment your guard started, as the harness saw it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Payment {
    /// Invoice or payment id, if the guard has one.
    pub id: Option<String>,
    /// The account that asked for it: the agent, or someone else.
    pub by_agent: bool,
    pub to: String,
    pub amount: u128,
    /// The window (e.g. UTC day) the request was made in.
    pub window: u64,
    /// The owner approved this one by hand (a held payment).
    pub owner_approved: bool,
    /// The money arrived (transfer succeeded). Only delivered payments count.
    pub delivered: bool,
}

/// What the owner allowed. Leave a rule `None` if your guard does not claim it.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Payees the agent may pay. Owner-approved payments are the owner's call.
    pub payees: Option<BTreeSet<String>>,
    pub per_payment_cap: Option<u128>,
    /// Per window, for agent payments without owner approval.
    pub window_cap: Option<u128>,
    /// Above this, a payment must wait for the owner.
    pub approval_threshold: Option<u128>,
    /// id -> (receiver, amount), for invoice guards.
    pub invoices: Option<BTreeMap<String, (String, u128)>>,
}

fn delivered(l: &[Payment]) -> impl Iterator<Item = &Payment> {
    l.iter().filter(|p| p.delivered)
}

/// no-double-pay: an id never delivers more than once, nor more than its invoice says.
pub fn no_double_pay(l: &[Payment], pol: &Policy) -> Result<(), String> {
    let mut per_id: BTreeMap<&str, (u32, u128)> = BTreeMap::new();
    for p in delivered(l) {
        let Some(id) = &p.id else { continue };
        let e = per_id.entry(id).or_default();
        e.0 += 1;
        e.1 += p.amount;
        let limit = pol.invoices.as_ref().and_then(|m| m.get(id.as_str())).map(|v| v.1);
        if e.0 > 1 || limit.is_some_and(|lim| e.1 > lim) {
            return Err(format!("id {id} delivered {} times, {} in total", e.0, e.1));
        }
    }
    Ok(())
}

/// payee-list-only: the agent's payments reach only listed payees (or the invoice's receiver).
pub fn payee_list_only(l: &[Payment], pol: &Policy) -> Result<(), String> {
    for p in delivered(l).filter(|p| !p.owner_approved) {
        let listed = pol.payees.as_ref().is_none_or(|s| s.contains(&p.to));
        let invoiced = match (&pol.invoices, &p.id) {
            (Some(m), Some(id)) => m.get(id).is_some_and(|v| v.0 == p.to),
            (Some(_), None) => false,
            (None, _) => true,
        };
        if !p.by_agent || !listed || !invoiced {
            return Err(format!("{} paid to {} (by agent: {})", p.amount, p.to, p.by_agent));
        }
    }
    Ok(())
}

/// never-beyond-cap: no single payment above the per-payment cap, approved or not.
pub fn never_beyond_cap(l: &[Payment], pol: &Policy) -> Result<(), String> {
    let Some(cap) = pol.per_payment_cap else { return Ok(()) };
    match delivered(l).find(|p| p.amount > cap) {
        Some(p) => Err(format!("one payment of {} > cap {cap}", p.amount)),
        None => Ok(()),
    }
}

/// approval-threshold: above the threshold, nothing is paid unless the owner approved it.
pub fn approval_threshold(l: &[Payment], pol: &Policy) -> Result<(), String> {
    let Some(t) = pol.approval_threshold else { return Ok(()) };
    match delivered(l).find(|p| p.amount > t && !p.owner_approved) {
        Some(p) => Err(format!("{} > threshold {t} paid without approval", p.amount)),
        None => Ok(()),
    }
}

/// window-budget: per window, the agent's unapproved payments add up to at most the cap.
pub fn window_budget(l: &[Payment], pol: &Policy) -> Result<(), String> {
    let Some(cap) = pol.window_cap else { return Ok(()) };
    let mut per: BTreeMap<u64, u128> = BTreeMap::new();
    for p in delivered(l).filter(|p| !p.owner_approved) {
        *per.entry(p.window).or_default() += p.amount;
    }
    match per.into_iter().find(|&(_, sum)| sum > cap) {
        Some((w, sum)) => Err(format!("window {w}: {sum} > cap {cap}")),
        None => Ok(()),
    }
}

pub type Property = fn(&[Payment], &Policy) -> Result<(), String>;

/// Every property, by name. A harness checks the ones its guard claims.
pub const ALL: [(&str, Property); 5] = [
    ("no-double-pay", no_double_pay),
    ("payee-list-only", payee_list_only),
    ("never-beyond-cap", never_beyond_cap),
    ("approval-threshold", approval_threshold),
    ("window-budget", window_budget),
];
