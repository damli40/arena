//! Arena's property library: five money properties for an AI agent's payment guard.
//!
//! `spec.rs` holds the properties: short functions over a ledger of payments.
//! This file holds the explorer: point it at a [`World`] (your guard plus a small
//! simulated chain) and it tries every reachable order of steps up to your bound, and
//! checks the properties you chose in every state it reaches.
//!
//! How to apply a property to your guard: `proofs/properties/README.md`.
pub mod spec;
pub use spec::{Payment, Policy, Property, ALL};
use std::collections::{BTreeMap, HashSet};

/// Your guard inside a small simulated world. One value = one situation.
pub trait World: Clone {
    type Step: std::fmt::Debug;
    /// Every step that could happen next (a request, a transfer outcome, a callback...).
    fn steps(&self) -> Vec<Self::Step>;
    /// Run one step. Return false to stop exploring this branch.
    fn apply(&mut self, s: &Self::Step) -> bool;
    /// Two situations with the same key behave the same from here on.
    fn key(&self) -> u128;
    /// Every payment your guard sent so far, read from its receipts.
    fn ledger(&self) -> Vec<Payment>;
}

#[derive(Debug, Default)]
pub struct Report {
    pub states: u64,
    /// property -> the earliest-found sequence of steps that breaks it
    pub broken: BTreeMap<String, (String, Vec<String>)>,
}

/// Stack-based search (follows one path to its end, then backs up), each distinct situation once, every chosen property checked in each.
pub fn explore<W: World>(start: W, policy: &Policy, props: &[&str]) -> Report {
    let chosen: Vec<_> = ALL.iter().filter(|(n, _)| props.contains(n)).collect();
    assert_eq!(chosen.len(), props.len(), "unknown property name in {props:?}");
    let mut rep = Report::default();
    let mut seen = HashSet::new();
    let mut stack = vec![(start, Vec::<String>::new())];
    while let Some((w, path)) = stack.pop() {
        if !seen.insert(w.key()) {
            continue;
        }
        rep.states += 1;
        let ledger = w.ledger();
        for (name, prop) in &chosen {
            if let Err(why) = prop(&ledger, policy) {
                rep.broken.entry(name.to_string()).or_insert((why, path.clone()));
            }
        }
        for s in w.steps() {
            let mut next = w.clone();
            let mut p = path.clone();
            p.push(format!("{s:?}"));
            if next.apply(&s) {
                stack.push((next, p));
            }
        }
    }
    rep
}

/// One line per property, then `PROPERTIES ... broken=[...]`.
pub fn print(rep: &Report, props: &[&str], what: &str, secs: f64) {
    for p in props {
        match rep.broken.get(*p) {
            None => println!("  {p:<20} holds"),
            Some((why, path)) => {
                println!("  {p:<20} BROKEN: {why}");
                for s in path {
                    println!("      {s}");
                }
            }
        }
    }
    let names: Vec<_> = rep.broken.keys().collect();
    println!("PROPERTIES {what} states={} secs={secs:.1} broken={names:?}", rep.states);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pay(id: &str, to: &str, amount: u128, window: u64) -> Payment {
        Payment { id: Some(id.into()), by_agent: true, to: to.into(), amount, window, owner_approved: false, delivered: true }
    }
    #[test]
    fn each_property_catches_its_own_flaw() {
        let pol = Policy {
            payees: Some(["sam".to_string()].into()),
            per_payment_cap: Some(100),
            window_cap: Some(150),
            approval_threshold: Some(80),
            invoices: None,
        };
        let ok = vec![pay("a", "sam", 80, 0), pay("b", "sam", 70, 0), pay("c", "sam", 80, 1)];
        for (n, p) in ALL {
            assert!(p(&ok, &pol).is_ok(), "{n} rejected an honest ledger");
        }
        let flawed = [
            ("no-double-pay", vec![pay("a", "sam", 50, 0), pay("a", "sam", 50, 0)]),
            ("payee-list-only", vec![pay("a", "eve", 50, 0)]),
            ("never-beyond-cap", vec![Payment { owner_approved: true, ..pay("a", "sam", 101, 0) }]),
            ("approval-threshold", vec![pay("a", "sam", 81, 0)]),
            ("window-budget", vec![pay("a", "sam", 80, 0), pay("b", "sam", 80, 0)]),
        ];
        for (name, ledger) in flawed {
            for (n, p) in ALL {
                assert_eq!(p(&ledger, &pol).is_err(), n == name, "{n} on the {name} ledger");
            }
        }
    }
}
