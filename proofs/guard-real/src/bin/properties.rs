//! Arena's own guard (contracts/guard, real source) checked against the shared property
//! library (proofs/properties). This file is the whole harness: it adapts the existing
//! world in src/lib.rs to the library's `World` trait and declares the policy.
//!
//!   cargo run --release --bin properties -- <N pays> [full]
//!   cargo run --release --features mutant --bin properties -- 3          # must break no-double-pay
//!   `-- 2 full` (dead callbacks, reconcile, outside transfers) also works, but did not finish in
//!   100 minutes on our loaded machine; proofs/run.sh proof1 covers that world with exhaustive.rs.
//!
//! Applies: no-double-pay (each invoice delivers once, at most its amount). The guard has
//! no payee list beyond each invoice's receiver, no per-payment cap, no approval threshold
//! and no daily budget, so the other four do not apply. (A transfer to any account other
//! than the invoice's receiver already stops the run: src/lib.rs, Item::Transfer.)
use arena_properties::{explore, print, Payment, Policy};
use guard_proofs::*;
use std::hash::{Hash, Hasher};

#[derive(Clone)]
struct W(World);

impl arena_properties::World for W {
    type Step = (usize, String, Choice);
    fn steps(&self) -> Vec<Self::Step> {
        let w = &self.0;
        let d = Choice::default();
        let mut v = vec![];
        for idx in w.runnable() {
            // The same choices as src/bin/exhaustive.rs.
            let cs: Vec<Choice> = match w.pending[idx] {
                Item::Transfer { .. } => vec![Choice { ok: true, ..d }, Choice { ok: false, ..d }],
                Item::Callback { .. } if w.deaths_left > 0 => vec![d, Choice { dies: true, ..d }],
                Item::Reconcile => (0..NINV).flat_map(|inv| [true, false].map(|wait| Choice { inv, wait, ..d })).collect(),
                Item::Resolve => (0..NINV)
                    .flat_map(|inv| [true, false].into_iter().flat_map(move |sent| [true, false].map(move |wait| Choice { inv, sent, wait, ..d })))
                    .collect(),
                _ => vec![d],
            };
            for c in cs {
                v.push((idx, format!("{:?}", w.pending[idx]), c));
            }
        }
        v
    }
    fn apply(&mut self, s: &Self::Step) -> bool {
        self.0.step_with(s.0, s.2, None);
        true
    }
    fn key(&self) -> u128 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.0.key().hash(&mut h);
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        7u8.hash(&mut h2);
        self.0.key().hash(&mut h2);
        ((h.finish() as u128) << 64) | h2.finish() as u128
    }
    fn ledger(&self) -> Vec<Payment> {
        self.0
            .trace
            .iter()
            .filter_map(|e| match e {
                Event::TransferOk { inv, amount } => Some(Payment {
                    id: Some(INVOICES[*inv].0.into()),
                    by_agent: true,
                    to: INVOICES[*inv].1.into(),
                    amount: *amount,
                    window: 0,
                    owner_approved: false,
                    delivered: true,
                }),
                _ => None,
            })
            .collect()
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n: u32 = a.get(1).map(|s| s.parse().unwrap()).unwrap_or(3);
    let full = a.get(2).is_some_and(|s| s == "full");
    std::panic::set_hook(Box::new(|_| {})); // refused pays panic by design
    let policy = Policy { invoices: Some(INVOICES.iter().map(|&(id, to, amt)| (id.to_string(), (to.to_string(), amt))).collect()), ..Default::default() };
    let props = ["no-double-pay"];
    let build = if cfg!(feature = "mutant") { "mutant" } else if cfg!(feature = "mutant-reopen") { "mutant-reopen" } else { "real" };
    let t0 = std::time::Instant::now();
    let (mut states, mut broken) = (0, std::collections::BTreeMap::new());
    // Every choice of invoice for each of the N pay calls, as exhaustive.rs does.
    for combo in 0..(NINV as u32).pow(n) {
        let mut c = combo;
        let pays: Vec<usize> = (0..n).map(|_| { let v = (c % NINV as u32) as usize; c /= NINV as u32; v }).collect();
        let rep = explore(W(World::new_world(Mode::Fixed, &pays, full)), &policy, &props);
        states += rep.states;
        for (k, v) in rep.broken {
            broken.entry(k).or_insert(v);
        }
    }
    let rep = arena_properties::Report { states, broken };
    print(&rep, &props, &format!("guard=arena build={build} mode=fixed pays={n} world={}", if full { "full" } else { "base" }), t0.elapsed().as_secs_f64());
}
