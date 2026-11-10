//! Exhaustive bounded check of the REAL guard: every schedule, every transfer outcome,
//! every choice of invoice per `pay`. Plain Rust, no solver: it runs each case.
//!
//!   cargo run --release --bin exhaustive -- <vulnerable_fixture|fixed> <N pays>
//!
//! Prints one summary line per property and the first counterexample trace, then
//! `RESULT mode=... n=... p1=HOLDS|FAILS p2=HOLDS|FAILS filter=AGREES|DISAGREES`.
use guard_proofs::*;

type Key = (Vec<(Vec<u8>, Vec<u8>)>, Vec<(u8, usize, String, u128, u8)>, [u128; NINV], guard_model::Model<NINV>);

#[derive(Default)]
struct Stats {
    seen: std::collections::HashSet<Key>,
    edges: u64,
    nodes: u64,
    leaves: u64,
    p1_violations: u64,
    p2_violations: u64,
    filter_checks: u64,
    filter_disagreements: u64,
    max_sent: [u128; NINV],
    first_p1: Option<(Vec<usize>, Vec<Event>, [u128; NINV])>,
    first_p2: Option<(Vec<usize>, Vec<Event>)>,
    model_mismatch_states: u64,
    first_mismatch: Option<(Vec<Event>, Vec<String>)>,
}

fn dfs(w: World, pays: &[usize], st: &mut Stats) {
    // Each distinct state is explored once (different orders often reach the same state).
    if !st.seen.insert(w.key()) {
        return;
    }
    st.nodes += 1;
    if !w.mismatches.is_empty() {
        st.model_mismatch_states += 1;
        if st.first_mismatch.is_none() {
            st.first_mismatch = Some((w.trace.clone(), w.mismatches.clone()));
        }
    }
    for i in 0..NINV {
        st.max_sent[i] = st.max_sent[i].max(w.sent[i]);
        if w.sent[i] > INVOICES[i].2 {
            st.p1_violations += 1;
            if st.first_p1.is_none() {
                st.first_p1 = Some((pays.to_vec(), w.trace.clone(), w.sent));
            }
            // Keep exploring: we report how many schedules fail, not just one.
        }
    }
    let runnable = w.runnable();
    if runnable.is_empty() {
        st.leaves += 1;
        for i in 0..NINV {
            let s = w.status(i);
            let ok = if w.sent[i] == 0 { s == Status::Approved } else { s == Status::Paid };
            // "Payable again" is checked for real: a fresh pay must be accepted.
            let payable_again = if w.sent[i] == 0 {
                let mut probe = w.clone();
                probe.pending.push(Item::Pay { inv: i });
                let idx = probe.pending.len() - 1;
                probe.step(idx, true, None);
                matches!(probe.trace.last(), Some(Event::PayAccepted { .. }))
            } else {
                true
            };
            if !(ok && payable_again) {
                st.p2_violations += 1;
                if st.first_p2.is_none() {
                    st.first_p2 = Some((pays.to_vec(), w.trace.clone()));
                }
            }
        }
        return;
    }
    for idx in runnable {
        let outcomes: &[bool] = match w.pending[idx] {
            Item::Transfer { .. } => &[true, false],
            _ => &[true],
        };
        for &ok in outcomes {
            st.edges += 1;
            let mut next = w.clone();
            if let Item::Pay { inv } = next.pending[idx] {
                let predicted = pay_would_be_accepted(next.mode, next.status(inv));
                next.step(idx, ok, None);
                let actual = matches!(next.trace.last(), Some(Event::PayAccepted { .. }));
                st.filter_checks += 1;
                if predicted != actual {
                    st.filter_disagreements += 1;
                }
            } else {
                next.step(idx, ok, None);
            }
            dfs(next, pays, st);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = match args.get(1).map(|s| s.as_str()) {
        Some("vulnerable_fixture") => Mode::VulnerableFixture,
        Some("fixed") => Mode::Fixed,
        _ => panic!("usage: exhaustive <vulnerable_fixture|fixed> <N>"),
    };
    let n: u32 = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(3);
    // Silence the guard's expected refusals (they are panics caught by the driver).
    std::panic::set_hook(Box::new(|_| {}));
    let t0 = std::time::Instant::now();
    let mut st = Stats::default();
    for combo in 0..(NINV as u32).pow(n) {
        let mut c = combo;
        let pays: Vec<usize> = (0..n).map(|_| { let v = (c % NINV as u32) as usize; c /= NINV as u32; v }).collect();
        let w = World::new(mode, &pays);
        dfs(w, &pays, &mut st);
    }
    let secs = t0.elapsed().as_secs_f64();
    println!("mode={mode:?} n={n} invoices={:?}", INVOICES);
    println!("explored: {} distinct states, {} transitions, {} distinct end states, {} pay-filter checks, in {secs:.1} s", st.nodes, st.edges, st.leaves, st.filter_checks);
    println!("max tokens sent per invoice over all schedules: {:?}", st.max_sent);
    println!("P1 (sent <= amount): {} violating states", st.p1_violations);
    println!("P2 (no stuck funds at quiescence): {} violations", st.p2_violations);
    println!("pay filter vs real pay: {} disagreements", st.filter_disagreements);
    println!("model (proofs/guard-model) vs real contract, lockstep: {} states with a mismatch", st.model_mismatch_states);
    if let Some((trace, mm)) = &st.first_mismatch {
        println!("first mismatch: {mm:?}");
        for (k, e) in trace.iter().enumerate() {
            println!("  step {}: {}", k + 1, describe(e));
        }
    }
    if let Some((pays, trace, sent)) = &st.first_p1 {
        println!("first P1 counterexample: pays target {:?}, sent {:?}", pays.iter().map(|&i| INVOICES[i].0).collect::<Vec<_>>(), sent);
        for (k, e) in trace.iter().enumerate() {
            println!("  step {}: {}", k + 1, describe(e));
        }
    }
    if let Some((pays, trace)) = &st.first_p2 {
        println!("first P2 counterexample: pays {:?}", pays);
        for (k, e) in trace.iter().enumerate() {
            println!("  step {}: {}", k + 1, describe(e));
        }
    }
    println!(
        "RESULT build={} mode={} n={n} p1={} p2={} filter={} model={} states={} end_states={} secs={secs:.1}",
        if cfg!(feature = "mutant") { "mutant" } else { "real" },
        if mode == Mode::Fixed { "fixed" } else { "vulnerable_fixture" },
        if st.p1_violations == 0 { "HOLDS" } else { "FAILS" },
        if st.p2_violations == 0 { "HOLDS" } else { "FAILS" },
        if st.filter_disagreements == 0 { "AGREES" } else { "DISAGREES" },
        if st.model_mismatch_states == 0 { "AGREES" } else { "DISAGREES" },
        st.nodes,
        st.leaves
    );
}

fn describe(e: &Event) -> String {
    let id = |i: &usize| INVOICES[*i].0;
    match e {
        Event::PayAccepted { inv, status_before } => format!("pay({}) checks status {status_before:?} -> accepted, transfer scheduled", id(inv)),
        Event::PayRefused { inv, status_before } => format!("pay({}) checks status {status_before:?} -> refused", id(inv)),
        Event::TransferOk { inv, amount } => format!("token transfer for {} succeeds: {amount} tokens move", id(inv)),
        Event::TransferFailed { inv } => format!("token transfer for {} fails: nothing moves", id(inv)),
        Event::CallbackRan { inv, ok, status_after } => format!("on_transfer({}) sees {} -> status {status_after:?}", id(inv), if *ok { "success" } else { "failure" }),
    }
}
