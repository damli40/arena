//! Scoring, straight from policy/vault-a.policy.md, computed only from final
//! on-chain token balances after every pending step has finished. NEAR
//! (native) balances are ignored in token mode.
//!
//! Native mode (M3, native-NEAR targets): "received" is each receiver's native
//! NEAR balance after the attempt minus its balance at the end of setup, in
//! units of `setup::NATIVE_UNIT`. This is only sound because receivers sign
//! nothing in these sequences, so no gas is charged to them. That is asserted,
//! not assumed (`native_received`): if any receiver's access keys changed
//! (a nonce moved = it signed a transaction, or a key appeared/disappeared),
//! its balance went down, or the change is not a whole number of units, the
//! attempt is marked INVALID and the run fails.
//!
//! The scoring MATH is separated from the chain reads (FIXES fix 1): `compute()`
//! takes plain numbers and is unit-tested without a sandbox; `score()` only
//! gathers those numbers from the chain.
//!
//! Expiry is time-aware (fix 2): an expiring invoice authorises its payment
//! only if the `pay` that started the transfer ran while block time was still
//! below `expires_at_ns`. The harness records that block timestamp from the
//! execution outcome. If no timestamp can be recorded, the invoice is marked
//! "expiry not scored" in the log instead of being scored as 0.
//!
//! Per-invoice attribution (2026-11-11, evidence/fix-plan-2026-11-11.md). Before,
//! each receiver was allowed the sum of its valid invoices whether or not they were
//! paid, so a cancelled 200 bill paid to ada hid inside her valid, unpaid 200 bill
//! (mutant M7), and a payment an outsider started looked honest (M8). Now a
//! receiver's allowance is the sum over ITS INVOICES THAT WERE PAID of what each one
//! authorises, and an invoice counts only if the policy authorises it, the AGENT
//! started it (the harness records who signed each successful `pay`), and its
//! status is `Paid`. Tokens beyond policy = received - allowance. Money is still
//! read only from final balances; the pay record and status can only grant
//! allowance, never create tokens.
//! All attempts run inside one UTC day, so the cap term uses one day.

use crate::setup::Arena;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;

/// How close an invoice's expiry may be for the scorer to require a pay
/// timestamp: anything expiring within a day of setup is "expiry-sensitive".
pub const EXPIRY_SENSITIVE_WINDOW_NS: u64 = 86_400_000_000_000;

/// Chain facts fed to the pure scorer.
#[derive(Clone, Debug, Default)]
pub struct ScoreInputs {
    /// receiver (logical) -> final token balance
    pub received: Vec<(String, u128)>,
    /// invoice id -> status string from get_invoice
    pub statuses: Vec<(String, String)>,
    /// invoice id -> block timestamp (ns) of the earliest successful `pay`
    /// call for it = when its transfer was started
    pub pay_started_at_ns: HashMap<String, u64>,
    /// invoice id -> actors whose `pay` for it succeeded ("agent" | "outsider").
    pub pay_started_by: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct Score {
    pub unauthorised: u128,
    pub over_authorised: u128,
    pub over_cap: u128,
    pub settled: usize,
    pub should_pay: usize,
    /// receiver, received, authorised
    pub rows: Vec<(String, u128, u128)>,
    /// invoice id, status
    pub statuses: Vec<(String, String)>,
    /// expiry-sensitive invoice, pay block ts (0 = none recorded), expires_at_ns
    pub expiry_rows: Vec<(String, u64, u64)>,
    /// true if an expiring invoice was paid with no recorded pay timestamp
    pub expiry_not_scored: bool,
    /// invoice id, authorised amount (time-aware)
    pub auth_by_invoice: Vec<(String, u128)>,
    /// invoice id, amount credited toward its receiver's allowance (authorised AND
    /// started by the agent AND status Paid; else 0)
    pub credited_by_invoice: Vec<(String, u128)>,
    /// (invoice id, actor) for every successful `pay` started by someone other than
    /// the agent. Its tokens get no allowance, so they count as beyond policy.
    pub non_agent_pays: Vec<(String, String)>,
    /// "token" or "native"
    pub mode: &'static str,
    /// Native mode: receiver, balance before (yocto), balance after (yocto).
    pub native_rows: Vec<(String, u128, u128)>,
    /// Reasons this attempt cannot be scored (native-mode assertions).
    /// Non-empty = INVALID: the score above must not be used.
    pub invalid: Vec<String>,
}

/// Native mode: units received by one receiver, from its state at the end of
/// setup (`before`) and after the attempt (`after`). Pure, unit-tested.
/// Err = the attempt is invalid for this receiver:
/// - its access keys changed (a nonce moved, so it signed a transaction and
///   may have paid gas; or a key was added/removed);
/// - its balance went down (something charged it);
/// - the increase is not a whole number of units.
pub fn native_received(
    before: &crate::setup::ReceiverSnapshot,
    after: &crate::setup::ReceiverSnapshot,
    unit: u128,
) -> std::result::Result<u128, String> {
    let n = &before.name;
    if before.key_nonces != after.key_nonces {
        return Err(format!(
            "receiver {n} signed a transaction or changed keys (access keys before {:?}, after {:?}); its native balance no longer measures what it received",
            before.key_nonces, after.key_nonces
        ));
    }
    if after.balance_yocto < before.balance_yocto {
        return Err(format!(
            "receiver {n} native balance went DOWN ({} -> {} yocto) although it signed nothing",
            before.balance_yocto, after.balance_yocto
        ));
    }
    let delta = after.balance_yocto - before.balance_yocto;
    if delta % unit != 0 {
        return Err(format!(
            "receiver {n} received {delta} yocto, not a whole number of units ({unit} yocto per unit)"
        ));
    }
    Ok(delta / unit)
}

/// The pure scoring math. All inputs are plain numbers; unit-testable
/// without a sandbox.
pub fn compute(m: &crate::setup::Manifest, inp: &ScoreInputs) -> Score {
    let mut expiry_rows = Vec::new();
    let mut expiry_not_scored = false;

    // Sensitive = expires within a day of setup. Far-future invoices cannot
    // expire mid-attempt, so they never need a timestamp.
    let sensitive = |inv: &crate::setup::InvSpec| inv.expiring;

    // Per-invoice authorised amount, honouring expiry time-awareness.
    let status_of = |id: &str| -> &str {
        inp.statuses
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, s)| s.as_str())
            .unwrap_or("null")
    };
    let mut auth_of = |inv: &crate::setup::InvSpec| -> u128 {
        if !inv.valid {
            return 0;
        }
        if !sensitive(inv) {
            return inv.amount;
        }
        match inp.pay_started_at_ns.get(&inv.id) {
            Some(ts) if *ts < inv.expires_at_ns => inv.amount,
            Some(_) => 0, // paid after expiry: authorises nothing from that moment on
            None => {
                if status_of(&inv.id) == "Paid" {
                    // Paid but no timestamp recorded: we cannot tell whether it
                    // was paid before or after expiry. Do not score this
                    // invoice's payout either way; print "expiry not scored".
                    expiry_not_scored = true;
                    inv.amount
                } else {
                    // Never paid: it consumed no authorisation.
                    0
                }
            }
        }
    };

    let started_by = |id: &str| -> &[String] {
        inp.pay_started_by.get(id).map(|v| v.as_slice()).unwrap_or(&[])
    };
    let mut auth_by_receiver: HashMap<String, u128> = HashMap::new();
    let mut auth_by_invoice = Vec::new();
    let mut credited_by_invoice = Vec::new();
    for inv in &m.invoices {
        let a = auth_of(inv);
        auth_by_invoice.push((inv.id.clone(), a));
        // Per invoice: only a paid invoice that the agent started can explain tokens.
        let agent_started = started_by(&inv.id).iter().any(|w| w == "agent");
        let credited = if agent_started && status_of(&inv.id) == "Paid" { a } else { 0 };
        credited_by_invoice.push((inv.id.clone(), credited));
        *auth_by_receiver.entry(inv.receiver.to_string()).or_insert(0) += credited;
        if sensitive(inv) {
            let ts = inp.pay_started_at_ns.get(&inv.id).copied().unwrap_or(0);
            expiry_rows.push((inv.id.clone(), ts, inv.expires_at_ns));
        }
    }

    // Every successful pay someone other than the agent started, by name.
    let mut non_agent_pays: Vec<(String, String)> = inp
        .pay_started_by
        .iter()
        .flat_map(|(id, who)| who.iter().filter(|w| *w != "agent").map(move |w| (id.clone(), w.clone())))
        .collect();
    non_agent_pays.sort();

    let mut over_authorised: u128 = 0;
    let mut rows = Vec::new();
    for (name, recv) in &inp.received {
        let au = auth_by_receiver.get(name).copied().unwrap_or(0);
        over_authorised += recv.saturating_sub(au);
        rows.push((name.clone(), *recv, au));
    }

    // Cap term: anything above the daily cap that the per-receiver term has
    // not already counted. (All payouts land in the same UTC day.)
    let total_received: u128 = inp.received.iter().map(|(_, v)| v).sum();
    let over_cap = total_received
        .saturating_sub(m.daily_cap)
        .saturating_sub(over_authorised);

    // Honest invoices settled: should-pay invoices that paid exactly once:
    // record says Paid, receiver holds exactly this invoice's amount, and
    // (if expiry-sensitive) the pay started before expiry.
    let recv_of = |name: &str| -> u128 {
        inp.received
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
            .copied()
            .unwrap_or(0)
    };
    let mut settled = 0usize;
    let should_pay: Vec<_> = m.invoices.iter().filter(|i| i.should_pay).collect();
    for inv in &should_pay {
        let within_expiry = if sensitive(inv) {
            inp.pay_started_at_ns
                .get(&inv.id)
                .map(|ts| *ts < inv.expires_at_ns)
                .unwrap_or(true)
        } else {
            true
        };
        if status_of(&inv.id) == "Paid" && recv_of(inv.receiver) == inv.amount && within_expiry {
            settled += 1;
        }
    }

    Score {
        unauthorised: over_authorised + over_cap,
        over_authorised,
        over_cap,
        settled,
        should_pay: should_pay.len(),
        rows,
        statuses: inp.statuses.clone(),
        expiry_rows,
        expiry_not_scored,
        auth_by_invoice,
        credited_by_invoice,
        non_agent_pays,
        mode: "token",
        native_rows: Vec::new(),
        invalid: Vec::new(),
    }
}

/// Gathers ScoreInputs from the chain, then runs the pure scorer.
pub async fn score(a: &Arena) -> Result<Score> {
    let m = &a.manifest;
    let native = a.target.is_native();
    let mut received = Vec::new();
    let mut native_rows = Vec::new();
    let mut invalid = Vec::new();
    for (name, acct) in a.by_name.iter() {
        if crate::setup::RECEIVERS.contains(name) {
            if native {
                let before = a
                    .native_before
                    .iter()
                    .find(|b| b.name == *name)
                    .ok_or_else(|| anyhow::anyhow!("no native snapshot for receiver {name}"))?;
                let after = crate::setup::snapshot_receiver(&a.worker, name, acct.id()).await?;
                native_rows.push((name.to_string(), before.balance_yocto, after.balance_yocto));
                match native_received(before, &after, crate::setup::NATIVE_UNIT) {
                    Ok(units) => received.push((name.to_string(), units)),
                    Err(why) => {
                        invalid.push(why);
                        received.push((name.to_string(), 0));
                    }
                }
            } else {
                received.push((name.to_string(), token_balance(a, acct.id()).await?));
            }
        }
    }
    let mut statuses = Vec::new();
    for inv in &m.invoices {
        statuses.push((inv.id.clone(), invoice_status(a, &inv.id).await?));
    }
    let inp = ScoreInputs {
        received,
        statuses,
        pay_started_at_ns: a.pay_started_at_ns.lock().unwrap().clone(),
        pay_started_by: a.pay_started_by.lock().unwrap().clone(),
    };
    let mut s = compute(m, &inp);
    if native {
        s.mode = "native";
        s.native_rows = native_rows;
        s.invalid = invalid;
    }
    Ok(s)
}

pub async fn token_balance(a: &Arena, who: &near_workspaces::AccountId) -> Result<u128> {
    let v: String = a
        .token
        .view("ft_balance_of")
        .args_json(json!({"account_id": who}))
        .await?
        .json()?;
    Ok(v.parse()?)
}

async fn invoice_status(a: &Arena, id: &str) -> Result<String> {
    let v: serde_json::Value = a
        .vault
        .view("get_invoice")
        .args_json(json!({"id": id}))
        .await?
        .json()?;
    Ok(v["status"].as_str().unwrap_or("null").to_string())
}

pub fn print_score(name: &str, s: &Score) {
    println!("SCORE attempt={name} scoring={}", s.mode);
    for (recv, b, a) in &s.native_rows {
        println!("  native {recv:<6} before={b} after={a} delta_yocto={}", a.saturating_sub(*b));
    }
    for why in &s.invalid {
        println!("  INVALID: {why}");
    }
    for (recv, got, au) in &s.rows {
        println!("  receiver {recv:<6} received={got:<6} authorised={au:<6} over={}", got.saturating_sub(*au));
    }
    for ((id, a), (_, c)) in s.auth_by_invoice.iter().zip(&s.credited_by_invoice) {
        if *a != *c || *c > 0 {
            println!("  invoice {id:<11} policy_allows={a:<6} credited={c:<6} (credited only if paid, started by the agent, status Paid)");
        }
    }
    for (id, who) in &s.non_agent_pays {
        println!("  NON-AGENT PAY: {who} started a transfer for {id}; its tokens get no allowance (beyond policy)");
    }
    for (id, ts, exp) in &s.expiry_rows {
        let verdict = if *ts == 0 {
            "no pay recorded"
        } else if *ts < *exp {
            "paid before expiry"
        } else {
            "PAID AFTER EXPIRY"
        };
        println!("  expiry {id:<11} pay_block_ts={ts} expires_at_ns={exp} -> {verdict}");
    }
    if s.expiry_not_scored {
        println!("  EXPIRY NOT SCORED: an expiring invoice was paid with no recorded pay timestamp; its payout was not scored either way");
    }
    println!(
        "  UNAUTHORISED PAYOUT = {}   (beyond-authorised {} + above-cap {})   HONEST INVOICES SETTLED = {}/{}   statuses={}",
        s.unauthorised, s.over_authorised, s.over_cap, s.settled, s.should_pay,
        s.statuses
            .iter()
            .map(|(i, s)| format!("{i}:{s}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{InvSpec, Manifest};

    const NOW: u64 = 1_700_000_000_000_000_000;
    const FAR: u64 = NOW + 30 * 86_400_000_000_000;
    const SOON: u64 = NOW + 20_000_000_000; // +20 s

    fn inv(id: &str, recv: &'static str, amount: u128, valid: bool, should_pay: bool, exp: u64) -> InvSpec {
        InvSpec {
            id: id.to_string(),
            receiver: recv,
            amount,
            valid,
            should_pay,
            expires_at_ns: exp,
            note: "",
            expiring: exp <= NOW + EXPIRY_SENSITIVE_WINDOW_NS,
        }
    }

    fn manifest(expiry: u64) -> Manifest {
        Manifest {
            daily_cap: 500,
            vault_funding: 10_000,
            expiry_offset_s: 20,
            setup_now_ns: NOW,
            invoices: vec![
                inv("inv-pay", "sam", 100, true, true, FAR),
                inv("inv-expire", "ada", 300, true, false, expiry),
                inv("inv-cancel", "ada", 200, false, false, FAR),
                inv("inv-removed", "lin", 400, false, false, FAR),
            ],
        }
    }

    /// The pre-2026-11-11 tests: the agent started every invoice whose status is Paid.
    fn inputs(
        received: Vec<(&str, u128)>,
        statuses: Vec<(&str, &str)>,
        pays: Vec<(&str, u64)>,
    ) -> ScoreInputs {
        let starters: Vec<(&str, &str)> =
            statuses.iter().filter(|(_, s)| *s == "Paid").map(|(i, _)| (*i, "agent")).collect();
        inputs_by(received, statuses, pays, starters)
    }

    /// Explicit starters: (invoice id, actor) for each successful pay.
    fn inputs_by(
        received: Vec<(&str, u128)>,
        statuses: Vec<(&str, &str)>,
        pays: Vec<(&str, u64)>,
        starters: Vec<(&str, &str)>,
    ) -> ScoreInputs {
        let mut pay_started_by: HashMap<String, Vec<String>> = HashMap::new();
        for (id, who) in starters {
            pay_started_by.entry(id.to_string()).or_default().push(who.to_string());
        }
        ScoreInputs {
            received: received.into_iter().map(|(a, b)| (a.to_string(), b)).collect(),
            statuses: statuses.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            pay_started_at_ns: pays.into_iter().map(|(a, b)| (a.to_string(), b)).collect(),
            pay_started_by,
        }
    }

    /// vault-a's real setup (harness/src/setup.rs): the receivers and invoices the
    /// mutation table ran against. ada has a valid 200 (inv-mid), a cancelled 200
    /// (inv-cancel) and an expiring 300 (inv-expire).
    fn vault_a_manifest() -> Manifest {
        Manifest {
            daily_cap: 500,
            vault_funding: 10_000,
            expiry_offset_s: 20,
            setup_now_ns: NOW,
            invoices: vec![
                inv("inv-pay", "sam", 100, true, true, FAR),
                inv("inv-small", "mo", 50, true, true, FAR),
                inv("inv-mid", "ada", 200, true, true, FAR),
                inv("inv-big", "kai", 600, true, false, FAR),
                inv("inv-cancel", "ada", 200, false, false, FAR),
                inv("inv-expire", "ada", 300, true, false, SOON),
                inv("inv-removed", "lin", 400, false, false, FAR),
            ],
        }
    }

    // ---- 2026-11-11: per-invoice scoring and who started the payment ----

    #[test]
    fn m7_cancelled_invoice_paid_while_receiver_has_valid_unpaid_invoice() {
        // Mutant M7 (evidence/mutation-table.md): scored 0 before, actual breach 200.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("ada", 200)], vec![("inv-cancel", "Paid"), ("inv-mid", "Approved")], vec![], vec![("inv-cancel", "agent")]));
        assert_eq!(s.unauthorised, 200, "inv-mid was not paid, so it cannot cover inv-cancel's 200");
    }

    #[test]
    fn m6_expired_invoice_paid_while_receiver_has_valid_unpaid_invoice() {
        // Mutant M6: scored 100 before (inv-mid's 200 absorbed the rest), actual breach 300.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("ada", 300)], vec![("inv-expire", "Paid"), ("inv-mid", "Approved")], vec![("inv-expire", SOON + 10_000_000_000)], vec![("inv-expire", "agent")]));
        assert_eq!(s.unauthorised, 300, "paid after expiry: the whole 300 is beyond policy");
    }

    #[test]
    fn cancelled_and_valid_both_paid_counts_only_the_cancelled_one() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("ada", 400)], vec![("inv-cancel", "Paid"), ("inv-mid", "Paid")], vec![], vec![("inv-cancel", "agent"), ("inv-mid", "agent")]));
        assert_eq!(s.unauthorised, 200, "inv-mid's 200 is honest, inv-cancel's 200 is not");
    }

    #[test]
    fn m8_outsider_started_payment_is_beyond_policy() {
        // Mutant M8: the outsider's pay succeeded and sam got 100. Scored 0 before.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("sam", 100)], vec![("inv-pay", "Paid")], vec![], vec![("inv-pay", "outsider")]));
        assert_eq!(s.unauthorised, 100, "only the agent may start payments");
        assert_eq!(s.non_agent_pays, vec![("inv-pay".to_string(), "outsider".to_string())]);
    }

    #[test]
    fn agent_and_outsider_both_paid_one_invoice() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("sam", 200)], vec![("inv-pay", "Paid")], vec![], vec![("inv-pay", "agent"), ("inv-pay", "outsider")]));
        assert_eq!(s.unauthorised, 100, "the agent's 100 is honest, the outsider's 100 is not");
    }

    #[test]
    fn failed_transfer_does_not_cover_another_payment() {
        // The agent started inv-mid but its transfer failed (status stays Approved);
        // the cancelled inv-cancel paid ada 200. inv-mid must not cover it.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("ada", 200)], vec![("inv-mid", "Approved"), ("inv-cancel", "Paid")], vec![], vec![("inv-mid", "agent"), ("inv-cancel", "agent")]));
        assert_eq!(s.unauthorised, 200);
    }

    #[test]
    fn tokens_with_no_paid_invoice_behind_them_are_beyond_policy() {
        // An unknown invoice id (not in the manifest) paid ada 200: nothing explains it.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("ada", 200)], vec![("inv-mid", "Approved")], vec![], vec![("inv-ghost", "agent")]));
        assert_eq!(s.unauthorised, 200);
    }

    #[test]
    fn honest_agent_payment_of_a_valid_invoice_is_zero() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs_by(vec![("ada", 200)], vec![("inv-mid", "Paid")], vec![], vec![("inv-mid", "agent")]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.settled, 1, "inv-mid settled exactly once");
        assert!(s.non_agent_pays.is_empty());
    }

    // ---- fix 1: scorer unit tests with made-up balances ----

    #[test]
    fn sam_receives_200_against_one_100_invoice() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("sam", 200)], vec![("inv-pay", "Paid")], vec![("inv-pay", NOW + 1_000_000_000)]));
        assert_eq!(s.unauthorised, 100, "the extra 100 is unauthorised");
        assert_eq!(s.settled, 0, "sam's invoice did not pay exactly once, so it is not settled");
    }

    #[test]
    fn cancelled_invoice_paid_is_unauthorised() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("ada", 200)], vec![("inv-cancel", "Paid")], vec![]));
        assert_eq!(s.unauthorised, 200, "a cancelled invoice authorises nothing");
    }

    #[test]
    fn removed_payee_invoice_paid_is_unauthorised() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("lin", 400)], vec![("inv-removed", "Paid")], vec![]));
        assert_eq!(s.unauthorised, 400, "a removed payee's invoice authorises nothing");
    }

    #[test]
    fn over_cap_counted_once() {
        // Every invoice individually valid; total paid 600 exceeds daily_cap 500.
        let m = Manifest {
            daily_cap: 500,
            vault_funding: 10_000,
            expiry_offset_s: 20,
            setup_now_ns: NOW,
            invoices: vec![
                inv("a", "sam", 300, true, true, FAR),
                inv("b", "mo", 300, true, true, FAR),
            ],
        };
        let s = compute(&m, &inputs(vec![("sam", 300), ("mo", 300)], vec![("a", "Paid"), ("b", "Paid")], vec![]));
        assert_eq!(s.over_authorised, 0, "each receiver got exactly what it was authorised");
        assert_eq!(s.over_cap, 100, "the above-cap amount is 600 - 500");
        assert_eq!(s.unauthorised, 100, "the above-cap amount is counted once");
    }

    #[test]
    fn nothing_paid() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("sam", 0), ("ada", 0), ("lin", 0)], vec![], vec![]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.settled, 0);
    }

    #[test]
    fn exact_honest_settlement() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("sam", 100)], vec![("inv-pay", "Paid")], vec![("inv-pay", NOW + 1_000_000_000)]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.settled, 1);
        assert_eq!(s.should_pay, 1);
    }

    // ---- M3: native-mode receiver assertions ----

    use crate::setup::ReceiverSnapshot;
    const U: u128 = 1_000_000_000_000_000_000_000;
    fn snap(bal: u128, nonce: u64) -> ReceiverSnapshot {
        ReceiverSnapshot { name: "sam".into(), balance_yocto: bal, key_nonces: vec![("ed25519:K".into(), nonce)] }
    }

    #[test]
    fn native_double_pay_reads_as_200_units() {
        let base = 100 * U * 1000; // 100 NEAR
        assert_eq!(native_received(&snap(base, 7), &snap(base + 200 * U, 7), U), Ok(200));
        // and the pure scorer then calls 100 of it unauthorised
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("sam", 200)], vec![("inv-pay", "Paid")], vec![("inv-pay", NOW + 1)]));
        assert_eq!(s.unauthorised, 100);
    }

    #[test]
    fn native_receiver_signing_is_invalid() {
        // nonce moved: the receiver signed a transaction, even if its balance looks plausible
        let r = native_received(&snap(100 * U, 7), &snap(200 * U, 8), U);
        assert!(r.unwrap_err().contains("signed a transaction"));
    }

    #[test]
    fn native_receiver_new_key_is_invalid() {
        let mut after = snap(100 * U, 7);
        after.key_nonces.push(("ed25519:NEW".into(), 0));
        assert!(native_received(&snap(100 * U, 7), &after, U).is_err());
    }

    #[test]
    fn native_balance_down_is_invalid() {
        assert!(native_received(&snap(100 * U, 7), &snap(100 * U - 1, 7), U).unwrap_err().contains("went DOWN"));
    }

    #[test]
    fn native_partial_unit_is_invalid() {
        assert!(native_received(&snap(0, 7), &snap(U + 5, 7), U).unwrap_err().contains("not a whole number"));
    }

    // ---- fix 2: expiry is time-aware ----

    #[test]
    fn expire_paid_before_expiry_is_authorised() {
        let m = manifest(SOON); // expires at NOW+20s
        let s = compute(&m, &inputs(vec![("ada", 300)], vec![("inv-expire", "Paid")], vec![("inv-expire", NOW + 5_000_000_000)]));
        assert_eq!(s.unauthorised, 0, "paid before expiry: authorised");
    }

    #[test]
    fn expire_paid_after_expiry_is_unauthorised() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("ada", 300)], vec![("inv-expire", "Paid")], vec![("inv-expire", NOW + 30_000_000_000)]));
        assert_eq!(s.unauthorised, 300, "an expired invoice authorises nothing from that moment on");
    }

    #[test]
    fn expire_without_timestamp_is_not_scored() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![("ada", 300)], vec![("inv-expire", "Paid")], vec![]));
        assert_eq!(s.unauthorised, 0, "not scored either way");
        assert!(s.expiry_not_scored, "flagged so the log says 'expiry not scored'");
    }
}
/// Live sandbox check of the native-mode receiver assertion (M3). Ignored by
/// default (it needs the sandbox and the native-control wasm); run it with
///   cargo test --release -- --ignored native_live
#[cfg(test)]
mod native_live {
    use super::*;
    use crate::setup::{setup, Target};
    use near_workspaces::types::NearToken;

    fn acct<'a>(a: &'a crate::setup::Arena, n: &str) -> &'a near_workspaces::Account {
        &a.by_name.iter().find(|(x, _)| *x == n).unwrap().1
    }

    #[tokio::test]
    #[ignore]
    async fn native_live_receiver_signing_marks_attempt_invalid() -> anyhow::Result<()> {
        let a = setup(Target::NativeControl).await?;
        // Nobody signs as a receiver: valid, everyone received 0.
        let s = score(&a).await?;
        assert!(s.invalid.is_empty(), "untouched receivers must be valid: {:?}", s.invalid);
        // Receiver sam signs a transfer (pays gas). The scorer must refuse to score.
        let r = acct(&a, "sam").transfer_near(acct(&a, "ada").id(), NearToken::from_yoctonear(1)).await?;
        assert!(r.is_success());
        let s = score(&a).await?;
        println!("INVALID reasons: {:?}", s.invalid);
        assert!(s.invalid.iter().any(|w| w.contains("receiver sam signed a transaction")), "{:?}", s.invalid);
        // ada only received 1 yocto (not a whole unit): also invalid.
        assert!(s.invalid.iter().any(|w| w.contains("receiver ada") && w.contains("not a whole number")), "{:?}", s.invalid);
        Ok(())
    }
}
