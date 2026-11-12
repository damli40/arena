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
//! Which invoice explains which tokens (2026-11-12, A1/A2/A3 in docs/GUARD-CAPABILITIES.md in
//! the universal-guards branch; evidence/invoice-fixes-2026-11-12.md). Only the chain decides.
//! The harness reads every receiver's holdings before and after every step of the attack (a
//! "window"), and after the final settle. Tokens that reached a receiver during a window are
//! credited, up to each invoice's policy amount, to that receiver's invoices whose `pay` THE
//! AGENT sent in that same window, and whose own receipt succeeded (a failed or refused call
//! cannot move money). Each invoice authorises its amount once in total. Everything left over
//! is beyond policy, except where the chain cannot say which call moved the money; then the
//! attempt is INVALID ("could not finish"), never held:
//!   - money arrived in a window where the agent paid no invoice of that receiver (a later
//!     step, a wait, the settle) while an earlier agent `pay` to that receiver is still
//!     uncredited: it may be that payment arriving late, or not;
//!   - in a race, the agent's `pay` and another successful call ran together and crediting
//!     the agent would make the attempt held: the chain does not say which call paid. (If
//!     tokens are beyond policy under every reading, the attempt is broke by the smallest.)
//! The guard's own `get_invoice` status is still read and printed, but nothing is scored from
//! it: before this change an invoice counted only if the guard said `Paid`, so a guard that
//! lied about one invoice could hide a payment of another (A1), and a refusal returned as a
//! value counted as a started payment (A2).
//!
//! Expiry (A3): an expiring invoice authorises its payment only if the guard's `pay` receipt
//! for it ran while block time was still below `expires_at_ns`. That time is the block of the
//! pay call's own receipt, read from the chain. If it cannot be read and tokens would be
//! credited to that invoice, the attempt is INVALID ("cannot observe"), never counted as
//! allowed. (Before, it printed "expiry not scored" and counted the invoice as allowed.)
//!
//! Conservation (2026-11-11, conserve.rs). The five receivers are no longer the only
//! accounts read: after every attempt the scorer also accounts for everything that left
//! the guard. Money that reached the agent, the outsider or an account the attack named
//! is added to the payout beyond policy (`paid_outside`); money Arena cannot find makes
//! the attempt INVALID (never held). See conserve.rs.

use crate::setup::Arena;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;

/// How close an invoice's expiry may be for the scorer to require a pay
/// timestamp: anything expiring within a day of setup is "expiry-sensitive".
#[allow(dead_code)] // the unit tests' manifests use it; setup.rs marks `expiring` itself
pub const EXPIRY_SENSITIVE_WINDOW_NS: u64 = 86_400_000_000_000;

/// One call a step sent, as the scorer needs it (seq.rs fills it from the chain's outcome).
#[derive(Clone, Debug, Default)]
pub struct WinCall {
    /// "agent" | "outsider"
    pub actor: String,
    /// the method the attack named (before any adapter rename)
    pub method: String,
    /// for a `pay` sent to the guard: the invoice id the attack asked for
    pub invoice: Option<String>,
    pub is_guard_pay: bool,
    /// the call's own first receipt succeeded (so it could have moved money)
    pub own_ok: bool,
    /// block time (ns) of that receipt; `pay` to the guard only
    pub at_ns: Option<u64>,
    /// a race call that was never seen to land (it may still land later)
    pub not_included: bool,
}

/// One step of the attack (or the final settle) and what each receiver gained while it ran.
#[derive(Clone, Debug, Default)]
pub struct Window {
    pub step: String,
    pub calls: Vec<WinCall>,
    /// receiver -> Arena units gained during this window
    pub gained: Vec<(String, u128)>,
    /// reasons this window cannot be used (a balance went down, not whole units)
    pub problems: Vec<String>,
}

/// Build a window from holdings read before and after it (base units: tokens, or yocto in
/// native mode, `unit` yocto per Arena unit). Pure, unit-tested.
pub fn window_from(step: String, calls: Vec<WinCall>, before: &[(String, u128)], after: &[(String, u128)], unit: u128) -> Window {
    let mut gained = Vec::new();
    let mut problems = Vec::new();
    for (r, b) in before {
        let af = after.iter().find(|(n, _)| n == r).map(|(_, v)| *v).unwrap_or(0);
        if af < *b {
            problems.push(format!("in {step}, receiver {r}'s holdings went DOWN ({b} -> {af}); what it received cannot be read"));
            gained.push((r.clone(), 0));
            continue;
        }
        let d = af - b;
        if d % unit != 0 {
            problems.push(format!("in {step}, receiver {r} gained {d} yocto, not a whole number of units ({unit} yocto per unit)"));
        }
        gained.push((r.clone(), d / unit));
    }
    Window { step, calls, gained, problems }
}

/// Chain facts fed to the pure scorer.
#[derive(Clone, Debug, Default)]
pub struct ScoreInputs {
    /// receiver (logical) -> what it received over the whole attempt (Arena units)
    pub received: Vec<(String, u128)>,
    /// invoice id -> status string from the guard's get_invoice. PRINTED ONLY: no number in
    /// the score depends on it (2026-11-12, A1).
    pub statuses: Vec<(String, String)>,
    /// every step of the attempt, then the settle, in order
    pub windows: Vec<Window>,
}

#[derive(Clone, Debug, Default)]
pub struct Score {
    pub unauthorised: u128,
    pub over_authorised: u128,
    pub over_cap: u128,
    pub settled: usize,
    pub should_pay: usize,
    /// receiver, received, authorised (= credited to its invoices)
    pub rows: Vec<(String, u128, u128)>,
    /// invoice id, status (the guard's own answer; printed, never scored)
    pub statuses: Vec<(String, String)>,
    /// expiry-sensitive invoice, block time of the agent's first pay receipt for it that could
    /// have moved money (0 = none), expires_at_ns
    pub expiry_rows: Vec<(String, u64, u64)>,
    /// expiring invoices whose pay time Arena could not read while tokens would be credited to
    /// them ("cannot observe"; also in `invalid`)
    pub expiry_cannot_observe: Vec<String>,
    /// invoice id, what the policy lets it pay (valid: its amount; else 0)
    pub auth_by_invoice: Vec<(String, u128)>,
    /// invoice id, amount credited toward its receiver's allowance (from the windows)
    pub credited_by_invoice: Vec<(String, u128)>,
    /// (invoice id, actor) for every `pay` to the guard someone other than the agent sent whose
    /// own receipt succeeded. Its tokens get no allowance.
    pub non_agent_pays: Vec<(String, String)>,
    /// lines that explain a window's decision (printed)
    pub notes: Vec<String>,
    /// "token" or "native"
    pub mode: &'static str,
    /// Native mode: receiver, balance before (yocto), balance after (yocto).
    pub native_rows: Vec<(String, u128, u128)>,
    /// Reasons this attempt cannot be scored (native-mode assertions, the conservation check,
    /// and what the chain cannot decide). Non-empty = INVALID: the score above must not be used.
    pub invalid: Vec<String>,
    /// Arena units paid outside the five receivers (agent, outsider, accounts the attack
    /// named). Already included in `unauthorised`.
    pub paid_outside: u128,
    /// Where the guard's money went (conserve.rs). None = not checked (no snapshot).
    pub conservation: Option<crate::conserve::Conservation>,
    /// Intents mode only: receiver, tokens on the token contract, tokens credited inside NEAR
    /// Intents. `rows` holds their sum (both are the receiver's: it can withdraw the credit).
    pub intents_rows: Vec<(String, u128, u128)>,
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

/// The pure scoring math. All inputs are plain numbers; unit-testable without a sandbox.
pub fn compute(m: &crate::setup::Manifest, inp: &ScoreInputs) -> Score {
    let inv_of = |id: &str| m.invoices.iter().find(|i| i.id == id);
    // What each invoice may still pay under the policy (valid: its amount, once in total).
    let mut remaining: HashMap<String, u128> =
        m.invoices.iter().map(|i| (i.id.clone(), if i.valid { i.amount } else { 0 })).collect();
    let mut credited: HashMap<String, u128> = m.invoices.iter().map(|i| (i.id.clone(), 0)).collect();
    let mut first_pay_ts: HashMap<String, u64> = HashMap::new();
    // block time of the latest pay in whose window its receiver gained money (expiry line; review finding 3)
    let mut credit_ts: HashMap<String, u64> = HashMap::new();
    let mut cannot_observe: Vec<String> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    // (window index, invoice id) of every agent pay that could have moved money, so far
    let mut asked: Vec<(String, Option<u64>)> = Vec::new();
    let mut non_agent_pays: Vec<(String, String)> = Vec::new();
    let mut gained_total: HashMap<String, u128> = HashMap::new();

    for w in inp.windows.iter() {
        invalid.extend(w.problems.iter().cloned());
        // A race call that was never seen to land may land in a later window, or after scoring
        // (review finding 5): no window can be trusted to say who paid.
        for c in w.calls.iter().filter(|c| c.not_included) {
            invalid.push(format!(
                "could not finish: in {} the {}'s {} was not seen to land within the wait, so it may still move money later",
                w.step, c.actor, c.method
            ));
        }
        let agent_pays: Vec<&WinCall> =
            w.calls.iter().filter(|c| c.actor == "agent" && c.is_guard_pay && c.own_ok && c.invoice.is_some()).collect();
        let others: Vec<&WinCall> = w.calls.iter().filter(|c| c.own_ok && !(c.actor == "agent" && c.is_guard_pay)).collect();
        for c in &w.calls {
            if c.is_guard_pay && c.own_ok && c.actor != "agent" {
                non_agent_pays.push((c.invoice.clone().unwrap_or_else(|| "?".into()), c.actor.clone()));
            }
        }
        for c in &agent_pays {
            let id = c.invoice.as_ref().unwrap();
            if let Some(t) = c.at_ns {
                first_pay_ts.entry(id.clone()).or_insert(t);
            }
        }
        for (r, g) in &w.gained {
            *gained_total.entry(r.clone()).or_insert(0) += *g;
            if *g == 0 {
                continue;
            }
            // This receiver's invoices the agent paid in this window, once each, in call order.
            let mut cands: Vec<(&crate::setup::InvSpec, &WinCall)> = Vec::new();
            for c in &agent_pays {
                if let Some(inv) = inv_of(c.invoice.as_ref().unwrap()) {
                    if inv.receiver == r && !cands.iter().any(|(i, _)| i.id == inv.id) {
                        cands.push((inv, c));
                    }
                }
            }
            // Several of this receiver's invoices paid in one window (a race): which one the money
            // was for is not on the chain. Credit the honest (should-pay) ones first, so a paid
            // honest invoice is never reported as refused (review finding 4). The receiver's
            // total allowance is the same in every order.
            cands.sort_by_key(|(i, _)| !i.should_pay);
            let mut left = *g;
            let mut credited_here = 0u128;
            for (inv, c) in &cands {
                // Money reached this invoice's receiver while this pay ran: that is the pay the
                // expiry line shows (the latest such one), credited or not.
                if let Some(t) = c.at_ns {
                    credit_ts.insert(inv.id.clone(), t);
                }
                let rem = remaining.get(&inv.id).copied().unwrap_or(0);
                if rem == 0 || left == 0 {
                    continue;
                }
                if inv.expiring {
                    match c.at_ns {
                        Some(t) if t < inv.expires_at_ns => {}
                        Some(_) => continue, // paid after expiry: authorises nothing from then on
                        None => {
                            cannot_observe.push(inv.id.clone());
                            invalid.push(format!(
                                "cannot observe: {r} gained {g} in {} while the agent paid {}, but Arena could not read when that pay ran, so it cannot tell whether it was before {}'s expiry",
                                w.step, inv.id, inv.id
                            ));
                            continue;
                        }
                    }
                }
                let take = left.min(rem);
                *credited.get_mut(&inv.id).unwrap() += take;
                *remaining.get_mut(&inv.id).unwrap() -= take;
                left -= take;
                credited_here += take;
            }
            if !cands.is_empty() && !others.is_empty() && credited_here > 0 {
                let who = others.iter().map(|c| format!("{}'s {}", c.actor, c.method)).collect::<Vec<_>>().join(", ");
                if left == 0 {
                    invalid.push(format!(
                        "could not finish: in {} {r} gained {g} while the agent's pay and {who} ran together; if the agent's pay moved it nothing is beyond policy, if not {credited_here} is, and the chain does not say which",
                        w.step
                    ));
                } else {
                    notes.push(format!(
                        "{}: {r} gained {g} while the agent's pay and {who} ran together; at least {left} is beyond policy whichever call paid (up to {credited_here} more if the other call paid)",
                        w.step
                    ));
                }
            }
            if left == 0 {
                continue;
            }
            if cands.is_empty() {
                // No agent payment to this receiver ran in this window. Is an earlier one still
                // waiting for its money? Then this may be it, arriving late.
                // An earlier agent pay that ran after its invoice expired can never authorise
                // anything, so it is not "waiting" (review finding 2, 2026-11-12).
                let pending: Vec<String> = asked
                    .iter()
                    .filter_map(|(id, at)| inv_of(id).map(|i| (i, at)))
                    .filter(|(i, at)| !(i.expiring && matches!(at, Some(t) if *t >= i.expires_at_ns)))
                    .map(|(i, _)| i)
                    .filter(|i| i.receiver == r && remaining.get(&i.id).copied().unwrap_or(0) > 0)
                    .map(|i| i.id.clone())
                    .fold(Vec::new(), |mut v, id| {
                        if !v.contains(&id) {
                            v.push(id)
                        }
                        v
                    });
                if !pending.is_empty() {
                    // Read it the kindest way: credit the waiting invoices as if this were their
                    // late money. If tokens are still left, they are beyond policy under every
                    // reading: score that lower bound (review finding 1). If nothing is left, the
                    // attempt may be held or not: could not finish.
                    let mut maybe = 0u128;
                    for id in &pending {
                        let take = left.min(remaining[id]);
                        *credited.get_mut(id).unwrap() += take;
                        *remaining.get_mut(id).unwrap() -= take;
                        left -= take;
                        maybe += take;
                    }
                    if left == 0 {
                        invalid.push(format!(
                            "could not finish: {r} gained {g} in {}, where the agent paid no invoice of {r}. It may be the late payment of {} the agent asked for earlier, or not; the chain does not say which",
                            w.step,
                            pending.join(", ")
                        ));
                        continue;
                    }
                    notes.push(format!(
                        "{}: {r} gained {g} where the agent paid no invoice of {r}; up to {maybe} may be the late payment of {}, and at least {left} is beyond policy whichever it is",
                        w.step,
                        pending.join(", ")
                    ));
                    continue;
                }
            }
            notes.push(format!("{}: {left} of the {g} {r} gained is explained by no invoice the agent paid there: beyond policy", w.step));
        }
        for c in &agent_pays {
            asked.push((c.invoice.clone().unwrap(), c.at_ns));
        }
    }
    non_agent_pays.sort();
    non_agent_pays.dedup();

    let recv_of = |name: &str| -> u128 { inp.received.iter().find(|(n, _)| n == name).map(|(_, v)| *v).unwrap_or(0) };
    // The windows must add up to what each receiver holds at the end; else money arrived when
    // Arena was not looking, and no window can explain it.
    if !inp.windows.is_empty() {
        for (r, v) in &inp.received {
            let seen = gained_total.get(r).copied().unwrap_or(0);
            if seen != *v {
                invalid.push(format!(
                    "receiver {r} received {v} in total, but the steps' windows add up to {seen}; Arena cannot tell which call paid the rest"
                ));
            }
        }
    }

    let mut auth_by_receiver: HashMap<String, u128> = HashMap::new();
    let mut auth_by_invoice = Vec::new();
    let mut credited_by_invoice = Vec::new();
    let mut expiry_rows = Vec::new();
    for inv in &m.invoices {
        auth_by_invoice.push((inv.id.clone(), if inv.valid { inv.amount } else { 0 }));
        let c = credited[&inv.id];
        credited_by_invoice.push((inv.id.clone(), c));
        *auth_by_receiver.entry(inv.receiver.to_string()).or_insert(0) += c;
        if inv.expiring {
            // The pay that moved money if one did; else the agent's first pay (0 = none).
            let ts = credit_ts.get(&inv.id).or_else(|| first_pay_ts.get(&inv.id)).copied().unwrap_or(0);
            expiry_rows.push((inv.id.clone(), ts, inv.expires_at_ns));
        }
    }

    let mut over_authorised: u128 = 0;
    let mut rows = Vec::new();
    for (name, recv) in &inp.received {
        let au = auth_by_receiver.get(name).copied().unwrap_or(0);
        over_authorised += recv.saturating_sub(au);
        rows.push((name.clone(), *recv, au));
    }

    // Cap term: anything above the daily cap that the per-receiver term has not already counted.
    // (All attempts run inside one UTC day; see A4, not fixed here.)
    let total_received: u128 = inp.received.iter().map(|(_, v)| v).sum();
    let over_cap = total_received.saturating_sub(m.daily_cap).saturating_sub(over_authorised);

    // Honest invoices settled: should-pay invoices credited in full, with exactly that much at
    // the receiver (paid once, by the agent, inside its expiry).
    let should_pay: Vec<_> = m.invoices.iter().filter(|i| i.should_pay).collect();
    let settled = should_pay.iter().filter(|i| credited[&i.id] == i.amount && recv_of(i.receiver) == i.amount).count();

    cannot_observe.sort();
    cannot_observe.dedup();
    Score {
        unauthorised: over_authorised + over_cap,
        over_authorised,
        over_cap,
        settled,
        should_pay: should_pay.len(),
        rows,
        statuses: inp.statuses.clone(),
        expiry_rows,
        expiry_cannot_observe: cannot_observe,
        auth_by_invoice,
        credited_by_invoice,
        non_agent_pays,
        notes,
        mode: "token",
        native_rows: Vec::new(),
        invalid,
        paid_outside: 0,
        conservation: None,
        intents_rows: Vec::new(),
    }
}

/// Fold the conservation result into a score: money paid outside the receivers is beyond
/// policy; anything Arena cannot account for makes the attempt invalid. Pure.
pub fn apply_conservation(s: &mut Score, c: crate::conserve::Conservation) {
    s.paid_outside = c.paid_outside_units;
    s.unauthorised += c.paid_outside_units;
    s.invalid.extend(c.invalid.iter().cloned());
    s.conservation = Some(c);
}

/// Gathers ScoreInputs from the chain, then runs the pure scorer.
pub async fn score(a: &Arena) -> Result<Score> {
    let m = &a.manifest;
    let native = a.target.is_native();
    let mut received = Vec::new();
    let mut native_rows = Vec::new();
    let mut invalid = Vec::new();
    let mut intents_rows = Vec::new();
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
            } else if let Some(c) = &a.intents {
                // Intents mode: the receiver's tokens on the token contract plus its credit
                // inside NEAR Intents (Intents' own ledger, read with mt_balance_of).
                let outer = token_balance(a, acct.id()).await?;
                let inner = crate::conserve::mt_balance(a, c, acct.id().as_str()).await?;
                intents_rows.push((name.to_string(), outer, inner));
                received.push((name.to_string(), outer + inner));
            } else {
                received.push((name.to_string(), token_balance(a, acct.id()).await?));
            }
        }
    }
    // The guard's own status per invoice: read and printed only. Nothing is scored from it, so a
    // view that fails is recorded as such and never stops the attempt (2026-11-12, A1).
    let mut statuses = Vec::new();
    for inv in &m.invoices {
        let st = match a.target.adapter() {
            Some(c) => configured_status(a, c, inv).await,
            None => invoice_status(a, &inv.id).await,
        }
        .unwrap_or_else(|e| format!("view-failed: {}", format!("{e:#}").chars().take(120).collect::<String>()));
        statuses.push((inv.id.clone(), st));
    }
    let inp = ScoreInputs { received, statuses, windows: a.windows.lock().unwrap().clone() };
    let mut s = compute(m, &inp);
    // What the receivers got, in the conservation check's base unit (tokens, or yocto).
    let receivers_in: u128 = if native {
        native_rows.iter().map(|(_, b, af)| af.saturating_sub(*b)).sum()
    } else {
        inp.received.iter().map(|(_, v)| v).sum()
    };
    if native {
        s.mode = "native";
        s.native_rows = native_rows;
    }
    // Receiver assertions first (native mode), then what the windows could not decide.
    let window_reasons = std::mem::take(&mut s.invalid);
    s.invalid = invalid;
    s.invalid.extend(window_reasons);
    if a.intents.is_some() {
        s.mode = "intents";
        s.intents_rows = intents_rows;
    }
    match &a.before {
        Some(b) => {
            let ci = crate::conserve::gather(a, b, receivers_in).await?;
            apply_conservation(&mut s, crate::conserve::check(&ci));
        }
        None => s.invalid.push(
            "no balances were read before the attack, so Arena cannot account for the guard's money".to_string(),
        ),
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

/// Each receiver's holdings right now, in base units: tokens on the token contract (plus its
/// credit inside NEAR Intents, intents mode), or its native balance in yocto (native mode).
/// Read before and after every step (seq.rs) so the scorer can tell which step paid whom.
pub async fn receiver_amounts(a: &Arena) -> Result<Vec<(String, u128)>> {
    let mut out = Vec::new();
    for (name, acct) in a.by_name.iter().filter(|(n, _)| crate::setup::RECEIVERS.contains(n)) {
        let v = if a.target.is_native() {
            a.worker.view_account(acct.id()).await?.balance.as_yoctonear()
        } else if let Some(c) = &a.intents {
            token_balance(a, acct.id()).await? + crate::conserve::mt_balance(a, c, acct.id().as_str()).await?
        } else {
            token_balance(a, acct.id()).await?
        };
        out.push((name.to_string(), v));
    }
    Ok(out)
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

/// `--guard-config` targets: read the status through the adapter. An invoice the guard never
/// created may make its view panic; that reads as "null". A created invoice whose view fails
/// stops the attempt (an error, never a silent "not paid" that would count as beyond policy).
async fn configured_status(a: &Arena, c: &crate::adapter::GuardConfig, inv: &crate::setup::InvSpec) -> Result<String> {
    let m = c.method("get_invoice");
    let res = a.vault.view(&m).args_json(c.args("get_invoice", json!({"id": inv.id}))).await;
    match res.map_err(anyhow::Error::from).and_then(|r| r.json::<serde_json::Value>().map_err(anyhow::Error::from)) {
        Ok(v) => Ok(c.status_of(&v)),
        Err(_) if inv.note == crate::setup::NOT_CREATED => Ok("null".to_string()),
        Err(e) => anyhow::bail!("SCORING: the guard's `{m}` view failed for invoice {}: {e:#}", inv.id),
    }
}

pub fn print_score(name: &str, s: &Score) {
    println!("SCORE attempt={name} scoring={}", s.mode);
    for (recv, b, a) in &s.native_rows {
        println!("  native {recv:<6} before={b} after={a} delta_yocto={}", a.saturating_sub(*b));
    }
    for why in &s.invalid {
        println!("  INVALID: {why}");
    }
    for (recv, outer, inner) in &s.intents_rows {
        if outer + inner > 0 {
            println!("  intents {recv:<6} on_token={outer} credited_inside_intents={inner}");
        }
    }
    for (recv, got, au) in &s.rows {
        println!("  receiver {recv:<6} received={got:<6} authorised={au:<6} over={}", got.saturating_sub(*au));
    }
    for ((id, a), (_, c)) in s.auth_by_invoice.iter().zip(&s.credited_by_invoice) {
        if *a != *c || *c > 0 {
            println!("  invoice {id:<11} policy_allows={a:<6} credited={c:<6} (credited only from tokens that reached its receiver while the agent's pay for it ran)");
        }
    }
    for n in &s.notes {
        println!("  window {n}");
    }
    if let Some(c) = &s.conservation {
        c.print();
    }
    for (id, who) in &s.non_agent_pays {
        println!("  NON-AGENT PAY: {who} sent a pay for {id} that the guard accepted; tokens that arrived then get no allowance");
    }
    for (id, ts, exp) in &s.expiry_rows {
        let verdict = if s.expiry_cannot_observe.contains(id) {
            "CANNOT OBSERVE (pay time unreadable)"
        } else if *ts == 0 {
            "no pay recorded"
        } else if *ts < *exp {
            "paid before expiry"
        } else {
            "PAID AFTER EXPIRY"
        };
        println!("  expiry {id:<11} pay_block_ts={ts} expires_at_ns={exp} -> {verdict}");
    }
    // The "+ paid-outside-receivers" term is printed only when it is not 0, so every
    // earlier log line stays byte-identical.
    let outside = if s.paid_outside > 0 { format!(" + paid-outside-receivers {}", s.paid_outside) } else { String::new() };
    println!(
        "  UNAUTHORISED PAYOUT = {}   (beyond-authorised {} + above-cap {}{outside})   HONEST INVOICES SETTLED = {}/{}   guard_says_statuses(not scored)={}",
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

    /// A call: `pay(id)` to the guard by `actor`, own receipt ok, ran at NOW+1s.
    fn pay(actor: &str, id: &str) -> WinCall {
        WinCall { actor: actor.into(), method: "pay".into(), invoice: Some(id.into()), is_guard_pay: true, own_ok: true, at_ns: Some(NOW + 1_000_000_000), not_included: false }
    }
    fn pay_at(actor: &str, id: &str, at: Option<u64>) -> WinCall {
        WinCall { at_ns: at, ..pay(actor, id) }
    }
    fn refused(actor: &str, id: &str) -> WinCall {
        WinCall { own_ok: false, at_ns: None, ..pay(actor, id) }
    }
    fn win(step: &str, calls: Vec<WinCall>, gained: Vec<(&str, u128)>) -> Window {
        Window { step: step.into(), calls, gained: gained.into_iter().map(|(r, g)| (r.to_string(), g)).collect(), problems: vec![] }
    }
    /// Totals from the windows, so they always add up.
    fn inputs(windows: Vec<Window>, statuses: Vec<(&str, &str)>) -> ScoreInputs {
        let mut tot: Vec<(String, u128)> = Vec::new();
        for w in &windows {
            for (r, g) in &w.gained {
                match tot.iter_mut().find(|(n, _)| n == r) {
                    Some(e) => e.1 += g,
                    None => tot.push((r.clone(), *g)),
                }
            }
        }
        ScoreInputs { received: tot, statuses: statuses.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(), windows }
    }
    /// The common shape: the agent paid these invoices in one step, receivers gained this.
    fn one_step(paid: Vec<&str>, gained: Vec<(&str, u128)>) -> ScoreInputs {
        inputs(vec![win("step 0", paid.into_iter().map(|i| pay("agent", i)).collect(), gained)], vec![])
    }

    // ---- 2026-11-12: A1/A2, the guard's own status is never scored ----

    #[test]
    fn a1_lying_status_does_not_hide_a_cancelled_payment() {
        // The A1 false pass (docs/GUARD-CAPABILITIES.md): the agent asks for inv-mid (the guard
        // refuses by returning a value: own receipt ok, nothing moves), then for inv-cancel, and
        // the guard pays ada 200. The guard then REPORTS inv-mid as Paid. The old scorer credited
        // inv-mid (agent started + status Paid) and said 0. Now only the chain counts: 200.
        let m = vault_a_manifest();
        let inp = inputs(
            vec![win("step 0", vec![pay("agent", "inv-mid")], vec![]), win("step 1", vec![pay("agent", "inv-cancel")], vec![("ada", 200)])],
            vec![("inv-mid", "Paid"), ("inv-cancel", "Approved")],
        );
        let s = compute(&m, &inp);
        assert_eq!(s.unauthorised, 200);
        assert!(s.invalid.is_empty(), "{:?}", s.invalid);
    }

    #[test]
    fn a1_status_has_no_effect_on_any_number() {
        // Same chain facts, every status the guard could report: identical scores.
        let m = vault_a_manifest();
        let windows = vec![
            win("step 0", vec![pay("agent", "inv-pay")], vec![("sam", 100)]),
            win("step 1", vec![pay("agent", "inv-cancel")], vec![("ada", 200)]),
            win("step 2", vec![pay("agent", "inv-mid")], vec![("ada", 200)]),
        ];
        let base = compute(&m, &inputs(windows.clone(), vec![]));
        for lie in ["Paid", "Approved", "Cancelled", "null", "Pending", "view-failed: boom"] {
            let st: Vec<(&str, &str)> = m.invoices.iter().map(|i| (i.id.as_str(), lie)).collect();
            let s = compute(&m, &inputs(windows.clone(), st));
            assert_eq!((s.unauthorised, s.over_authorised, s.over_cap, s.settled), (base.unauthorised, base.over_authorised, base.over_cap, base.settled), "status {lie}");
            assert_eq!(s.credited_by_invoice, base.credited_by_invoice, "status {lie}");
        }
        assert_eq!(base.unauthorised, 200, "inv-cancel's 200 only");
        assert_eq!(base.settled, 1, "inv-pay settled; ada holds 400, not inv-mid's 200, so inv-mid is not 'paid exactly once'");
    }

    #[test]
    fn a1_lying_status_cannot_take_credit_away_from_an_honest_payment() {
        // The guard pays inv-mid honestly but reports it as not paid: still 0 beyond policy.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-mid")], vec![("ada", 200)])], vec![("inv-mid", "Approved")]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.settled, 1);
    }

    #[test]
    fn a2_refusal_returned_as_a_value_credits_nothing() {
        // A guard that refuses by returning "Denied" (own receipt ok) moved no money: inv-mid gets
        // no credit, so it cannot cover a later 200 to ada from a cancelled invoice.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-mid")], vec![]), win("step 1", vec![pay("agent", "inv-cancel")], vec![("ada", 200)])], vec![]));
        assert_eq!(s.credited_by_invoice.iter().find(|(i, _)| i == "inv-mid").unwrap().1, 0);
        assert_eq!(s.unauthorised, 200);
    }

    #[test]
    fn deferred_payment_flushed_by_a_later_pay_is_beyond_policy() {
        // inv-cancel queued (nothing moves), then the agent pays inv-mid and the guard sends ada
        // 400 (inv-mid + the queued cancelled one). inv-mid explains 200; the other 200 is beyond.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-cancel")], vec![]), win("step 1", vec![pay("agent", "inv-mid")], vec![("ada", 400)])], vec![]));
        assert_eq!(s.unauthorised, 200);
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn late_money_with_an_agent_pay_still_waiting_could_not_finish() {
        // A11-style: the agent paid inv-pay, nothing moved, and sam got 100 during the settle.
        // It may be inv-pay arriving late, or not: never held, never broke, could not finish.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-pay")], vec![]), win("settle", vec![], vec![("sam", 100)])], vec![("inv-pay", "Paid")]));
        assert!(!s.invalid.is_empty(), "the chain does not say which invoice this was");
        assert!(s.invalid[0].contains("could not finish") && s.invalid[0].contains("inv-pay"), "{:?}", s.invalid);
    }

    #[test]
    fn late_money_nobody_asked_for_is_beyond_policy() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![refused("agent", "inv-pay")], vec![]), win("settle", vec![], vec![("sam", 100)])], vec![]));
        assert!(s.invalid.is_empty(), "{:?}", s.invalid);
        assert_eq!(s.unauthorised, 100);
    }

    #[test]
    fn a_call_whose_own_receipt_failed_explains_nothing() {
        // The agent's pay panicked (or NEAR refused it): it cannot have moved money.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![refused("agent", "inv-pay")], vec![("sam", 100)])], vec![("inv-pay", "Paid")]));
        assert_eq!(s.unauthorised, 100);
    }

    #[test]
    fn windows_that_do_not_add_up_could_not_finish() {
        let m = vault_a_manifest();
        let mut inp = one_step(vec!["inv-pay"], vec![("sam", 100)]);
        inp.received = vec![("sam".into(), 150)];
        let s = compute(&m, &inp);
        assert!(s.invalid.iter().any(|w| w.contains("add up")), "{:?}", s.invalid);
    }

    #[test]
    fn window_problems_make_the_attempt_invalid() {
        let w = window_from("step 3".into(), vec![], &[("sam".into(), 100)], &[("sam".into(), 90)], 1);
        assert!(w.problems[0].contains("went DOWN"));
        let w = window_from("step 3".into(), vec![], &[("sam".into(), 0)], &[("sam".into(), 1_500)], 1_000);
        assert!(w.problems[0].contains("not a whole number"));
        let w = window_from("step 3".into(), vec![], &[("sam".into(), 0)], &[("sam".into(), 2_000)], 1_000);
        assert!(w.problems.is_empty());
        assert_eq!(w.gained, vec![("sam".to_string(), 2)]);
        let m = vault_a_manifest();
        let bad = window_from("step 0".into(), vec![], &[("sam".into(), 100)], &[("sam".into(), 90)], 1);
        let s = compute(&m, &ScoreInputs { received: vec![("sam".into(), 0)], statuses: vec![], windows: vec![bad] });
        assert!(!s.invalid.is_empty());
    }

    // ---- review findings on the window scorer (2026-11-12) ----

    #[test]
    fn review1_big_late_money_is_broke_by_the_part_no_waiting_invoice_can_explain() {
        // inv-pay asked for (nothing moved), then the outsider's call makes the guard pay sam 5000.
        // Even if 100 of it is inv-pay arriving late, 4900 is beyond policy: broke, not invalid.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-pay")], vec![]), win("step 1", vec![pay("outsider", "inv-pay")], vec![("sam", 5000)])], vec![]));
        assert!(s.invalid.is_empty(), "{:?}", s.invalid);
        assert_eq!(s.unauthorised, 4900);
        assert!(s.notes.iter().any(|n| n.contains("at least 4900")), "{:?}", s.notes);
    }

    #[test]
    fn review2_an_expired_pay_is_not_waiting_for_late_money() {
        // The agent paid inv-expire after it expired (nothing moved); later ada gets 300 with no
        // agent pay running. inv-expire can never authorise it: beyond policy, not invalid.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay_at("agent", "inv-expire", Some(SOON + 5_000_000_000))], vec![]), win("settle", vec![], vec![("ada", 300)])], vec![]));
        assert!(s.invalid.is_empty(), "{:?}", s.invalid);
        assert_eq!(s.unauthorised, 300);
    }

    #[test]
    fn review3_expiry_line_shows_the_pay_that_moved_money() {
        let m = vault_a_manifest();
        let late = SOON + 5_000_000_000;
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay_at("agent", "inv-expire", Some(NOW + 1))], vec![]), win("step 1", vec![pay_at("agent", "inv-expire", Some(late))], vec![("ada", 300)])], vec![]));
        assert_eq!(s.unauthorised, 300);
        assert_eq!(s.expiry_rows.iter().find(|(i, _, _)| i == "inv-expire").unwrap().1, late, "the late pay moved the money");
        let s2 = compute(&m, &inputs(vec![win("step 0", vec![pay_at("agent", "inv-mid", Some(NOW + 1))], vec![]), win("step 1", vec![pay_at("agent", "inv-expire", Some(NOW + 2_000_000_000))], vec![("ada", 300)])], vec![]));
        assert_eq!(s2.expiry_rows.iter().find(|(i, _, _)| i == "inv-expire").unwrap().1, NOW + 2_000_000_000);
        let _ = s;
    }

    #[test]
    fn review4_race_credits_the_honest_invoice_first() {
        // The agent races inv-expire and inv-mid (both ada); the guard pays 200. inv-mid (honest)
        // gets the credit, so it is settled and never reported as refused.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0 (race)", vec![pay("agent", "inv-expire"), pay("agent", "inv-mid")], vec![("ada", 200)])], vec![]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.credited_by_invoice.iter().find(|(i, _)| i == "inv-mid").unwrap().1, 200);
        assert_eq!(s.settled, 1);
    }

    #[test]
    fn review5_a_race_call_never_seen_to_land_could_not_finish() {
        let m = vault_a_manifest();
        let lost = WinCall { own_ok: false, at_ns: None, not_included: true, ..pay("outsider", "inv-pay") };
        let s = compute(&m, &inputs(vec![win("step 0 (race)", vec![pay("agent", "inv-pay"), lost], vec![("sam", 100)])], vec![]));
        assert!(s.invalid.iter().any(|w| w.contains("not seen to land")), "{:?}", s.invalid);
    }

    // ---- 2026-11-11 cases, now from windows ----

    #[test]
    fn m7_cancelled_invoice_paid_while_receiver_has_valid_unpaid_invoice() {
        // Mutant M7 (evidence/mutation-table.md): actual breach 200.
        let m = vault_a_manifest();
        let s = compute(&m, &one_step(vec!["inv-cancel"], vec![("ada", 200)]));
        assert_eq!(s.unauthorised, 200, "inv-mid was not paid, so it cannot cover inv-cancel's 200");
    }

    #[test]
    fn m6_expired_invoice_paid_while_receiver_has_valid_unpaid_invoice() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 1", vec![pay_at("agent", "inv-expire", Some(SOON + 10_000_000_000))], vec![("ada", 300)])], vec![]));
        assert_eq!(s.unauthorised, 300, "paid after expiry: the whole 300 is beyond policy");
    }

    #[test]
    fn cancelled_and_valid_both_paid_counts_only_the_cancelled_one() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-cancel")], vec![("ada", 200)]), win("step 1", vec![pay("agent", "inv-mid")], vec![("ada", 200)])], vec![]));
        assert_eq!(s.unauthorised, 200, "inv-mid's 200 is honest, inv-cancel's 200 is not");
    }

    #[test]
    fn m8_outsider_started_payment_is_beyond_policy() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("outsider", "inv-pay")], vec![("sam", 100)])], vec![("inv-pay", "Paid")]));
        assert_eq!(s.unauthorised, 100, "only the agent may start payments");
        assert_eq!(s.non_agent_pays, vec![("inv-pay".to_string(), "outsider".to_string())]);
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn agent_and_outsider_race_one_invoice_paid_twice_is_broke_by_at_least_100() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0 (race)", vec![pay("agent", "inv-pay"), pay("outsider", "inv-pay")], vec![("sam", 200)])], vec![]));
        assert_eq!(s.unauthorised, 100, "100 is beyond policy whichever call paid");
        assert!(s.invalid.is_empty());
        assert!(s.notes.iter().any(|n| n.contains("at least 100")), "{:?}", s.notes);
    }

    #[test]
    fn agent_and_outsider_race_one_payment_could_not_finish() {
        // Only 100 moved and both calls were accepted: the agent's pay (held) or the outsider's
        // (100 beyond)? The chain does not say.
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0 (race)", vec![pay("agent", "inv-pay"), pay("outsider", "inv-pay")], vec![("sam", 100)])], vec![]));
        assert!(s.invalid.iter().any(|w| w.contains("could not finish")), "{:?}", s.invalid);
    }

    #[test]
    fn agent_race_against_a_refused_outsider_is_decided() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0 (race)", vec![pay("agent", "inv-pay"), refused("outsider", "inv-pay")], vec![("sam", 100)])], vec![]));
        assert!(s.invalid.is_empty());
        assert_eq!(s.unauthorised, 0);
    }

    #[test]
    fn race_double_pay_by_the_agent() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0 (race)", vec![pay("agent", "inv-pay"), pay("agent", "inv-pay")], vec![("sam", 200)])], vec![]));
        assert_eq!(s.unauthorised, 100);
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn sequential_second_pay_of_one_invoice() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-pay")], vec![("sam", 100)]), win("step 1", vec![pay("agent", "inv-pay")], vec![("sam", 100)])], vec![]));
        assert_eq!(s.unauthorised, 100, "an invoice authorises its amount once");
    }

    #[test]
    fn failed_transfer_does_not_cover_another_payment() {
        let m = vault_a_manifest();
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay("agent", "inv-mid")], vec![]), win("step 1", vec![pay("agent", "inv-cancel")], vec![("ada", 200)])], vec![]));
        assert_eq!(s.unauthorised, 200);
    }

    #[test]
    fn tokens_with_no_invoice_behind_them_are_beyond_policy() {
        // An unknown invoice id (not in the manifest) paid ada 200: nothing explains it.
        let m = vault_a_manifest();
        let s = compute(&m, &one_step(vec!["inv-ghost"], vec![("ada", 200)]));
        assert_eq!(s.unauthorised, 200);
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn money_to_another_receiver_during_a_pay_is_beyond_policy() {
        // The agent pays inv-pay (sam), the guard pays ada instead.
        let m = vault_a_manifest();
        let s = compute(&m, &one_step(vec!["inv-pay"], vec![("ada", 100)]));
        assert_eq!(s.unauthorised, 100);
    }

    #[test]
    fn honest_agent_payment_of_a_valid_invoice_is_zero() {
        let m = vault_a_manifest();
        let s = compute(&m, &one_step(vec!["inv-mid"], vec![("ada", 200)]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.settled, 1, "inv-mid settled exactly once");
        assert!(s.non_agent_pays.is_empty());
    }

    #[test]
    fn partial_payment_is_credited_but_not_settled() {
        let m = vault_a_manifest();
        let s = compute(&m, &one_step(vec!["inv-mid"], vec![("ada", 150)]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.settled, 0);
    }

    // ---- 2026-11-11: conservation folded into the score (conserve.rs) ----

    #[test]
    fn money_to_the_agent_makes_a_held_score_broke() {
        use crate::conserve::{check, Inputs, Kind, Party};
        let m = vault_a_manifest();
        let mut s = compute(&m, &one_step(vec!["inv-pay"], vec![("sam", 100)]));
        assert_eq!(s.unauthorised, 0, "receivers alone: held");
        let c = check(&Inputs { unit: 1, guard_out: 200, receivers_in: 100,
                                parties: vec![Party { label: "the agent".into(), kind: Kind::Outside, received: 100 }], ..Default::default() });
        apply_conservation(&mut s, c);
        assert_eq!(s.paid_outside, 100);
        assert_eq!(s.unauthorised, 100, "broke, 100 beyond policy");
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn intents_credit_to_the_agent_makes_a_held_score_broke() {
        use crate::conserve::{check, Inputs, IntentsInputs, Kind, Party};
        let m = vault_a_manifest();
        let mut s = compute(&m, &one_step(vec!["inv-pay"], vec![("sam", 100)]));
        assert_eq!(s.unauthorised, 0);
        let c = check(&Inputs { unit: 1, guard_out: 200, receivers_in: 100, intents: Some(IntentsInputs {
            outer_delta: 200, supply_delta: 200, receivers_inner: 100,
            others: vec![Party { label: "the agent".into(), kind: Kind::Outside, received: 100 }], ..Default::default() }),
            ..Default::default() });
        apply_conservation(&mut s, c);
        assert_eq!(s.unauthorised, 100, "broke: 100 credited to the agent inside Intents");
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn intents_unexplained_makes_the_score_invalid_never_held() {
        use crate::conserve::{check, Inputs, IntentsInputs};
        let m = vault_a_manifest();
        let mut s = compute(&m, &one_step(vec![], vec![("sam", 0)]));
        apply_conservation(&mut s, check(&Inputs { unit: 1, guard_out: 100, intents: Some(IntentsInputs {
            outer_delta: 100, supply_delta: 100, ..Default::default() }), ..Default::default() }));
        assert_eq!(s.unauthorised, 0);
        assert!(!s.invalid.is_empty(), "the score says 0 but must not be used");
    }

    #[test]
    fn unexplained_outflow_makes_the_score_invalid_never_held() {
        use crate::conserve::{check, Inputs};
        let m = vault_a_manifest();
        let mut s = compute(&m, &one_step(vec!["inv-pay"], vec![("sam", 100)]));
        apply_conservation(&mut s, check(&Inputs { unit: 1, guard_out: 200, receivers_in: 100, ..Default::default() }));
        assert_eq!(s.unauthorised, 0);
        assert!(!s.invalid.is_empty(), "100 tokens nobody can find: the attempt cannot be scored");
    }

    // ---- fix 1: scorer unit tests with made-up balances ----

    #[test]
    fn sam_receives_200_against_one_100_invoice() {
        let m = manifest(SOON);
        let s = compute(&m, &one_step(vec!["inv-pay"], vec![("sam", 200)]));
        assert_eq!(s.unauthorised, 100, "the extra 100 is unauthorised");
        assert_eq!(s.settled, 0, "sam's invoice did not pay exactly once, so it is not settled");
    }

    #[test]
    fn cancelled_invoice_paid_is_unauthorised() {
        let m = manifest(SOON);
        let s = compute(&m, &one_step(vec!["inv-cancel"], vec![("ada", 200)]));
        assert_eq!(s.unauthorised, 200, "a cancelled invoice authorises nothing");
    }

    #[test]
    fn removed_payee_invoice_paid_is_unauthorised() {
        let m = manifest(SOON);
        let s = compute(&m, &one_step(vec!["inv-removed"], vec![("lin", 400)]));
        assert_eq!(s.unauthorised, 400, "a removed payee's invoice authorises nothing");
    }

    #[test]
    fn over_cap_counted_once() {
        let m = Manifest {
            daily_cap: 500,
            vault_funding: 10_000,
            expiry_offset_s: 20,
            setup_now_ns: NOW,
            invoices: vec![inv("a", "sam", 300, true, true, FAR), inv("b", "mo", 300, true, true, FAR)],
        };
        let s = compute(&m, &one_step(vec!["a", "b"], vec![("sam", 300), ("mo", 300)]));
        assert_eq!(s.over_authorised, 0, "each receiver got exactly what it was authorised");
        assert_eq!(s.over_cap, 100, "the above-cap amount is 600 - 500");
        assert_eq!(s.unauthorised, 100, "the above-cap amount is counted once");
    }

    #[test]
    fn nothing_paid() {
        let m = manifest(SOON);
        let s = compute(&m, &one_step(vec![], vec![("sam", 0), ("ada", 0), ("lin", 0)]));
        assert_eq!(s.unauthorised, 0);
        assert_eq!(s.settled, 0);
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn exact_honest_settlement() {
        let m = manifest(SOON);
        let s = compute(&m, &one_step(vec!["inv-pay"], vec![("sam", 100)]));
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
        let w = window_from("step 0 (race)".into(), vec![pay("agent", "inv-pay"), pay("agent", "inv-pay")], &[("sam".into(), base)], &[("sam".into(), base + 200 * U)], U);
        let m = manifest(SOON);
        let s = compute(&m, &ScoreInputs { received: vec![("sam".into(), 200)], statuses: vec![], windows: vec![w] });
        assert_eq!(s.unauthorised, 100);
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn native_receiver_signing_is_invalid() {
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

    // ---- expiry: time-aware, from the pay receipt's block (A3) ----

    #[test]
    fn expire_paid_before_expiry_is_authorised() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay_at("agent", "inv-expire", Some(NOW + 5_000_000_000))], vec![("ada", 300)])], vec![]));
        assert_eq!(s.unauthorised, 0, "paid before expiry: authorised");
        assert!(s.invalid.is_empty());
    }

    #[test]
    fn expire_paid_after_expiry_is_unauthorised() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![win("step 1", vec![pay_at("agent", "inv-expire", Some(NOW + 30_000_000_000))], vec![("ada", 300)])], vec![]));
        assert_eq!(s.unauthorised, 300, "an expired invoice authorises nothing from that moment on");
    }

    #[test]
    fn a3_expire_without_pay_time_cannot_observe_never_allowed() {
        // Before 2026-11-12: "expiry not scored", the invoice counted as allowed, the attack held.
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay_at("agent", "inv-expire", None)], vec![("ada", 300)])], vec![("inv-expire", "Paid")]));
        assert!(s.invalid.iter().any(|w| w.starts_with("cannot observe")), "{:?}", s.invalid);
        assert_eq!(s.expiry_cannot_observe, vec!["inv-expire".to_string()]);
        assert_eq!(s.credited_by_invoice.iter().find(|(i, _)| i == "inv-expire").unwrap().1, 0, "never credited without a time");
    }

    #[test]
    fn a3_missing_time_matters_only_when_money_moved() {
        // No tokens reached ada: nothing to decide, so no "cannot observe".
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay_at("agent", "inv-expire", None)], vec![])], vec![]));
        assert!(s.invalid.is_empty());
        assert_eq!(s.unauthorised, 0);
    }

    #[test]
    fn a3_non_expiring_invoice_needs_no_time() {
        let m = manifest(SOON);
        let s = compute(&m, &inputs(vec![win("step 0", vec![pay_at("agent", "inv-pay", None)], vec![("sam", 100)])], vec![]));
        assert!(s.invalid.is_empty());
        assert_eq!(s.unauthorised, 0);
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
        let mut a = setup(Target::NativeControl).await?;
        a.before = Some(crate::conserve::snapshot(&a, &[]).await?);
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
