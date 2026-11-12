//! Controlled race ordering (branch `race-ordering`, design: RACE-ORDERING-DESIGN section 3).
//!
//! A plain `race` step fires its calls together and hopes (seq.rs `do_race`, unchanged). A
//! `race` step with `offsets` asks for each later payment's guard CHECK to run a chosen number
//! of blocks after the first payment's check:
//!
//! ```json
//! {"race": [ {"actor":"agent","method":"pay","args":{"id":"inv-pay"}},
//!            {"actor":"agent","method":"pay","args":{"id":"inv-pay"}} ],
//!  "offsets": [0, 1]}
//! ```
//!
//! Timed mode (no `hold`, the normal token): wait until a new block has just been made (head H),
//! send leg 1 at once (accepted in H+2, its check runs in H+3, as measured: see SEND_TO_CHECK),
//! then for each later leg wait until the head is H+offset and send it. The harness cannot place a
//! transaction in a block, so it records what happened instead and never claims more: per leg it
//! writes a `race` facts object into that leg's `receipts` value (requested offset, the head when
//! it was sent, whether every block in the step's range really exists). The verdict (race proven,
//! tie, sequential, or "not produced") is computed from those facts by ONE judge,
//! `tools/race/ordering.py`, never here.
//!
//! Offsets above 1 are refused in timed mode: with the normal token the callback lands 2 blocks
//! after the check, so a second check 2 blocks later is a payment in a row, not a race.
//!
//! Held mode (`"hold": "until-all-checks"`, needs `--token slow`, contracts/slow-token): the token
//! moves the money at once but parks its answer until the harness releases it (NEAR yield/resume),
//! so the first payment's callback cannot run early. The harness sends leg 1, waits until the token
//! holds one answer, sends each later leg when its check should land `offset` blocks after leg 1's,
//! waits until that leg was either parked by the token (its check passed) or finished (refused),
//! then releases every parked answer. The order "every check before any callback" is then by
//! construction; only the exact offsets depend on timing, and they are read back the same way.
//! `hold` without `--token slow` is a hard error, never a silent fallback to timed mode.
//!
//! This file never fast-forwards: the sandbox's fast-forward skips block numbers (no code runs in
//! the skipped blocks), so "k blocks apart" is only ever read from blocks that actually ran.

use crate::seq::{
    build_tx, finish, is_protocol_rejection, method_of, print_step, short, target_id, StepOutcome, OUTCOME_NOT_INCLUDED,
    RACE_INCLUSION_TIMEOUT_S,
};
use crate::setup::Arena;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::future::IntoFuture;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

/// The slow token's build output (contracts/slow-token is its own cargo workspace).
pub const SLOW_TOKEN_WASM: &str = "../contracts/slow-token/target/wasm32-unknown-unknown/release/slow_token.wasm";
static SLOW: AtomicBool = AtomicBool::new(false);

/// `--token slow` | `--token test` | absent (= test). Anything else is refused.
pub fn select_token(v: Option<&str>) -> Result<()> {
    match v {
        None | Some("test") => Ok(()),
        Some("slow") => {
            SLOW.store(true, Ordering::SeqCst);
            println!("TOKEN: slow (contracts/slow-token: can park transfer answers; holding is off until a held race step)");
            Ok(())
        }
        Some(o) => bail!("--token must be test or slow, got {o:?}"),
    }
}
pub fn slow() -> bool {
    SLOW.load(Ordering::SeqCst)
}
/// Which token wasm setup deploys (relative to harness/).
pub fn token_wasm() -> &'static str {
    if slow() {
        SLOW_TOKEN_WASM
    } else {
        crate::setup::TOKEN_WASM
    }
}
pub fn token_build_hint() -> &'static str {
    if slow() {
        "; for the slow token: (cd contracts/slow-token && cargo build --release --target wasm32-unknown-unknown)"
    } else {
        ""
    }
}
/// Slow token only: say so in the result file. A default run writes exactly the JSON it wrote before.
pub fn mark_result(rj: &mut Value) {
    if slow() {
        rj["token"] = json!({"kind": "slow", "wasm_sha256": crate::setup::sha256_file(&crate::setup::resolve(SLOW_TOKEN_WASM)).unwrap_or_default()});
    }
}
/// Blocks between the head a transaction is sent at and the block its guard check runs in, as
/// measured on the sandbox (sent at head H: accepted in H+2, checked in H+3; 648 of the 649 race legs
/// with send facts in evidence/, the other one, c3-matrix-s4held/s4-cap-held--vault-a-slow--try3 leg 2,
/// H+1 and H+2). Held mode uses it to
/// aim; the judge reads the real offset back from the trace either way.
const SEND_TO_CHECK: u64 = 3;
/// Held mode: give up waiting for a leg to be parked or to finish after this long.
const HOLD_WAIT: Duration = Duration::from_secs(30);
/// Held mode: how long to wait for each leg to finish after release (a parked answer that nobody
/// releases is woken by NEAR after ~200 blocks).
const HELD_FINISH_S: u64 = 400;

/// Largest offset a step may ask for (the slow token holds an answer for at most ~200 blocks).
pub const MAX_OFFSET: u64 = 150;
/// Held mode: smallest gap between consecutive offsets. A call is sent only once the previous one is
/// seen parked (its transfer ran, one block after its check), and a call sent at head H is checked
/// at H+3, so the next check can be no earlier than 4 blocks after the previous one. Measured: a run
/// asking [0, 2, 4] landed at [0, 4, 8] 10 of 10 times (evidence/race-ordering-2026-11-11.md).
pub const MIN_HELD_GAP: u64 = 4;
/// Largest offset timed mode (normal token) can produce as a race (callback = check + 2).
pub const MAX_TIMED_OFFSET: u64 = 1;
/// How often the head block is polled while waiting for a tick (local RPC, a few ms per call).
const POLL: Duration = Duration::from_millis(3);
/// Give up waiting for a block tick after this long (the sandbox makes blocks on a timer).
const TICK_TIMEOUT: Duration = Duration::from_secs(20);

fn offsets_of(step: &Value) -> Result<Option<Vec<u64>>> {
    match step.get("offsets") {
        None => Ok(None),
        Some(Value::Array(xs)) => xs
            .iter()
            .map(|x| x.as_u64().context("offsets must be whole numbers >= 0"))
            .collect::<Result<Vec<_>>>()
            .map(Some),
        Some(other) => bail!("offsets must be an array of whole numbers, got {other}"),
    }
}

/// Load-time check of a race step's `offsets` / `hold` (called from seq.rs `load_sequence`).
/// A step without either key is not looked at, so every existing file loads exactly as before.
pub fn validate(step: &Value, seq_name: &str) -> Result<()> {
    let has_offsets = step.get("offsets").is_some();
    let hold = step.get("hold");
    if !has_offsets && hold.is_none() {
        return Ok(());
    }
    let calls = match step.get("race").and_then(|r| r.as_array()) {
        Some(c) => c,
        None => bail!("{seq_name}: \"offsets\" and \"hold\" are only allowed on a race step: {step}"),
    };
    let offs = offsets_of(step)
        .with_context(|| format!("{seq_name}: bad offsets"))?
        .with_context(|| format!("{seq_name}: a race step with \"hold\" also needs \"offsets\" (one per call)"))?;
    if offs.len() != calls.len() {
        bail!("{seq_name}: {} offsets for {} race calls (need one per call)", offs.len(), calls.len());
    }
    if offs.len() < 2 {
        bail!("{seq_name}: a staggered race needs at least 2 calls");
    }
    if offs[0] != 0 {
        bail!("{seq_name}: the first offset must be 0 (offsets are counted from the first call's check)");
    }
    if offs.windows(2).any(|w| w[1] < w[0]) {
        bail!("{seq_name}: offsets must not decrease: {offs:?}");
    }
    if let Some(m) = offs.iter().find(|o| **o > MAX_OFFSET) {
        bail!("{seq_name}: offset {m} is above the maximum {MAX_OFFSET}");
    }
    match hold {
        None => {
            if let Some(m) = offs.iter().find(|o| **o > MAX_TIMED_OFFSET) {
                bail!(
                    "{seq_name}: offset {m} needs \"hold\" (the slow token). Without it the first call's callback lands 2 blocks \
                     after its check, so a check {m} blocks later is a payment in a row, not a race"
                );
            }
        }
        Some(Value::String(s)) if s == "until-all-checks" || s == "no-release" => {
            if let Some(w) = offs.windows(2).find(|w| w[1] - w[0] < MIN_HELD_GAP) {
                bail!(
                    "{seq_name}: in held mode each call's offset must be at least {MIN_HELD_GAP} above the one before (got {} then {}): \
                     the harness sends a call only after it has seen the previous one parked, which takes {MIN_HELD_GAP} blocks on the sandbox",
                    w[0], w[1]
                );
            }
        }
        Some(other) => bail!("{seq_name}: hold must be \"until-all-checks\" (or \"no-release\", the timeout negative control), got {other}"),
    }
    for c in calls {
        let c = c.get("call").unwrap_or(c);
        if c["actor"].as_str().map(|a| a != "agent" && a != "outsider").unwrap_or(true) {
            bail!("race call actor must be \"agent\" or \"outsider\" in {seq_name}: {c}");
        }
    }
    Ok(())
}

async fn head(a: &Arena) -> Result<u64> {
    Ok(a.worker.view_block().await?.height())
}

/// Poll until the head block changes; return the new height. Right after a tick there is the
/// longest possible time before the next block, so a transaction sent now lands in head+1.
async fn wait_for_tick(a: &Arena) -> Result<u64> {
    let start = Instant::now();
    let h0 = head(a).await?;
    loop {
        let h = head(a).await?;
        if h != h0 {
            return Ok(h);
        }
        if start.elapsed() > TICK_TIMEOUT {
            bail!("no new block in {TICK_TIMEOUT:?} (head stayed at {h0}); is the sandbox making blocks?");
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Poll until the head is at least `h`; return the head seen (may be above `h` if a block was
/// missed, which the judge then sees as a wrong offset).
async fn wait_until_head(a: &Arena, h: u64) -> Result<u64> {
    let start = Instant::now();
    loop {
        let now = head(a).await?;
        if now >= h {
            return Ok(now);
        }
        if start.elapsed() > TICK_TIMEOUT {
            bail!("head did not reach block {h} within {TICK_TIMEOUT:?} (at {now})");
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Every block from `lo` to `hi` (inclusive) exists. False if any height is unknown, which is
/// what a fast-forward leaves behind (it skips heights).
async fn blocks_contiguous(a: &Arena, lo: u64, hi: u64) -> bool {
    for h in lo..=hi {
        if a.worker.view_block().block_height(h).await.is_err() {
            return false;
        }
    }
    true
}

fn not_included(i: usize, c: &Value, tgt_short: &str, tgt_name: &str, args: Value, failure: String) -> Result<StepOutcome> {
    let who = c["actor"].as_str().unwrap_or("?").to_string();
    let method = method_of(c)?.to_string();
    print_step(i, "race", &who, tgt_short, &method, &args, OUTCOME_NOT_INCLUDED, &failure);
    Ok(StepOutcome {
        kind: "race-call",
        actor: who,
        target: tgt_name.to_string(),
        method,
        args,
        success: false,
        outcome: OUTCOME_NOT_INCLUDED,
        failure,
        logs: vec![],
        view_json: None,
        receipts: None,
        own_ok: false, // never included: no receipt ran, so it moved nothing (as seq.rs do_race)
        ran_at_ns: None,
    })
}

/// Lowest and highest block a leg's trace mentions (transaction block .. last receipt).
fn trace_range(t: &Value) -> Option<(u64, u64)> {
    let mut hs: Vec<u64> = t["receipts"].as_array()?.iter().filter_map(|r| r["block_height"].as_u64()).collect();
    if let Some(h) = t["tx_block_height"].as_u64() {
        hs.push(h);
    }
    Some((*hs.iter().min()?, *hs.iter().max()?))
}

/// Run one staggered race step. Returns one StepOutcome per leg, in leg order.
pub async fn run(a: &Arena, i: usize, step: &Value) -> Result<Vec<StepOutcome>> {
    let calls = step["race"].as_array().context("race step needs calls")?;
    let offs = offsets_of(step)?.context("staggered race needs offsets")?;
    let held_mode = step.get("hold").is_some();
    if held_mode && !slow() {
        bail!("step {i}: \"hold\" needs the slow token (run with --token slow); refusing (never a silent fallback to timed mode)");
    }
    // Same element styles as do_race, never silently (fix 5.1).
    let legs: Vec<&Value> = calls
        .iter()
        .map(|w| match w.get("call") {
            Some(inner) => {
                println!("  FORMAT FIX step {i}: race element wrapped in a \"call\" object; unwrapped");
                inner
            }
            None => w,
        })
        .collect();

    // Build every transaction first, so the time between sends is only polling and one send.
    let mut built = Vec::new();
    for c in &legs {
        let (tx, tgt_name, args) = build_tx(a, i, c)?;
        let (tgt, _) = target_id(a, c)?;
        built.push((tx, tgt, tgt_name, args));
    }

    if held_mode {
        let release = step["hold"].as_str() != Some("no-release");
        return run_held(a, i, &legs, built, &offs, release).await;
    }
    let tick = wait_for_tick(a).await?;
    println!("  step {i} [race-timed] offsets {offs:?}; block {tick} just made, sending leg 1 now");
    let mut sent = Vec::new(); // (leg, c, tgt, tgt_name, args, Option<status>, facts)
    let mut early: Vec<(usize, StepOutcome)> = Vec::new();
    for (k, ((tx, tgt, tgt_name, args), c)) in built.into_iter().zip(legs.iter()).enumerate() {
        let target_head = tick + offs[k];
        let head_before = wait_until_head(a, target_head).await?;
        let t0 = Instant::now();
        let res = tx.transact_async().await;
        let send_ms = t0.elapsed().as_millis() as u64;
        let head_after = head(a).await?;
        let facts = json!({
            "leg": k + 1, "requested_offset": offs[k], "mode": "timed",
            "tick_block": tick, "wanted_head": target_head,
            "sent_when_head_was": head_before, "head_after_send": head_after, "send_ms": send_ms,
            "fast_forward_used": false,
        });
        match res {
            Ok(status) => sent.push((k, *c, tgt, tgt_name, args, status, facts)),
            Err(e) if is_protocol_rejection(&e) => {
                let mut o = finish(a, i, "race-call", c, tgt, tgt_name, args, Err(e)).await?;
                o.receipts = Some(json!({"race": facts}));
                early.push((k, o));
            }
            Err(e) => {
                let mut o = not_included(i, c, &short(tgt), tgt_name, args, format!("async broadcast failed, no protocol reason given: {e:?}"))?;
                o.receipts = Some(json!({"race": facts}));
                early.push((k, o));
            }
        }
    }

    finish_legs(a, i, early, sent, tick, RACE_INCLUSION_TIMEOUT_S).await
}

type Sent<'a> = (usize, &'a Value, &'a near_workspaces::AccountId, &'static str, Value, near_workspaces::operations::TransactionStatus, Value);

/// Await every sent leg, attach its facts, check that the step's blocks all exist, print one line per leg.
async fn finish_legs<'a>(a: &'a Arena, i: usize, early: Vec<(usize, StepOutcome)>, sent: Vec<Sent<'a>>, first_head: u64, wait_s: u64) -> Result<Vec<StepOutcome>> {
    let mut done: Vec<(usize, StepOutcome)> = early;
    for (k, c, tgt, tgt_name, args, status, facts) in sent {
        let mut o = match tokio::time::timeout(Duration::from_secs(wait_s), status.into_future()).await {
            Ok(res) => finish(a, i, "race-call", c, tgt, tgt_name, args, res).await?,
            Err(_) => not_included(
                i,
                c,
                &short(tgt),
                tgt_name,
                args,
                format!("not finished within {wait_s}s (async broadcast returns no reason)"),
            )?,
        };
        o.receipts = Some(match o.receipts.take() {
            Some(mut t) => {
                t["race"] = facts;
                t
            }
            None => json!({"race": facts}),
        });
        done.push((k, o));
    }
    done.sort_by_key(|(k, _)| *k);
    let mut out: Vec<StepOutcome> = done.into_iter().map(|(_, o)| o).collect();

    // Did every block from the first send to the last receipt really run? (no fast-forward gap)
    let ranges: Vec<(u64, u64)> = out.iter().filter_map(|o| o.receipts.as_ref().and_then(trace_range)).collect();
    if let (Some(lo), Some(hi)) = (ranges.iter().map(|r| r.0).min(), ranges.iter().map(|r| r.1).max()) {
        let ok = blocks_contiguous(a, lo.min(first_head), hi).await;
        for o in out.iter_mut() {
            if let Some(t) = o.receipts.as_mut() {
                t["race"]["blocks_checked"] = json!([lo.min(first_head), hi]);
                t["race"]["blocks_contiguous"] = json!(ok);
            }
        }
    }
    for o in &out {
        let t = o.receipts.as_ref();
        let r = t.and_then(|t| t["receipts"].as_array());
        let check = r.and_then(|r| r.first()).and_then(|x| x["block_height"].as_u64());
        let f = t.map(|t| &t["race"]);
        println!(
            "      race leg {} requested_offset={} sent_at_head={} check_block={} check_ok={}",
            f.map(|f| f["leg"].clone()).unwrap_or(Value::Null),
            f.map(|f| f["requested_offset"].clone()).unwrap_or(Value::Null),
            f.map(|f| f["sent_when_head_was"].clone()).unwrap_or(Value::Null),
            check.map(|c| c.to_string()).unwrap_or_else(|| "none".into()),
            r.and_then(|r| r.first()).map(|x| x["ok"].clone()).unwrap_or(Value::Null),
        );
    }
    Ok(out)
}

async fn held_count(a: &Arena) -> Result<usize> {
    let v: Vec<Value> = a.token.view("held").await?.json()?;
    Ok(v.len())
}

/// Token-account call (set_hold / release). The harness holds the token account, as at setup;
/// testers never sign as it.
async fn token_admin(a: &Arena, method: &str, args: Value) -> Result<()> {
    let r = a.token.call(method).args_json(args).max_gas().transact().await?;
    if !r.is_success() {
        bail!("slow token {method} failed: {:?}", r.failures());
    }
    Ok(())
}

/// Wait until the token holds more than `before` answers (the leg's check passed and its transfer is
/// parked) or the leg's transaction finished (the guard refused it, or it failed). Returns which.
async fn wait_parked_or_done(a: &Arena, before: usize, st: &near_workspaces::operations::TransactionStatus) -> Result<&'static str> {
    let start = Instant::now();
    loop {
        if held_count(a).await? > before {
            return Ok("parked");
        }
        if let Ok(Poll::Ready(_)) = st.status().await {
            return Ok("finished");
        }
        if start.elapsed() > HOLD_WAIT {
            return Ok("timeout");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn run_held<'a>(
    a: &'a Arena,
    i: usize,
    legs: &[&'a Value],
    built: Vec<(near_workspaces::operations::CallTransaction, &'a near_workspaces::AccountId, &'static str, Value)>,
    offs: &[u64],
    release: bool,
) -> Result<Vec<StepOutcome>> {
    token_admin(a, "set_hold", json!({"on": true})).await?;
    let first_head = head(a).await?;
    println!("  step {i} [race-held] offsets {offs:?}; slow token holding answers from head {first_head}");
    let mut sent: Vec<Sent<'a>> = Vec::new();
    let mut early: Vec<(usize, StepOutcome)> = Vec::new();
    let mut leg1_check: Option<u64> = None;
    let mut seen = 0usize;
    for (k, ((tx, tgt, tgt_name, args), c)) in built.into_iter().zip(legs.iter()).enumerate() {
        let wanted_head = leg1_check.map(|c1| (c1 + offs[k]).saturating_sub(SEND_TO_CHECK));
        let head_before = match wanted_head {
            Some(h) => wait_until_head(a, h).await?,
            None => head(a).await?,
        };
        let res = tx.transact_async().await;
        let mut facts = json!({
            "leg": k + 1, "requested_offset": offs[k], "mode": "held",
            "wanted_head": wanted_head, "sent_when_head_was": head_before, "fast_forward_used": false,
        });
        match res {
            Ok(status) => {
                let how = wait_parked_or_done(a, seen, &status).await?;
                if how == "parked" {
                    seen += 1;
                }
                if k == 0 {
                    // leg 1's transfer ran one block after its check; read it from the token
                    let v: Vec<Value> = a.token.view("held").await?.json()?;
                    leg1_check = v.first().and_then(|h| h["since_block"].as_u64()).map(|b| b.saturating_sub(1));
                    if leg1_check.is_none() {
                        println!("  step {i} [race-held] leg 1 was not parked ({how}); later legs are sent at once (the judge decides)");
                        leg1_check = Some(head(a).await?);
                    }
                }
                facts["after_send"] = json!(how);
                facts["held_seen"] = json!(seen);
                sent.push((k, *c, tgt, tgt_name, args, status, facts));
            }
            Err(e) if is_protocol_rejection(&e) => {
                let mut o = finish(a, i, "race-call", c, tgt, tgt_name, args, Err(e)).await?;
                o.receipts = Some(json!({"race": facts}));
                early.push((k, o));
            }
            Err(e) => {
                let mut o = not_included(i, c, &short(tgt), tgt_name, args, format!("async broadcast failed, no protocol reason given: {e:?}"))?;
                o.receipts = Some(json!({"race": facts}));
                early.push((k, o));
            }
        }
    }
    let released_at = head(a).await?;
    if release {
        token_admin(a, "release", json!({})).await?;
        println!("  step {i} [race-held] {seen} parked answer(s) released at head {released_at}");
    } else {
        // Negative control for the timeout path: nobody releases; NEAR wakes each parked answer
        // itself after ~200 blocks, the token logs HOLD-TIMEOUT, and the judge says not-produced.
        println!("  step {i} [race-held] NOT releasing {seen} parked answer(s) (hold = no-release): waiting for NEAR's own timeout");
    }
    token_admin(a, "set_hold", json!({"on": false})).await?;
    for s in sent.iter_mut() {
        s.6["released_at_head"] = if release { json!(released_at) } else { Value::Null };
    }
    finish_legs(a, i, early, sent, first_head, HELD_FINISH_S).await
}

#[cfg(test)]
mod tests {
    use super::validate;
    use serde_json::json;

    fn step(offsets: serde_json::Value, n: usize) -> serde_json::Value {
        let call = json!({"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}});
        json!({"race": vec![call; n], "offsets": offsets})
    }

    #[test]
    fn plain_race_is_not_looked_at() {
        let call = json!({"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}});
        assert!(validate(&json!({"race": [call.clone(), call]}), "t").is_ok());
        assert!(validate(&json!({"call": {"actor": "agent", "method": "pay"}}), "t").is_ok());
    }

    #[test]
    fn good_timed_offsets() {
        assert!(validate(&step(json!([0, 0]), 2), "t").is_ok());
        assert!(validate(&step(json!([0, 1]), 2), "t").is_ok());
        assert!(validate(&step(json!([0, 0, 1]), 3), "t").is_ok());
    }

    #[test]
    fn bad_offsets_refused() {
        assert!(validate(&step(json!([1, 1]), 2), "t").is_err(), "first must be 0");
        assert!(validate(&step(json!([0, 1, 0]), 3), "t").is_err(), "decreasing");
        assert!(validate(&step(json!([0]), 2), "t").is_err(), "wrong length");
        assert!(validate(&step(json!([0, 1, 1]), 2), "t").is_err(), "wrong length");
        assert!(validate(&step(json!([0, -1]), 2), "t").is_err(), "negative");
        assert!(validate(&step(json!([0, 1.5]), 2), "t").is_err(), "fraction");
        assert!(validate(&step(json!("0,1"), 2), "t").is_err(), "not an array");
        assert!(validate(&step(json!([0, 2]), 2), "t").is_err(), "timed mode above 1");
        assert!(validate(&json!({"call": {}, "offsets": [0, 0]}), "t").is_err(), "not a race");
    }

    #[test]
    fn hold_shape() {
        let mut s = step(json!([0, 4]), 2);
        s["hold"] = json!("until-all-checks");
        assert!(validate(&s, "t").is_ok());
        s["offsets"] = json!([0, 151]);
        assert!(validate(&s, "t").is_err(), "above 150");
        s["offsets"] = json!([0, 2]);
        assert!(validate(&s, "t").is_err(), "held gap below 4");
        let call = json!({"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}});
        let three = json!({"race": [call.clone(), call.clone(), call], "offsets": [0, 4, 8], "hold": "until-all-checks"});
        assert!(validate(&three, "t").is_ok());
        let mut s = step(json!([0, 4]), 2);
        s["hold"] = json!("no-release");
        assert!(validate(&s, "t").is_ok());
        s["hold"] = json!("yes");
        assert!(validate(&s, "t").is_err(), "unknown hold value");
        let call = json!({"actor": "agent", "method": "pay", "args": {"id": "inv-pay"}});
        assert!(validate(&json!({"race": [call.clone(), call], "hold": "until-all-checks"}), "t").is_err(), "hold without offsets");
    }

    #[test]
    fn actor_checked() {
        let call = json!({"actor": "owner", "method": "pay", "args": {"id": "inv-pay"}});
        assert!(validate(&json!({"race": [call.clone(), call], "offsets": [0, 0]}), "t").is_err());
    }
}
