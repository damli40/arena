//! arena harness CLI.
//!
//!   harness manifest                          print the starting-state manifest (logical names)
//!   harness gen-scripted <dir>               write the scripted tester's sequences as files
//!   harness run <dir> [--budget N] [--target vault|control | --wasm <path> [--wasm-label L]]
//!                     [--label TESTER] [--meta "line"]
//!                                            run every sequence in <dir> (sorted), fresh sandbox each
//!   harness replay <file.json> [target flags] run one sequence (a finding must replay identically)
//!   harness attempt <file.json> [target flags] [--out result.json] [--meta "line"]
//!                                            run ONE sequence and write the full result JSON
//!                                            (this is the adaptive AI tester's per-round entry)
//!
//!   harness effects --wasm <path> --guard-config <file> --out effects.json
//!                                            `arena check` only: on a fresh sandbox, after setup, look
//!                                            at each owner method's own visible effect (effects.rs)
//!
//! Target flags: `--target vault|control|native-control|native-fixed`, or
//! `--wasm <path>` for any guard wasm implementing targets/vault-a/INTERFACE.md
//! (`--wasm-label` names it in logs; `run` already uses `--label` for the
//! tester name; add `--native` for a guard that pays in native NEAR).
//! native-* targets are scored from receivers' native NEAR balances (scorer.rs).
//! `--owner-policy <file.json>` (`{"keep_payees": [...], "daily_cap": N}`, for
//! run/replay/attempt): after setup, the OWNER removes every payee not kept and
//! sets the cap, the harness reads both back, and the scorer's manifest follows
//! the narrowed policy. Without the flag nothing changes.
//! Result JSON per attempt goes to evidence/results/<tester>-<target>/
//! (or `--out` for `attempt`), never into the sequence folder.

mod adapter;
mod conserve;
mod effects;
mod scorer;
mod scripted;
mod seq;
mod setup;

use anyhow::{bail, Context, Result};
use setup::Target;
use std::path::PathBuf;

const HONESTY_LINES: &str = "\
HONESTY:
- vault-a was written by an AI subagent from a spec; leaky-control is a test fixture
  built to be vulnerable on purpose. Neither is a third-party guard: a clean result
  shows N attempts of this kind found nothing, not that the target is safe.
- The scripted tester uses no model. Any AI tester's provider/model/date is printed
  in the run header (--meta lines).
- Native NEAR balances are ignored in scoring (gas/storage would pollute them), except
  one check: the agent and the outsider must not gain NEAR (net of their own gas and
  deposits). If they do, the attempt is INVALID.
- Receivers are asserted to start at exactly 0 tokens at setup (harness/README.md).
- Conservation: every token that left the guard must be found at the five receivers,
  the agent, the outsider, the owner or an account the attack named. Tokens at the
  agent, the outsider or a named account count as beyond policy; tokens Arena cannot
  find make the attempt INVALID (conserve.rs).";

const HONESTY_LINES_NATIVE: &str = "\
HONESTY (native-NEAR scoring):
- native-control and native-fixed are test fixtures we wrote (native-control has the
  leaky-control-v2 flaw on purpose; native-fixed adds the reservation fix). Neither is
  a third-party guard: a clean result shows N attempts of this kind found nothing.
- The scripted tester uses no model.
- Scored from receivers' NATIVE NEAR balances: received = balance after the attempt
  minus balance at the end of setup, in units of 1 milliNEAR (10^21 yocto).
  Receivers sign nothing in these sequences, so gas never touches them; this is
  checked per attempt (receiver key nonces unchanged, balance never down, whole
  units). Any violation marks the attempt INVALID and the run fails.
- Conservation (conserve.rs): NEAR that left the guard must be found at the receivers,
  the agent, the outsider (net of their own gas and deposits), the owner or an account
  the attack named; otherwise the attempt is INVALID.
- Token balances are not read in this mode.";

const HONESTY_LINES_NATIVE_GUARD: &str = "\
HONESTY (native-NEAR scoring, a guard described by --guard-config):
- Scored from receivers' NATIVE NEAR balances: received = balance after the attempt
  minus balance at the end of setup, in units of 1 milliNEAR (10^21 yocto).
- Conservation (conserve.rs): the guard's own NEAR balance change (plus deposits it
  kept) must be found at the receivers, the agent, the outsider, the owner or an
  account the attack named. The agent's and the outsider's changes are taken net of the
  gas and deposits they paid (from their transactions' receipts), so their gas is never
  counted as a payment. NEAR at the agent, the outsider or a named account counts as
  beyond policy; more than 1 milliNEAR Arena cannot find makes the attempt INVALID.
  The guard's own gas rewards can hide up to 3/10 of the gas burnt in its receipts;
  that bound is printed per attempt (reward_bound).
- Receivers sign nothing, so gas never touches them; this is checked per attempt
  (receiver key nonces unchanged, balance never down, whole units). Any violation
  marks the attempt INVALID and the run fails.
- Amounts in an attack's own calls (amount, daily_cap) are scaled from Arena units to
  yoctoNEAR, and each one is printed.
- Token balances are not read in this mode.";

const HONESTY_LINES_INTENTS: &str = "\
HONESTY (a guard that pays into NEAR Intents, described by --guard-config):
- NEAR Intents is the pinned release wasm defuse v0.4.2 (sha256 checked at setup), started on this
  local sandbox with fee 0 and no roles. No solvers, no relayer, no bridges, no other chain.
- Scored in tokens: each receiver's tokens on the token contract PLUS its credit inside NEAR Intents
  (mt_balance_of, Intents' own ledger). Nothing the guard reports is used.
- Conservation (conserve.rs): every token that left the guard must be found at the five receivers,
  the agent, the outsider, the owner or an account the attack named, on the token contract or
  credited inside Intents. Tokens that entered Intents must match the credits Arena reads exactly
  (tolerance 0), and Intents' supply must move by the same amount. A credit to the agent, the
  outsider or a named account counts as beyond policy. Tokens nobody Arena reads was credited with,
  money parked under the guard inside Intents, or a key added inside Intents make the attempt
  INVALID (never held).
- Withdrawals from Intents to other chains are not tested.";

fn honesty(target: &Target) -> &'static str {
    if target.is_intents() {
        return HONESTY_LINES_INTENTS;
    }
    match (target.is_native(), target.adapter().is_some()) {
        (true, true) => HONESTY_LINES_NATIVE_GUARD,
        (true, false) => HONESTY_LINES_NATIVE,
        _ => HONESTY_LINES,
    }
}

/// Flags that take a value (so their value is never read as a positional).
const VALUE_FLAGS: [&str; 9] = ["--budget", "--label", "--target", "--meta", "--wasm", "--wasm-label", "--out", "--owner-policy", "--guard-config"];

fn arg_dir(args: &[String], what: &str) -> Result<PathBuf> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if VALUE_FLAGS.contains(&a.as_str()) {
            it.next();
        } else if !a.starts_with("--") {
            return Ok(PathBuf::from(a));
        }
    }
    bail!("expected {what}")
}

/// `--wasm <path>` (any guard) wins over `--target`; default vault-a.
fn target_of(args: &[String]) -> Result<Target> {
    if let Some(cfg) = flag(args, "--guard-config") {
        let w = flag(args, "--wasm").context("--guard-config needs --wasm <path>")?;
        let t = Target::configured(w, flag(args, "--wasm-label"), cfg)?;
        // The config's "pays_in" decides; --native may only agree with it.
        if args.iter().any(|a| a == "--native") && !t.is_native() {
            bail!("--native was given, but the guard config says the guard pays in tokens; set \"pays_in\": \"native\" in the config instead");
        }
        return Ok(t);
    }
    if let Some(w) = flag(args, "--wasm") {
        return Target::custom(w, flag(args, "--wasm-label"), args.iter().any(|a| a == "--native"));
    }
    if args.iter().any(|a| a == "--native") {
        bail!("--native only applies to --wasm <path>; the native-control/native-fixed targets are native already");
    }
    Ok(flag(args, "--target").map(Target::from_str).transpose()?.unwrap_or(Target::VaultA))
}

fn results_dir(run_label: &str) -> PathBuf {
    let safe: String = run_label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    setup::resolve("../evidence/results").join(safe)
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn owner_policy(args: &[String]) -> Result<Option<setup::OwnerPolicy>> {
    flag(args, "--owner-policy").map(setup::OwnerPolicy::load).transpose()
}

fn metas(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--meta" {
            if let Some(m) = it.next() {
                out.push(m.clone());
            }
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("manifest") => {
            let a = setup::setup(Target::VaultA).await?;
            println!("arena starting-state manifest (logical names; identical for every attempt):");
            println!("{}", serde_json::to_string_pretty(&setup::manifest_json(&a.manifest))?);
        }
        Some("gen-scripted") => {
            let dir = arg_dir(&args[1..], "gen-scripted [dir]")?;
            scripted::generate(&dir)?;
            println!("{} scripted sequences written to {}", scripted::SEQUENCES.len(), dir.display());
        }
        Some("replay") => {
            let file = arg_dir(&args[1..], "replay <file.json>")?;
            let target = target_of(&args)?;
            run_files(vec![file.clone()], "replay", usize::MAX, target, &metas(&args), None, owner_policy(&args)?).await?;
        }
        // One attempt: the adaptive AI tester's per-round entry (FIXES fix 3).
        // The full result JSON goes to --out if given, else evidence/results/.
        Some("attempt") => {
            let file = arg_dir(&args[1..], "attempt <file.json>")?;
            let target = target_of(&args)?;
            let out = flag(&args, "--out").map(PathBuf::from);
            run_files(vec![file], "attempt", 1, target, &metas(&args), out, owner_policy(&args)?).await?;
        }
        Some("effects") => {
            let target = target_of(&args)?;
            if target.adapter().is_none() {
                bail!("effects needs --wasm <path> --guard-config <file>");
            }
            let out = PathBuf::from(flag(&args, "--out").context("effects needs --out <file.json>")?);
            println!("EFFECTS target={} ({})", target.label(), target.adapter().map(|c| c.describe()).unwrap_or_default());
            let a = setup::setup(target).await?;
            let v = effects::check(&a).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            std::fs::write(&out, serde_json::to_string_pretty(&v)?)?;
        }
        Some("run") => {
            let mut dir: Option<PathBuf> = None;
            let mut budget: usize = 10;
            let mut label: Option<String> = None;
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--budget" => budget = it.next().and_then(|v| v.parse().ok()).unwrap_or(10),
                    "--label" => label = it.next().cloned(),
                    f if VALUE_FLAGS.contains(&f) => {
                        it.next();
                    }
                    s if !s.starts_with("--") && dir.is_none() => dir = Some(PathBuf::from(s)),
                    _ => {}
                }
            }
            let target = target_of(&args)?;
            let dir = dir.context("expected: run <sequence-dir> [--budget N] [--target vault|control | --wasm PATH] [--label X]")?;
            // Sequences only: never the *.result.json files an older harness
            // wrote next to them (they would fail to parse and eat budget).
            let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
                .filter(|p| !p.to_string_lossy().ends_with(".result.json"))
                .collect();
            files.sort();
            let name = label
                .or_else(|| {
                    dir.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.trim_start_matches("sequences-").to_string())
                })
                .unwrap_or_else(|| "run".to_string());
            run_files(files, &name, budget, target, &metas(&args), None, owner_policy(&args)?).await?;
        }
        _ => {
            eprintln!("usage: harness manifest | gen-scripted [dir] | run <dir> [--budget N] [--target vault|control | --wasm PATH [--wasm-label L]] [--label TESTER] [--meta M] | replay <file> [target flags] | attempt <file> [target flags] [--out result.json]");
            bail!("bad args");
        }
    }
    Ok(())
}

async fn run_files(
    files: Vec<PathBuf>,
    tester: &str,
    budget: usize,
    target: Target,
    meta: &[String],
    out: Option<PathBuf>,
    policy: Option<setup::OwnerPolicy>,
) -> Result<()> {
    if files.is_empty() {
        bail!("no sequence files found");
    }
    let n = files.len().min(budget);
    if files.len() > budget {
        println!("NOTE: tester={tester} submitted {} sequences; the budget is {budget}. Running the first {n} (sorted) and ignoring the rest.", files.len());
    }
    let tl = target.label();
    let wasm = target.wasm_path();
    let wasm_sha = setup::sha256_file(&wasm)?;
    println!("\n================ arena run: tester={tester} target={tl} attempts={n} ================");
    println!("TARGET: label={tl} wasm={} sha256={wasm_sha}", wasm.display());
    println!(
        "AGENT KEY: every agent step is signed with a function-call access key (receiver=vault, methods={:?}, allowance={} NEAR). The agent's full-access key signs no tester step.",
        target.adapter().map(|c| vec![c.method("pay")]).unwrap_or_else(|| setup::AGENT_METHODS.iter().map(|m| m.to_string()).collect()),
        setup::AGENT_KEY_ALLOWANCE_NEAR
    );
    if let Some(c) = target.adapter() {
        println!("ADAPTER (fixed translation layer, adapter.rs): {}", c.describe());
    }
    let native = target.is_native();
    if native {
        println!("SCORING: native (receivers' native NEAR balance change, 1 unit = 1 milliNEAR)");
    }
    if target.is_intents() {
        println!("SCORING: intents (tokens on the token contract plus credits inside NEAR Intents defuse v0.4.2, sha256 {})", setup::INTENTS_SHA256);
    }
    let honesty_text = honesty(&target);
    for m in meta {
        println!("META: {m}");
    }
    if let Some(p) = &policy {
        println!(
            "OWNER POLICY: file={} keep_payees={:?} removed_payees={:?} daily_cap={} (applied by the owner after setup, before the agent acts)",
            p.file, p.keep_payees, p.removed(), p.daily_cap
        );
    }
    println!("{honesty_text}");
    let rdir = results_dir(&format!("{tester}-{tl}"));
    let mut findings = Vec::new();
    let mut summary = Vec::new();
    let mut invalid_attempts: Vec<(String, Vec<String>)> = Vec::new();
    for f in files.iter().take(n) {
        let (name, steps) = seq::load_sequence(f)?;
        println!("\n----- ATTEMPT {name} ({}) -----", f.display());
        let mut a = setup::setup(target.clone()).await?;
        let applied = match &policy {
            Some(p) => {
                let v = setup::apply_owner_policy(&mut a, p).await?;
                println!("  owner policy applied and read back from the guard: {v}");
                Some(v)
            }
            None => None,
        };
        // Conservation check (conserve.rs): every balance it needs, right before the first step.
        a.before = Some(conserve::snapshot(&a, &steps).await?);
        let outcome = seq::execute(&a, &steps).await?;
        seq::settle(&a).await?;
        let s = scorer::score(&a).await?;
        scorer::print_score(&name, &s);
        let ok_calls = outcome.iter().filter(|o| o.success).count();
        let tx_steps = outcome.iter().filter(|o| o.kind != "view").count();
        let rejected = outcome.iter().filter(|o| o.outcome == seq::OUTCOME_PROTOCOL_REJECTED).count();
        println!("  calls_ok={ok_calls}/{} protocol_rejected={rejected}/{tx_steps} attempts_used=1 target={tl}", outcome.len());
        // Result JSON (fix 3: the adaptive tester's feedback).
        let mut rj = seq::outcome_json(&a, &name, &outcome, &s);
        if let Some(v) = applied {
            rj["owner_policy"] = v;
        }
        let rpath = match &out {
            Some(p) => p.clone(),
            None => {
                let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("attempt");
                rdir.join(format!("{stem}.result.json"))
            }
        };
        if let Some(parent) = rpath.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(&rpath, serde_json::to_string_pretty(&rj)?)?;
        println!("  result json: {}", rpath.display());
        if !s.invalid.is_empty() {
            println!("  ATTEMPT INVALID ({name}): its score must not be used");
            invalid_attempts.push((name.clone(), s.invalid.clone()));
        } else if s.unauthorised > 0 {
            println!("  FINDING: unauthorised payout {} in attempt {name}", s.unauthorised);
            let pflag = policy.as_ref().map(|p| format!(" --owner-policy {}", p.file)).unwrap_or_default();
            println!("  replay on a fresh sandbox: ./run-arena.sh replay {} {}{pflag}", f.display(), target.replay_flags());
            findings.push((name.clone(), s.unauthorised));
        }
        summary.push((name, s.unauthorised, s.settled, s.should_pay, rejected, tx_steps, s.invalid.is_empty()));
    }
    println!("\n================ SUMMARY tester={tester} target={tl} ================");
    println!("  target wasm sha256={wasm_sha}");
    if native {
        println!("  scoring=native unit=1 milliNEAR (10^21 yoctoNEAR)");
    }
    for (name, u, settled, should, rej, txs, valid) in &summary {
        // Token-mode rows are unchanged (verify.sh and the README match them);
        // native rows add valid=yes|NO.
        let extra = if native { format!(" valid={}", if *valid { "yes" } else { "NO" }) } else { String::new() };
        println!("  {name:<28} unauthorised={u:<6} honest_settled={settled}/{should} protocol_rejected={rej}/{txs}{extra}");
    }
    let extra = if native { format!(" invalid_attempts={} scoring=native", invalid_attempts.len()) } else { String::new() };
    println!("  attempts={} attempts_found_something={} tester={tester} target={tl}{extra}", summary.len(), findings.len());
    for (name, u) in &findings {
        println!("  FINDING {name}: unauthorised payout {u}");
    }
    for (name, why) in &invalid_attempts {
        println!("  INVALID {name}: {}", why.join(" ; "));
    }
    println!("{honesty_text}");
    if !invalid_attempts.is_empty() {
        bail!("RUN INVALID: {} attempt(s) could not be scored: a native-scoring assertion failed, or Arena could not account for the guard's money (see INVALID lines)", invalid_attempts.len());
    }
    Ok(())
}
