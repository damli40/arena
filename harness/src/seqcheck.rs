//! Check-only path for attack files (2026-11-12): what the engine would do with a file, with
//! no sandbox. `arena-harness check-seq [--intents] <files or dirs>` prints one JSON line per
//! file. tools/agreement/compare.py feeds it the same files as the gatekeeper
//! (tools/hunter/validate.py) and fails if the gatekeeper lets through a file the engine would
//! refuse, or would run differently from how the gatekeeper read it.
//!
//! How it reads a file: first the real `seq::load_sequence` (the same function a run calls),
//! then `plan`, which walks the steps the way `seq::execute` does and stops where a run would
//! stop before anything is sent: an unknown step, an empty race, an actor other than agent or
//! outsider (`Arena::actor`), an unknown target (`target_id`), a missing method (`method_of`),
//! a bad add_key permission. It mirrors execute() rather than sharing code with it, so the two
//! can drift; the unit tests below read seq.rs and fail if execute() changes which keys it
//! tests or in what order. docs/SCHEMA-AGREEMENT.md "Next step" is the plan to share the code.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The step keys `seq::execute` tests, in the order it tests them.
pub const DISPATCH_ORDER: [&str; 6] = ["race", "call", "add_key", "view", "wait_blocks", "wait_seconds"];

/// target_id(): default vault; a target that is not a string also means vault.
fn target(c: &Value, intents: bool) -> Result<&'static str> {
    match c.get("target").and_then(|t| t.as_str()).unwrap_or("vault") {
        "vault" => Ok("vault"),
        "token" => Ok("token"),
        "intents" if intents => Ok("intents"),
        "intents" => bail!("target \"intents\" needs a guard that pays into NEAR Intents"),
        t => bail!("unknown target {t:?}"),
    }
}

/// Arena::actor(): only agent or outsider.
fn actor(v: &Value, what: &str) -> Result<String> {
    let a = v["actor"].as_str().with_context(|| format!("{what} needs an actor"))?;
    if a != "agent" && a != "outsider" {
        bail!("sequence actor must be \"agent\" or \"outsider\", got {a:?}");
    }
    Ok(a.to_string())
}

/// build_tx(): what one call would send. gas None = max gas; deposit None = no deposit.
fn call_plan(c: &Value, intents: bool) -> Result<Value> {
    let actor = actor(c, "call")?;
    let target = target(c, intents)?;
    let method = c["method"].as_str().context("call/view needs a method")?;
    Ok(json!({
        "actor": actor, "target": target, "method": method,
        "args": c.get("args").cloned().unwrap_or(json!({})),
        "gas_tgas": c.get("gas_tgas").and_then(|v| v.as_u64()),
        "deposit_yocto": c.get("deposit_yocto").and_then(|v| v.as_u64()),
    }))
}

/// Walk the steps the way seq::execute does, without sending anything.
pub fn plan(steps: &[Value], intents: bool) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (i, st) in steps.iter().enumerate() {
        let p = if let Some(calls) = st.get("race").and_then(|r| r.as_array()) {
            if calls.is_empty() {
                bail!("step {i}: race with no calls");
            }
            // do_race(): an element {"call": {...}} is unwrapped, anything else is the call.
            let cs = calls
                .iter()
                .map(|w| call_plan(w.get("call").unwrap_or(w), intents))
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("step {i}"))?;
            json!({"kind": "race", "calls": cs})
        } else if st.get("call").is_some() {
            json!({"kind": "call", "call": call_plan(&st["call"], intents).with_context(|| format!("step {i}"))?})
        } else if st.get("add_key").is_some() {
            let k = &st["add_key"];
            let a = actor(k, "add_key").with_context(|| format!("step {i}"))?;
            let perm = k.get("permission").and_then(|p| p.as_str()).unwrap_or("full_access");
            if perm != "full_access" && perm != "function_call_token" {
                bail!("step {i}: add_key permission must be full_access | function_call_token, got {perm:?}");
            }
            json!({"kind": "add_key", "actor": a, "permission": perm})
        } else if st.get("view").is_some() {
            let v = &st["view"];
            let t = target(v, intents).with_context(|| format!("step {i}"))?;
            let m = v["method"].as_str().with_context(|| format!("step {i}: view needs a method"))?;
            json!({"kind": "view", "target": t, "method": m, "args": v.get("args").cloned().unwrap_or(json!({}))})
        } else if let Some(n) = st.get("wait_blocks").and_then(|v| v.as_u64()) {
            json!({"kind": "wait_blocks", "n": n})
        } else if let Some(s) = st.get("wait_seconds").and_then(|v| v.as_u64()) {
            json!({"kind": "wait_seconds", "n": s})
        } else {
            bail!("unknown step: {st}");
        };
        out.push(p);
    }
    Ok(out)
}

fn check_file(path: &Path, intents: bool) -> Value {
    let r = crate::seq::load_sequence(path).and_then(|(name, steps)| Ok((name, plan(&steps, intents)?)));
    match r {
        Ok((name, steps)) => json!({"file": path.display().to_string(), "ok": true, "name": name, "steps": steps}),
        Err(e) => json!({"file": path.display().to_string(), "ok": false, "error": format!("{e:#}")}),
    }
}

/// `check-seq [--intents] <files or dirs>`: one JSON line per file. Exit status is 0 even when
/// files are refused; the caller reads the lines.
pub fn cli(args: &[String]) -> Result<()> {
    let intents = args.iter().any(|a| a == "--intents");
    let mut files: Vec<PathBuf> = Vec::new();
    for a in args.iter().filter(|a| !a.starts_with("--")) {
        let p = PathBuf::from(a);
        if p.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(&p)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
                .collect();
            v.sort();
            files.extend(v);
        } else {
            files.push(p);
        }
    }
    if files.is_empty() {
        bail!("check-seq needs at least one file or directory");
    }
    for f in &files {
        println!("{}", check_file(f, intents));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQ_RS: &str = include_str!("seq.rs");
    const SCHEMA: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../schema/attack.schema.json"));

    fn sorted(v: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = v.iter().map(|s| s.to_string()).collect();
        v.sort();
        v
    }

    /// The schema's step menu equals the engine's.
    #[test]
    fn step_kinds_match_schema() {
        let s: Value = serde_json::from_str(SCHEMA).unwrap();
        let kinds: Vec<String> = s["$defs"]["step"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|o| o["properties"].as_object().unwrap().keys().cloned())
            .collect();
        let mut kinds = kinds;
        kinds.sort();
        assert_eq!(kinds, sorted(&DISPATCH_ORDER), "schema step kinds differ from the engine's");
    }

    /// load_sequence's list of known steps is the same six.
    #[test]
    fn load_sequence_knows_the_same_kinds() {
        let body = &SEQ_RS[SEQ_RS.find("pub fn load_sequence").unwrap()..];
        let line = body.lines().find(|l| l.contains("let known = [")).expect("load_sequence's known list");
        let inner = &line[line.find('[').unwrap() + 1..line.rfind(']').unwrap()];
        let names: Vec<&str> = inner.split(',').map(|x| x.trim().trim_matches('"')).collect();
        assert_eq!(sorted(&names), sorted(&DISPATCH_ORDER));
    }

    /// execute() tests the step keys in the order plan() mirrors. If this fails, execute()
    /// changed: update plan() and DISPATCH_ORDER to match, then re-run tools/agreement/compare.py.
    #[test]
    fn execute_dispatch_order_is_mirrored() {
        let start = SEQ_RS.find("pub async fn execute").unwrap();
        let end = start + SEQ_RS[start..].find("pub async fn settle").unwrap();
        let body = &SEQ_RS[start..end];
        let mut seen = Vec::new();
        for (pos, _) in body.match_indices("st.get(\"") {
            let rest = &body[pos + 8..];
            let k = &rest[..rest.find('"').unwrap()];
            if !seen.contains(&k) {
                seen.push(k);
            }
        }
        assert_eq!(seen, DISPATCH_ORDER.to_vec(), "seq::execute's dispatch changed");
    }

    // ---- Stopgap until "Next step" in docs/SCHEMA-AGREEMENT.md (one shared function). ----
    // seqcheck.rs COPIES the engine's decisions; the tests above only check step names and
    // their order. This one fails on ANY change to the engine lines the copy mirrors (which
    // target a missing "target" means, which waits execute() accepts, how a race element is
    // unwrapped, actor and permission checks, gas and deposit). Its expected text is
    // seqcheck.snapshot. If it fails: change plan() above to match the engine, re-run
    // tools/agreement/compare.py, then refresh the snapshot. A snapshot catches edits to
    // these lines only; an engine change elsewhere (a new helper these lines call) can still
    // slip past.

    const SETUP_RS: &str = include_str!("setup.rs");
    const SNAPSHOT: &str = include_str!("seqcheck.snapshot");

    /// The lines of the item starting at `marker`, up to the closing brace at its indentation.
    fn item<'a>(src: &'a str, marker: &str) -> Vec<&'a str> {
        let s = src.find(marker).unwrap_or_else(|| panic!("engine item {marker:?} not found"));
        let ls = src[..s].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let close = format!("{}}}", &src[ls..s]);
        let mut out = Vec::new();
        for l in src[ls..].split('\n') {
            out.push(l);
            if l == close {
                break;
            }
        }
        out
    }

    fn engine_snapshot() -> String {
        let sections: [(&str, &str, &[&str]); 7] = [
            ("seq.rs", "fn target_id<", &[]),
            ("seq.rs", "fn method_of(", &[]),
            ("seq.rs", "fn build_tx(", &[]),
            ("seq.rs", "async fn do_add_key(", &["let perm", "match perm", "\"full_access\" =>", "\"function_call_token\" =>", "p => bail", "k[\"actor\"]", "a.actor("]),
            ("seq.rs", "async fn do_race(", &["\"call\"", "build_tx"]),
            ("seq.rs", "pub async fn execute(", &["st.get(", "bail!", "is_empty"]),
            ("setup.rs", "pub fn actor(", &[]),
        ];
        let mut out = Vec::new();
        for (file, marker, needles) in sections {
            out.push(format!("## {file} {marker}"));
            let src = if file == "seq.rs" { SEQ_RS } else { SETUP_RS };
            for l in item(src, marker) {
                let t = l.trim();
                if t.is_empty() || t.starts_with("//") {
                    continue;
                }
                if !needles.is_empty() && !needles.iter().any(|n| t.contains(n)) {
                    continue;
                }
                out.push(t.to_string());
            }
        }
        out.join("\n")
    }

    #[test]
    fn engine_lines_that_seqcheck_copies_are_unchanged() {
        let now = engine_snapshot();
        let want = SNAPSHOT.trim_end();
        if now != want {
            let first = now.lines().zip(want.lines()).position(|(a, b)| a != b).unwrap_or(now.lines().count().min(want.lines().count()));
            panic!(
                "the engine changed a line seqcheck.rs copies (first difference at snapshot line {}):\n  engine now: {:?}\n  snapshot:   {:?}\nUpdate plan() to match, re-run tools/agreement/compare.py, then refresh harness/src/seqcheck.snapshot.",
                first + 1,
                now.lines().nth(first).unwrap_or("<end>"),
                want.lines().nth(first).unwrap_or("<end>")
            );
        }
    }

    /// What the copy decides, on a table of inputs at the boundaries. Documents the engine's
    /// own limits (it has none on waits or step count; the gatekeeper holds those).
    #[test]
    fn copy_decisions_table() {
        for (c, want) in [
            (json!({}), Some("vault")),
            (json!({"target": "vault"}), Some("vault")),
            (json!({"target": "token"}), Some("token")),
            (json!({"target": 5}), Some("vault")),
            (json!({"target": null}), Some("vault")),
            (json!({"target": "owner"}), None),
            (json!({"target": "intents"}), None),
        ] {
            assert_eq!(target(&c, false).ok(), want, "target of {c}");
        }
        assert_eq!(target(&json!({"target": "intents"}), true).ok(), Some("intents"));
        let kind = |st: Value| plan(&[st], false).ok().map(|p| p[0]["kind"].as_str().unwrap().to_string());
        for n in [0u64, 1, 200, 201, u64::MAX] {
            assert_eq!(kind(json!({"wait_blocks": n})).as_deref(), Some("wait_blocks"), "wait_blocks {n}");
            assert_eq!(kind(json!({"wait_seconds": n})).as_deref(), Some("wait_seconds"), "wait_seconds {n}");
        }
        for bad in [json!({"wait_blocks": -1}), json!({"wait_blocks": 5.0}), json!({"wait_blocks": "5"}), json!({"wait_seconds": -1})] {
            assert_eq!(kind(bad.clone()), None, "{bad}");
        }
        let pay = json!({"actor": "agent", "method": "pay"});
        for n in 1..=6 {
            let r = json!({"race": vec![pay.clone(); n]});
            assert_eq!(kind(r).as_deref(), Some("race"), "race of {n}");
        }
    }

    #[test]
    fn plan_reads_the_six_kinds() {
        let steps: Vec<Value> = serde_json::from_str(
            r#"[{"call":{"actor":"agent","method":"pay","args":{"id":"a"}}},
                {"view":{"target":"token","method":"ft_balance_of"}},
                {"race":[{"actor":"agent","method":"pay"},{"call":{"actor":"outsider","method":"pay","gas_tgas":5}}]},
                {"wait_blocks":3},{"wait_seconds":1},{"add_key":{"actor":"agent"}}]"#,
        )
        .unwrap();
        let p = plan(&steps, false).unwrap();
        let kinds: Vec<&str> = p.iter().map(|s| s["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["call", "view", "race", "wait_blocks", "wait_seconds", "add_key"]);
        assert_eq!(p[2]["calls"][1]["gas_tgas"], 5);
        assert!(plan(&[json!({"race": []})], false).is_err());
        assert!(plan(&[json!({"call": {"actor": "owner", "method": "pay"}})], false).is_err());
        assert!(plan(&[json!({"view": {"target": "intents", "method": "x"}})], false).is_err());
        assert!(plan(&[json!({"view": {"target": "intents", "method": "x"}})], true).is_ok());
    }
}
