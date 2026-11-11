//! Sandbox tests for the 2026-11-11 additions: opt-in on chain, results other contracts can query,
//! and the in-place upgrade from the receipts-only code. Build the wasm first:
//!   (cd receipts && cargo build --release --target wasm32-unknown-unknown)
//! then: (cd receipts/host && cargo test --release --test onchain)
//!
//! The upgrade test also needs the receipts-only wasm (sha256 aba31658..., the code live on testnet
//! before the upgrade) at the path in ARENA_OLD_RECEIPTS_WASM, so cargo lists it as "ignored" unless
//! you add `-- --include-ignored`; then it fails if the variable is not set, never passes without it.
//! How to build that wasm: see evidence/onchain-2026-11-11.md.
use near_workspaces::types::NearToken;
use near_workspaces::{Account, Contract, Worker};
use near_workspaces::network::Sandbox;
use serde_json::{json, Value};

const WASM: &str = "../target/wasm32-unknown-unknown/release/arena_receipts.wasm";
const CALLER_WASM: &str = "../target/wasm32-unknown-unknown/release/arena_example_caller.wasm";
const H1: &str = "0382023bed1208667d8ef56af7223c2a46d8fa069caf1414c2aa84c08b48510e";
const H2: &str = "52a40f3200e313c1def01c3dabe85cec9669d69cee575d93560360b36598c7b1";
const UNKNOWN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const EV: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const C1: &str = "c08295f0c08295f0c08295f0c08295f0c08295f0";
const C2: &str = "86ccccdfff54def98bcc89a0615cd471da040c83";

fn err_text<T: std::fmt::Debug>(r: near_workspaces::result::Result<T, near_workspaces::result::ExecutionFailure>) -> String {
    format!("{:?}", r.unwrap_err())
}

async fn setup() -> anyhow::Result<(Worker<Sandbox>, Contract, Account)> {
    let worker = near_workspaces::sandbox().await?;
    let c = worker.dev_deploy(&std::fs::read(WASM)?).await?;
    let owner = worker.dev_create_account().await?;
    assert!(c.call("new").args_json(json!({"owner": owner.id()})).transact().await?.is_success());
    Ok((worker, c, owner))
}

fn result(hash: &str, suite: &str, status: &str, beyond: &str, intent: Option<&str>, commit: &str) -> Value {
    json!({"guard_code_hash": hash, "suite": suite, "suite_version": "v1", "status": status,
        "attacks_ran": 5, "not_applicable": 1, "beyond_policy": beyond, "against_intent": intent,
        "setup": null, "arena_commit": commit, "evidence_sha256": EV, "evidence_path": "evidence/x.md",
        "attestation_sha256": null})
}

async fn publish_result(owner: &Account, c: &Contract, r: Value) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(owner.call(c.id(), "publish_result").args_json(json!({"result": r})).deposit(NearToken::from_millinear(50)).transact().await?)
}

async fn answer(c: &Contract, hash: &str, suite: Option<&str>, commit: Option<&str>) -> anyhow::Result<Value> {
    Ok(c.view("arena_result").args_json(json!({"guard_code_hash": hash, "suite": suite, "arena_commit": commit})).await?.json()?)
}

#[tokio::test]
async fn opt_in_only_by_guard_or_parent() -> anyhow::Result<()> {
    let (worker, c, _owner) = setup().await?;
    let root = worker.root_account()?; // test.near
    let parent = root.create_subaccount("parent").initial_balance(NearToken::from_near(5)).transact().await?.into_result()?;
    let guard = parent.create_subaccount("guard").initial_balance(NearToken::from_near(2)).transact().await?.into_result()?;
    let stranger = worker.dev_create_account().await?;
    // a look-alike: "xparent.test.near" is not the parent of "guard.parent.test.near"
    let lookalike = root.create_subaccount("xparent").initial_balance(NearToken::from_near(2)).transact().await?.into_result()?;
    let dep = NearToken::from_millinear(20);
    let opt = |who: &Account, args: Value, d: NearToken| who.call(c.id(), "opt_in").args_json(args).deposit(d).transact();
    let args = |h: &str| json!({"guard": guard.id(), "code_hash": h, "contact": "dami@example.org", "expires_at": null, "pays_in": "token"});

    // refused: stranger, look-alike, grandparent (test.near), no deposit, all-zero hash, bad pays_in
    for who in [&stranger, &lookalike, &root] {
        let e = err_text(opt(who, args(H1), dep).await?.into_result());
        assert!(e.contains("only the guard account itself or its parent"), "{e}");
    }
    assert!(err_text(opt(&guard, args(H1), NearToken::from_yoctonear(0)).await?.into_result()).contains("for storage"));
    assert!(err_text(opt(&guard, args(&"0".repeat(64)), dep).await?.into_result()).contains("all zeros"));
    assert!(err_text(opt(&guard, args("ABC"), dep).await?.into_result()).contains("64 lowercase hex"));
    let mut bad = args(H1);
    bad["pays_in"] = json!("usdc");
    assert!(err_text(opt(&guard, bad, dep).await?.into_result()).contains("pays_in"));
    let now = worker.view_block().await?.timestamp();
    let mut past = args(H1);
    past["expires_at"] = json!(now.saturating_sub(1).to_string());
    assert!(err_text(opt(&guard, past, dep).await?.into_result()).contains("in the past"));
    let none: Value = c.view("opt_in_of").args_json(json!({"guard": guard.id()})).await?.json()?;
    assert!(none.is_null(), "nothing stored by refused calls");

    // parent opts in: recorded with signer_role parent; excess deposit refunded
    let before = parent.view_account().await?.balance;
    let ok = opt(&parent, args(H1), dep).await?;
    assert!(ok.is_success(), "{:?}", ok.failures());
    assert!(ok.logs().iter().any(|l| l.starts_with("EVENT_JSON:") && l.contains("\"event\":\"opt_in\"")));
    let spent = before.saturating_sub(parent.view_account().await?.balance);
    assert!(spent < NearToken::from_millinear(10), "parent spent {spent}");
    let o: Value = c.view("opt_in_of").args_json(json!({"guard": guard.id()})).await?.json()?;
    assert_eq!(o["signer_role"], "parent");
    assert_eq!(o["signed_by"], parent.id().as_str());
    assert_eq!(o["code_hash"], H1);
    assert_eq!(o["active"], true);
    println!("opt-in storage + gas paid by signer: {spent}");

    // opt-out needs 1 yocto; the guard itself opts out -> parent can no longer opt it back in
    let e = err_text(guard.call(c.id(), "opt_out").args_json(json!({"guard": guard.id()})).transact().await?.into_result());
    assert!(e.contains("attach 1 yoctoNEAR"), "{e}");
    let e = err_text(stranger.call(c.id(), "opt_out").args_json(json!({"guard": guard.id()})).deposit(NearToken::from_yoctonear(1)).transact().await?.into_result());
    assert!(e.contains("only the guard account itself or its parent"), "{e}");
    let out = guard.call(c.id(), "opt_out").args_json(json!({"guard": guard.id()})).deposit(NearToken::from_yoctonear(1)).transact().await?;
    assert!(out.is_success() && out.json::<bool>()?);
    let gone: Value = c.view("opt_in_of").args_json(json!({"guard": guard.id()})).await?.json()?;
    assert!(gone.is_null());
    let e = err_text(opt(&parent, args(H1), dep).await?.into_result());
    assert!(e.contains("opted out itself"), "{e}");
    // the guard itself can opt back in, which also lets the parent manage it again
    assert!(opt(&guard, args(H2), dep).await?.is_success());
    let o: Value = c.view("opt_in_of").args_json(json!({"guard": guard.id()})).await?.json()?;
    assert_eq!(o["signer_role"], "guard");
    assert_eq!(o["code_hash"], H2);
    assert!(opt(&parent, args(H1), dep).await?.is_success(), "parent allowed again after the guard opted back in");

    // expiry: an opt-in that expires soon shows active=false after more blocks
    let soon = worker.view_block().await?.timestamp() + 3_000_000_000; // ~3 s
    let mut exp = args(H1);
    exp["expires_at"] = json!(soon.to_string());
    assert!(opt(&parent, exp, dep).await?.is_success());
    worker.fast_forward(200).await?;
    let o: Value = c.view("opt_in_of").args_json(json!({"guard": guard.id()})).await?.json()?;
    assert_eq!(o["active"], false, "block time now {}", worker.view_block().await?.timestamp());

    // listing
    assert_eq!(c.view("opt_in_count").args_json(json!({})).await?.json::<u32>()?, 1);
    let all: Vec<Value> = c.view("opt_ins").args_json(json!({"from_index": 0, "limit": 10})).await?.json()?;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["guard"], guard.id().as_str());
    let page2: Vec<Value> = c.view("opt_ins").args_json(json!({"from_index": 1, "limit": 10})).await?.json()?;
    assert!(page2.is_empty());
    Ok(())
}

#[tokio::test]
async fn results_bound_to_code_hash_and_commit() -> anyhow::Result<()> {
    let (worker, c, owner) = setup().await?;
    let stranger = worker.dev_create_account().await?;

    // unknown hash -> not_tested, never null, no numbers
    let a = answer(&c, UNKNOWN, None, None).await?;
    assert_eq!(a["status"], "not_tested");
    assert!(a["attacks_ran"].is_null() && a["beyond_policy"].is_null() && a["arena_commit"].is_null());
    assert!(a["status_means"].as_str().unwrap().starts_with("not_tested"));

    // refused publishes
    assert!(err_text(publish_result(&stranger, &c, result(H1, "race", "held", "0", None, C1)).await?.into_result()).contains("only the owner"));
    assert!(err_text(publish_result(&owner, &c, result(H1, "race", "held", "100", None, C1)).await?.into_result()).contains("held needs"));
    assert!(err_text(publish_result(&owner, &c, result(H1, "race", "held", "0", Some("5"), C1)).await?.into_result()).contains("held needs"));
    assert!(err_text(publish_result(&owner, &c, result(H1, "race", "broke", "0", Some("0"), C1)).await?.into_result()).contains("broke needs"));
    assert!(err_text(publish_result(&owner, &c, result(H1, "race", "not_tested", "0", None, C1)).await?.into_result()).contains("cannot be published"));
    assert!(err_text(publish_result(&owner, &c, result(H1, "race", "held", "0", None, &format!("{C1}-dirty"))).await?.into_result()).contains("arena_commit"));
    assert!(err_text(publish_result(&owner, &c, result(H1, "race", "held", "0", None, "abc")).await?.into_result()).contains("arena_commit"));
    let mut zero_ran = result(H1, "race", "held", "0", None, C1);
    zero_ran["attacks_ran"] = json!(0);
    assert!(err_text(publish_result(&owner, &c, zero_ran).await?.into_result()).contains("held needs"));
    let mut bad_att = result(H1, "race", "held", "0", None, C1);
    bad_att["attestation_sha256"] = json!("nope");
    assert!(err_text(publish_result(&owner, &c, bad_att).await?.into_result()).contains("attestation_sha256"));
    let mut bad_status = result(H1, "race", "held", "0", None, C1);
    bad_status["status"] = json!("safe");
    assert!(!publish_result(&owner, &c, bad_status).await?.is_success(), "\"safe\" is not a status");
    assert!(c.view("arena_results_for").args_json(json!({"guard_code_hash": H1})).await?.json::<Vec<Value>>()?.is_empty());

    // publish: race held at C1 (with attestation + setup), injection broke at C1
    let mut race = result(H1, "race", "held", "0", None, C1);
    race["attestation_sha256"] = json!(EV);
    race["setup"] = json!("mode=fixed");
    let out = publish_result(&owner, &c, race).await?;
    assert!(out.is_success(), "{:?}", out.failures());
    assert!(out.logs().iter().any(|l| l.contains("\"event\":\"publish_result\"")));
    assert!(publish_result(&owner, &c, result(H1, "injection", "broke", "0", Some("450"), C1)).await?.is_success());

    // specific suite
    let a = answer(&c, H1, Some("race"), None).await?;
    assert_eq!(a["status"], "held");
    assert_eq!(a["guard_code_hash"], H1);
    assert_eq!(a["arena_commit"], C1);
    assert_eq!(a["setup"], "mode=fixed");
    assert_eq!(a["attestation_sha256"], EV);
    assert_eq!(a["attacks_ran"], 5);
    assert_eq!(a["not_applicable"], 1);
    assert!(a["status_means"].as_str().unwrap().contains("found no way past"));
    assert!(!a["status_means"].as_str().unwrap().to_lowercase().contains("safe"));

    // no suite: the worst latest result wins, so held never hides broke
    let a = answer(&c, H1, None, None).await?;
    assert_eq!(a["status"], "broke");
    assert_eq!(a["suite"], "injection");
    assert_eq!(a["against_intent"], "450");
    assert_eq!(a["suites_considered"], 2);

    // commit binding: asking for another commit -> not_tested; a newer commit's result is separate
    assert_eq!(answer(&c, H1, Some("race"), Some(C2)).await?["status"], "not_tested");
    assert!(publish_result(&owner, &c, result(H1, "race", "incomplete", "0", None, C2)).await?.is_success());
    assert_eq!(answer(&c, H1, Some("race"), None).await?["status"], "incomplete", "newest result in the suite");
    assert_eq!(answer(&c, H1, Some("race"), Some(C1)).await?["status"], "held", "pinned to C1");
    assert_eq!(answer(&c, H1, Some("race"), Some(C2)).await?["status"], "incomplete");

    // a result for one code hash never answers for another
    assert_eq!(answer(&c, H2, Some("race"), None).await?["status"], "not_tested");
    assert_eq!(answer(&c, H1, Some("nope"), None).await?["status"], "not_tested");
    assert_eq!(c.view("arena_results_for").args_json(json!({"guard_code_hash": H1})).await?.json::<Vec<Value>>()?.len(), 3);

    // the receipts side is untouched by any of this
    let rs: Vec<Value> = c.view("receipts_for").args_json(json!({"guard_code_hash": H1})).await?.json()?;
    assert!(rs.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_contract_asks_before_paying() -> anyhow::Result<()> {
    let (worker, c, owner) = setup().await?;
    let wallet = worker.dev_deploy(&std::fs::read(CALLER_WASM)?).await?;
    let user = worker.dev_create_account().await?;
    let mut race = result(H1, "race", "held", "0", None, C1);
    race["setup"] = json!("mode=fixed");
    assert!(publish_result(&owner, &c, race).await?.is_success());
    assert!(publish_result(&owner, &c, result(H2, "injection", "broke", "0", Some("450"), C1)).await?.is_success());

    let ask = |hash: &str, suite: Option<&str>, commit: Option<&str>, setup: Option<&str>| {
        user.call(wallet.id(), "ask").args_json(json!({"arena": c.id(), "guard_code_hash": hash, "suite": suite,
            "arena_commit": commit, "expected_setup": setup})).max_gas().transact()
    };
    let d = |r: near_workspaces::result::ExecutionFinalResult| -> anyhow::Result<Value> {
        assert!(r.is_success(), "{:?}", r.failures());
        Ok(r.json::<Value>()?)
    };

    let yes = d(ask(H1, Some("race"), Some(C1), Some("mode=fixed")).await?)?;
    assert_eq!(yes["may_pay"], true, "{yes}");
    assert_eq!(yes["status"], "held");
    assert_eq!(yes["arena_commit"], C1);

    let unknown = d(ask(UNKNOWN, None, None, None).await?)?;
    assert_eq!(unknown["may_pay"], false);
    assert_eq!(unknown["status"], "not_tested");

    let broke = d(ask(H2, None, None, None).await?)?;
    assert_eq!(broke["may_pay"], false);
    assert_eq!(broke["status"], "broke");

    let wrong_setup = d(ask(H1, Some("race"), None, Some("mode=vulnerable_fixture")).await?)?;
    assert_eq!(wrong_setup["may_pay"], false);
    assert!(wrong_setup["why"].as_str().unwrap().contains("different guard setup"));

    let wrong_commit = d(ask(H1, Some("race"), Some(C2), Some("mode=fixed")).await?)?;
    assert_eq!(wrong_commit["may_pay"], false);
    assert_eq!(wrong_commit["status"], "not_tested");

    // Arena account that does not exist: the call fails, the wallet says no
    let gone = user.call(wallet.id(), "ask").args_json(json!({"arena": "no-such-arena.test.near", "guard_code_hash": H1,
        "suite": "race", "arena_commit": null, "expected_setup": "mode=fixed"})).max_gas().transact().await?;
    let v = d(gone)?;
    assert_eq!(v["may_pay"], false);
    assert_eq!(v["status"], "error");
    Ok(())
}

/// The upgrade keeps every stored receipt and every old method's answer byte for byte.
/// Cargo lists it as "ignored" unless you run it on purpose:
///   ARENA_OLD_RECEIPTS_WASM=<path> cargo test --release --test onchain -- --include-ignored
#[tokio::test]
#[ignore = "needs ARENA_OLD_RECEIPTS_WASM (the aba31658 receipts-only wasm)"]
async fn upgrade_keeps_receipts_and_old_answers() -> anyhow::Result<()> {
    let old = std::env::var("ARENA_OLD_RECEIPTS_WASM").map_err(|_| {
        anyhow::anyhow!("set ARENA_OLD_RECEIPTS_WASM to the aba31658 receipts-only wasm; this test never passes without it")
    })?;
    let old = std::fs::read(old)?;
    assert_eq!(sha256_hex(&old), "aba31658ad84fbd5acdc8f694446b63ead1bb482abb726e65b9d9b3c11e13480", "wrong old wasm");
    let worker = near_workspaces::sandbox().await?;
    let c = worker.dev_deploy(&old).await?;
    assert!(c.call("new").args_json(json!({"owner": c.id()})).transact().await?.is_success());
    for (suite, beyond, intent) in [("race-double-pay:mode=fixed", "0", None), ("injection-scripted", "0", Some("450"))] {
        let r = json!({"guard_code_hash": H1, "guard_label": "x", "suite": suite, "beyond_policy": beyond,
            "against_intent": intent, "tests_run": 5, "tests_held": 5, "harness_commit": C1,
            "evidence_sha256": EV, "evidence_path": "evidence/x.md"});
        assert!(c.call("publish").args_json(json!({"receipt": r})).deposit(NearToken::from_millinear(50)).transact().await?.is_success());
    }
    let snapshot = |c: Contract| async move {
        let mut out = Vec::new();
        out.push(c.view("receipts_for").args_json(json!({"guard_code_hash": H1})).await?.result);
        out.push(c.view("receipts_for").args_json(json!({"guard_code_hash": UNKNOWN})).await?.result);
        out.push(c.view("latest").args_json(json!({"guard_code_hash": H1, "suite": "injection-scripted"})).await?.result);
        out.push(c.view("latest").args_json(json!({"guard_code_hash": H1, "suite": "nope"})).await?.result);
        for (s, b, i) in [("race-double-pay:mode=fixed", "0", None), ("injection-scripted", "0", Some("0")), ("injection-scripted", "0", Some("450"))] {
            out.push(c.view("passes").args_json(json!({"guard_code_hash": H1, "suite": s, "max_beyond_policy": b,
                "max_against_intent": i, "max_age_ns": "86400000000000000"})).await?.result);
        }
        anyhow::Ok(out)
    };
    let before = snapshot(c.clone()).await?;
    let up = c.as_account().deploy(&std::fs::read(WASM)?).await?;
    assert!(up.is_success());
    let after = snapshot(c.clone()).await?;
    assert_eq!(before, after, "old views changed after the upgrade");
    // new methods work on the upgraded contract, and publish still works
    assert_eq!(answer(&c, H1, None, None).await?["status"], "not_tested");
    assert!(c.view("opt_ins").args_json(json!({})).await?.json::<Vec<Value>>()?.is_empty());
    assert!(publish_result(c.as_account(), &c, result(H1, "race", "held", "0", None, C1)).await?.is_success());
    let r = json!({"guard_code_hash": H1, "guard_label": "x", "suite": "late", "beyond_policy": "0",
        "against_intent": null, "tests_run": 1, "tests_held": 1, "harness_commit": C1, "evidence_sha256": EV, "evidence_path": "e"});
    assert!(c.call("publish").args_json(json!({"receipt": r})).deposit(NearToken::from_millinear(50)).transact().await?.is_success());
    assert_eq!(c.view("receipts_for").args_json(json!({"guard_code_hash": H1})).await?.json::<Vec<Value>>()?.len(), 3);
    println!("upgrade: {} old view answers identical before and after", before.len());
    Ok(())
}

fn sha256_hex(b: &[u8]) -> String {
    use std::process::{Command, Stdio};
    use std::io::Write;
    let mut p = Command::new("shasum").args(["-a", "256"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    p.stdin.take().unwrap().write_all(b).unwrap();
    String::from_utf8(p.wait_with_output().unwrap().stdout).unwrap().split_whitespace().next().unwrap().to_string()
}
