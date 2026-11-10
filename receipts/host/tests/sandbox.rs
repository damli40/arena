//! Sandbox tests for arena-receipts. Build the wasm first:
//!   (cd receipts && cargo build --release --target wasm32-unknown-unknown)
//! then: (cd receipts/host && cargo test --release)
use near_workspaces::types::NearToken;
use serde_json::{json, Value};

const WASM: &str = "../target/wasm32-unknown-unknown/release/arena_receipts.wasm";
const H1: &str = "fcce82bf9bad46ae9c7d85952470faf664aa5905bea2df7111ab97601b773372";
const UNKNOWN: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const DAY: &str = "86400000000000";

fn receipt(suite: &str, beyond: &str, intent: Option<&str>) -> Value {
    json!({"guard_code_hash": H1, "guard_label": "test", "suite": suite, "beyond_policy": beyond,
        "against_intent": intent, "tests_run": 5, "tests_held": 5, "harness_commit": "abc",
        "evidence_sha256": UNKNOWN, "evidence_path": "evidence/x.md"})
}

#[tokio::test]
async fn receipts_end_to_end() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let c = worker.dev_deploy(&std::fs::read(WASM)?).await?;
    let owner = worker.dev_create_account().await?;
    let stranger = worker.dev_create_account().await?;
    assert!(c.call("new").args_json(json!({"owner": owner.id()})).transact().await?.is_success());

    let publish = |who: &near_workspaces::Account, r: Value, dep: NearToken| {
        who.call(c.id(), "publish").args_json(json!({"receipt": r})).deposit(dep).transact()
    };
    let dep = NearToken::from_millinear(50);

    // 1. owner publishes; a non-owner is refused; no deposit is refused.
    let ok = publish(&owner, receipt("race", "100", None), dep).await?;
    assert!(ok.is_success(), "{:?}", ok.failures());
    assert!(ok.logs().iter().any(|l| l.starts_with("EVENT_JSON:") && l.contains("\"event\":\"publish\"")));
    let bad = publish(&stranger, receipt("race", "0", None), dep).await?;
    assert!(format!("{:?}", bad.into_result().unwrap_err()).contains("only the owner can publish"));
    let broke = publish(&owner, receipt("race", "0", None), NearToken::from_yoctonear(0)).await?;
    assert!(format!("{:?}", broke.into_result().unwrap_err()).contains("for storage"));
    // storage is paid by the publisher and the excess is refunded: the contract keeps only the
    // storage cost (well under the 50 mNEAR attached)
    let before = c.as_account().view_account().await?.balance;
    assert!(publish(&owner, receipt("other", "0", None), dep).await?.is_success());
    let gained = c.as_account().view_account().await?.balance.saturating_sub(before);
    assert!(gained < NearToken::from_millinear(10), "contract kept {gained}");

    let passes = |hash: &str, suite: &str, b: &str, i: Option<&str>, age: &str| {
        c.view("passes").args_json(json!({"guard_code_hash": hash, "suite": suite,
            "max_beyond_policy": b, "max_against_intent": i, "max_age_ns": age}))
    };
    let p = |r: near_workspaces::result::ViewResultDetails| r.json::<bool>().unwrap();

    // 2. passes: over the beyond-policy limit -> false; within it -> true.
    assert!(!p(passes(H1, "race", "0", None, DAY).await?));
    assert!(p(passes(H1, "race", "100", None, DAY).await?));
    // a limit on intent fails a receipt that never measured intent
    assert!(!p(passes(H1, "race", "100", Some("1000"), DAY).await?));

    // intent limits on a receipt that measured intent
    assert!(publish(&owner, receipt("inj", "0", Some("450")), dep).await?.is_success());
    assert!(!p(passes(H1, "inj", "0", Some("0"), DAY).await?));
    assert!(p(passes(H1, "inj", "0", Some("450"), DAY).await?));
    assert!(p(passes(H1, "inj", "0", None, DAY).await?));

    // latest wins: a newer receipt for the same hash and suite replaces the verdict
    assert!(publish(&owner, receipt("inj", "0", Some("0")), dep).await?.is_success());
    assert!(p(passes(H1, "inj", "0", Some("0"), DAY).await?));
    let all: Vec<Value> = c.view("receipts_for").args_json(json!({"guard_code_hash": H1})).await?.json()?;
    assert_eq!(all.len(), 4);
    let latest: Value = c.view("latest").args_json(json!({"guard_code_hash": H1, "suite": "inj"})).await?.json()?;
    assert_eq!(latest["against_intent"], "0");

    // 3. max age: after more blocks, a 0-ns window fails and a 1-day window still passes.
    worker.fast_forward(5).await?;
    assert!(!p(passes(H1, "race", "100", None, "0").await?));
    assert!(p(passes(H1, "race", "100", None, DAY).await?));

    // 4. unknown hash, or unknown suite -> false; latest is null
    assert!(!p(passes(UNKNOWN, "race", "1000000", None, DAY).await?));
    assert!(!p(passes(H1, "nope", "1000000", None, DAY).await?));
    let none: Value = c.view("latest").args_json(json!({"guard_code_hash": UNKNOWN, "suite": "race"})).await?.json()?;
    assert!(none.is_null());
    Ok(())
}

#[tokio::test]
async fn rejects_malformed_receipts() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let c = worker.dev_deploy(&std::fs::read(WASM)?).await?;
    let owner = worker.dev_create_account().await?;
    assert!(c.call("new").args_json(json!({"owner": owner.id()})).transact().await?.is_success());
    let mut r = receipt("race", "0", None);
    r["guard_code_hash"] = json!("FCCE82BF");
    let out = owner.call(c.id(), "publish").args_json(json!({"receipt": r})).deposit(NearToken::from_millinear(50)).transact().await?;
    assert!(format!("{:?}", out.into_result().unwrap_err()).contains("64 lowercase hex"));
    let mut r = receipt("race", "0", None);
    r["tests_held"] = json!(6);
    let out = owner.call(c.id(), "publish").args_json(json!({"receipt": r})).deposit(NearToken::from_millinear(50)).transact().await?;
    assert!(format!("{:?}", out.into_result().unwrap_err()).contains("tests_held > tests_run"));
    Ok(())
}
