//! Spike (2026-11-11): can the pinned NEAR Intents release wasm (defuse v0.4.2) deploy, init and
//! credit a deposit on the near-workspaces 0.24 sandbox Arena already uses?
//! Run: cargo run --release --example intents_spike
use anyhow::{bail, Result};
use near_workspaces::types::NearToken;
use serde_json::json;

fn resolve(rel: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[tokio::main]
async fn main() -> Result<()> {
    let t = std::time::Instant::now();
    let worker = near_workspaces::sandbox().await?;
    let defuse = std::fs::read(resolve("../targets/intents-defuse-v0.4.2/defuse.wasm"))?;
    let token_wasm = std::fs::read(resolve("../contracts/target/wasm32-unknown-unknown/release/test_token.wasm"))?;
    let owner = worker.dev_create_account().await?;
    let sam = worker.dev_create_account().await?;
    let token = worker.dev_deploy(&token_wasm).await?;
    println!("STEP token deployed: {}", token.id());
    let intents = worker.dev_deploy(&defuse).await?;
    println!("STEP defuse.wasm deployed: {} ({} bytes)", intents.id(), defuse.len());
    let r = intents
        .call("new")
        .args_json(json!({"config": {"wnear_id": token.id(), "fees": {"fee": 0, "fee_collector": owner.id()}, "roles": {}}}))
        .max_gas()
        .transact()
        .await?;
    println!("STEP new(): success={} failures={:?}", r.is_success(), r.failures());
    if !r.is_success() { bail!("init failed"); }
    let r = owner.call(token.id(), "new").args_json(json!({"owner_id": owner.id(), "total_supply": "1000000"})).transact().await?;
    println!("STEP token new: {}", r.is_success());
    let r = owner.call(token.id(), "storage_deposit").args_json(json!({"account_id": intents.id()})).deposit(NearToken::from_millinear(10)).transact().await?;
    println!("STEP storage_deposit(intents) on token: {}", r.is_success());
    let r = owner
        .call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents.id(), "amount": "100", "msg": sam.id()}))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    println!("STEP ft_transfer_call 100 msg=sam: success={} failures={:?}", r.is_success(), r.failures());
    for l in r.logs() { println!("  LOG {l}"); }
    let tid = format!("nep141:{}", token.id());
    for (n, a) in [("sam", sam.id()), ("owner", owner.id())] {
        let v: serde_json::Value = intents.view("mt_balance_of").args_json(json!({"account_id": a, "token_id": tid})).await?.json()?;
        println!("VIEW mt_balance_of({n}, {tid}) = {v}");
    }
    let v: serde_json::Value = intents.view("mt_supply").args_json(json!({"token_id": tid})).await?.json()?;
    println!("VIEW mt_supply = {v}");
    let v: serde_json::Value = intents.view("mt_tokens").args_json(json!({"from_index": "0", "limit": 50})).await?.json()?;
    println!("VIEW mt_tokens = {v}");
    let v: serde_json::Value = intents.view("public_keys_of").args_json(json!({"account_id": sam.id()})).await?.json()?;
    println!("VIEW public_keys_of(sam) = {v}");
    let v: serde_json::Value = token.view("ft_balance_of").args_json(json!({"account_id": intents.id()})).await?.json()?;
    println!("VIEW token ft_balance_of(intents) = {v}");
    let v: serde_json::Value = token.view("ft_balance_of").args_json(json!({"account_id": owner.id()})).await?.json()?;
    println!("VIEW token ft_balance_of(owner) = {v}");
    // JSON msg form
    let r = owner
        .call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents.id(), "amount": "7", "msg": json!({"receiver_id": sam.id()}).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    println!("STEP ft_transfer_call 7 msg={{receiver_id: sam}}: success={}", r.is_success());
    let v: serde_json::Value = intents.view("mt_balance_of").args_json(json!({"account_id": sam.id(), "token_id": tid})).await?.json()?;
    println!("VIEW mt_balance_of(sam) = {v}");
    // withdraw by sam
    let r = sam.call(token.id(), "storage_deposit").args_json(json!({"account_id": sam.id()})).deposit(NearToken::from_millinear(10)).transact().await?;
    println!("STEP storage_deposit(sam): {}", r.is_success());
    let r = sam.call(intents.id(), "ft_withdraw").args_json(json!({"token": token.id(), "receiver_id": sam.id(), "amount": "7"})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?;
    println!("STEP sam ft_withdraw 7: success={} failures={:?}", r.is_success(), r.failures());
    let v: serde_json::Value = token.view("ft_balance_of").args_json(json!({"account_id": sam.id()})).await?.json()?;
    println!("VIEW token ft_balance_of(sam) = {v}");
    let v: serde_json::Value = intents.view("mt_supply").args_json(json!({"token_id": tid})).await?.json()?;
    println!("VIEW mt_supply = {v}");
    println!("DONE in {:.1}s", t.elapsed().as_secs_f64());
    Ok(())
}
