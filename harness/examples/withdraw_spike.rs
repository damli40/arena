//! Spike (2026-11-11, branch intents-withdraw): does `ft_withdraw` on the pinned NEAR Intents release
//! (defuse v0.4.2) reach Arena's bridge stand-in (contracts/bridge-standin) with the msg intact, and
//! does the stand-in refuse what it cannot read?
//! Run: cargo run --release --example withdraw_spike (after building contracts/ for wasm32).
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
    let bridge_wasm = std::fs::read(resolve("../contracts/target/wasm32-unknown-unknown/release/bridge_standin.wasm"))?;
    let owner = worker.dev_create_account().await?;
    let g = worker.dev_create_account().await?;
    let token = worker.dev_deploy(&token_wasm).await?;
    let intents = worker.dev_deploy(&defuse).await?;
    let bridge = worker.dev_deploy(&bridge_wasm).await?;
    let r = intents
        .call("new")
        .args_json(json!({"config": {"wnear_id": token.id(), "fees": {"fee": 0, "fee_collector": owner.id()}, "roles": {}}}))
        .max_gas()
        .transact()
        .await?;
    println!("STEP intents new(): success={}", r.is_success());
    let r = bridge.call("new").args_json(json!({"token": token.id()})).transact().await?;
    println!("STEP bridge new(token): success={}", r.is_success());
    owner.call(token.id(), "new").args_json(json!({"owner_id": owner.id(), "total_supply": "1000000"})).transact().await?.into_result()?;
    for a in [intents.id(), bridge.id()] {
        owner.call(token.id(), "storage_deposit").args_json(json!({"account_id": a})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    }
    let r = owner
        .call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents.id(), "amount": "1000", "msg": g.id()}))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    println!("STEP owner deposits 1000 into Intents for g: success={}", r.is_success());
    let tid = format!("nep141:{}", token.id());
    let mt = |who: near_workspaces::AccountId| {
        let intents = intents.clone();
        let tid = tid.clone();
        async move {
            let v: String = intents.view("mt_balance_of").args_json(json!({"account_id": who, "token_id": tid})).await?.json()?;
            Ok::<_, anyhow::Error>(v)
        }
    };
    let ft = |who: near_workspaces::AccountId| {
        let token = token.clone();
        async move {
            let v: String = token.view("ft_balance_of").args_json(json!({"account_id": who})).await?.json()?;
            Ok::<_, anyhow::Error>(v)
        }
    };
    println!("VIEW mt_balance_of(g) = {}", mt(g.id().clone()).await?);

    let cases = [
        ("good msg", Some(json!({"recipient": "eth:0x5a11000000000000000000000000000000000001"}).to_string()), "100"),
        ("unreadable msg", Some("not json".to_string()), "50"),
        ("no msg (plain ft_transfer)", None, "7"),
    ];
    for (what, msg, amount) in cases {
        let mut args = json!({"token": token.id(), "receiver_id": bridge.id(), "amount": amount, "memo": "memo text"});
        if let Some(m) = &msg {
            args["msg"] = json!(m);
        }
        let r = g.call(intents.id(), "ft_withdraw").args_json(args).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?;
        let ret: Option<String> = r.clone().json().ok();
        println!("STEP g ft_withdraw {amount} to bridge, {what}: success={} returned={ret:?} receipt_failures={}", r.is_success(), r.receipt_failures().len());
        for l in r.logs() {
            println!("  LOG {l}");
        }
        println!(
            "  VIEW after: g inside Intents={} bridge tokens={} intents tokens={} record_count={}",
            mt(g.id().clone()).await?,
            ft(bridge.id().clone()).await?,
            ft(intents.id().clone()).await?,
            bridge.view("record_count").args_json(json!({})).await?.json::<u64>()?
        );
    }
    let recs: serde_json::Value = bridge.view("records").args_json(json!({"from_index": 0, "limit": 10})).await?.json()?;
    println!("VIEW records = {recs}");
    // Another sender's tokens: the owner calls ft_transfer_call on the bridge directly.
    let r = owner
        .call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": bridge.id(), "amount": "3", "msg": json!({"recipient": "eth:0x01"}).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact()
        .await?;
    println!("STEP owner ft_transfer_call 3 straight to the bridge: success={} returned={:?}", r.is_success(), r.clone().json::<String>().ok());
    println!("  VIEW record_count={}", bridge.view("record_count").args_json(json!({})).await?.json::<u64>()?);
    if bridge.view("record_count").args_json(json!({})).await?.json::<u64>()? != 2 {
        bail!("expected 2 records (the good withdrawal and the owner's direct transfer)");
    }
    println!("DONE in {:.1}s", t.elapsed().as_secs_f64());
    Ok(())
}
