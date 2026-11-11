//! receipts-cli: the small testnet client behind tools/receipts/publish.py.
//! Same tooling as the Nov 9 testnet race (near-workspaces 0.24, FastNEAR RPC). Testnet only.
//!
//!   receipts-cli deploy  <funder-id> <sub-name> <wasm> <millinear>   create <sub>.<funder> (random key), deploy, new(owner=itself)
//!   receipts-cli redeploy <contract-id> <wasm>                        replace the code, keep the stored receipts
//!   receipts-cli publish <contract-id> <receipts.json>                 call publish once per receipt (signed by the contract's own key)
//!   receipts-cli view    <contract-id> <method> <args-json>            run a view call, print the JSON result
//!   receipts-cli publish-results <contract-id> <results.json>          call publish_result once per result (contract's own key)
//!   receipts-cli opt-in  <signer-id> <contract-id> <args-json>         call opt_in, signed by <signer-id> (guard or its parent)
//!   receipts-cli transfer <from-id> <to-id> <millinear>                send testnet NEAR (e.g. top up the contract before an upgrade)
//!
//! Output: one JSON object per line on stdout. Keys are never printed.
use near_workspaces::network::Testnet;
use near_workspaces::types::{KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Worker};
use serde_json::{json, Value};

fn cred_path(id: &str) -> anyhow::Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(std::env::var("HOME")?).join(format!(".near-credentials/testnet/{id}.json")))
}

/// Saves the key OUTSIDE the repo, near-cli style, mode 600. Never printed.
fn save_cred(id: &str, sk: &SecretKey) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = cred_path(id)?;
    anyhow::ensure!(!path.exists(), "refusing to overwrite an existing key file for {id}");
    std::fs::create_dir_all(path.parent().unwrap())?;
    let body = json!({"account_id": id, "public_key": sk.public_key().to_string(), "private_key": sk.to_string()});
    std::fs::write(&path, body.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn load_account(worker: &Worker<Testnet>, id: &str) -> anyhow::Result<Account> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(cred_path(id)?)?)?;
    let sk: SecretKey = v["private_key"].as_str().ok_or_else(|| anyhow::anyhow!("no key for {id}"))?.parse()?;
    Ok(Account::from_secret_key(id.parse()?, sk, worker))
}

/// The Nov 9 funder: a near-workspaces dev account whose key is derived from its id.
fn dev_account(worker: &Worker<Testnet>, id: &AccountId) -> Account {
    Account::from_secret_key(id.clone(), SecretKey::from_seed(KeyType::ED25519, id.as_str()), worker)
}

fn link(hash: impl std::fmt::Display) -> String {
    format!("https://testnet.nearblocks.io/txns/{hash}")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let rpc = std::env::var("TESTNET_RPC").unwrap_or_else(|_| "https://rpc.testnet.fastnear.com".into());
    let worker = near_workspaces::testnet().rpc_addr(&rpc).await?;
    match a.get(1).map(String::as_str) {
        Some("deploy") if a.len() == 6 => {
            let funder = dev_account(&worker, &a[2].parse()?);
            let id = format!("{}.{}", a[3], a[2]);
            let sk = SecretKey::from_random(KeyType::ED25519);
            save_cred(&id, &sk)?;
            let made = funder.create_subaccount(&a[3]).initial_balance(NearToken::from_millinear(a[5].parse()?)).keys(sk).transact().await?;
            println!("{}", json!({"step": "create", "account": id, "ok": made.is_success(), "tx": link(made.details.outcome().transaction_hash)}));
            let acct = made.into_result()?;
            let wasm = std::fs::read(&a[4])?;
            let dep = acct.deploy(&wasm).await?;
            println!("{}", json!({"step": "deploy", "ok": dep.is_success(), "tx": link(dep.details.outcome().transaction_hash)}));
            let init = acct.call(acct.id(), "new").args_json(json!({"owner": acct.id()})).transact().await?;
            println!("{}", json!({"step": "new", "ok": init.is_success(), "tx": link(init.outcome().transaction_hash), "failures": format!("{:?}", init.failures())}));
        }
        Some("redeploy") if a.len() == 4 => {
            // Replace the code on an existing contract account; stored receipts are kept.
            let dep = load_account(&worker, &a[2])?.deploy(&std::fs::read(&a[3])?).await?;
            println!("{}", json!({"step": "redeploy", "ok": dep.is_success(), "tx": link(dep.details.outcome().transaction_hash)}));
        }
        Some("publish") if a.len() == 4 => {
            let acct = load_account(&worker, &a[2])?;
            let receipts: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(&a[3])?)?;
            for r in receipts {
                let out = acct.call(acct.id(), "publish").args_json(json!({"receipt": r}))
                    .deposit(NearToken::from_millinear(50)).transact().await?;
                let returned: Option<Value> = out.clone().json().ok();
                println!("{}", json!({"step": "publish", "ok": out.is_success(), "tx": link(out.outcome().transaction_hash),
                    "tx_hash": out.outcome().transaction_hash.to_string(), "label": r["guard_label"], "suite": r["suite"],
                    "returned": returned, "logs": out.logs(), "failures": format!("{:?}", out.failures())}));
            }
        }
        Some("publish-results") if a.len() == 4 => {
            let acct = load_account(&worker, &a[2])?;
            let results: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(&a[3])?)?;
            for r in results {
                let out = acct.call(acct.id(), "publish_result").args_json(json!({"result": r}))
                    .deposit(NearToken::from_millinear(50)).transact().await?;
                let returned: Option<Value> = out.clone().json().ok();
                println!("{}", json!({"step": "publish_result", "ok": out.is_success(), "tx": link(out.outcome().transaction_hash),
                    "tx_hash": out.outcome().transaction_hash.to_string(), "suite": r["suite"], "guard_code_hash": r["guard_code_hash"],
                    "returned": returned, "failures": format!("{:?}", out.failures())}));
            }
        }
        Some("opt-in") if a.len() == 5 => {
            let signer = load_account(&worker, &a[2])?;
            let contract: AccountId = a[3].parse()?;
            let args: Value = serde_json::from_str(&a[4])?;
            let out = signer.call(&contract, "opt_in").args_json(args.clone()).deposit(NearToken::from_millinear(20)).transact().await?;
            let returned: Option<Value> = out.clone().json().ok();
            println!("{}", json!({"step": "opt_in", "ok": out.is_success(), "signer": a[2], "tx": link(out.outcome().transaction_hash),
                "tx_hash": out.outcome().transaction_hash.to_string(), "args": args, "returned": returned,
                "logs": out.logs(), "failures": format!("{:?}", out.failures())}));
        }
        Some("transfer") if a.len() == 5 => {
            let from = load_account(&worker, &a[2])?;
            let to: AccountId = a[3].parse()?;
            let out = from.transfer_near(&to, NearToken::from_millinear(a[4].parse()?)).await?;
            println!("{}", json!({"step": "transfer", "ok": out.is_success(), "from": a[2], "to": a[3], "millinear": a[4],
                "tx": link(out.outcome().transaction_hash), "tx_hash": out.outcome().transaction_hash.to_string()}));
        }
        Some("view") if a.len() == 5 => {
            let id: AccountId = a[2].parse()?;
            let args: Value = serde_json::from_str(&a[4])?;
            let res = worker.view(&id, &a[3]).args_json(args.clone()).await?;
            println!("{}", json!({"step": "view", "method": a[3], "args": args, "result": res.json::<Value>()?}));
        }
        _ => anyhow::bail!("usage: see the header of receipts/host/src/main.rs"),
    }
    Ok(())
}
