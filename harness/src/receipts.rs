//! Receipt trace for one transaction (additive, every mode): which block each receipt of the
//! transaction ran in, on which account, and whether it succeeded. Used to prove the ORDER of
//! raced or retried calls (which call's transfer landed in which block, and how its callback
//! ended). Never read by any scorer: it is evidence only.
//!
//! Shape (the `receipts` field of a step in a result JSON):
//! {"tx_hash": "<base58>", "tx_block_height": 123,
//!  "receipts": [{"index": 0, "executor": "<account id>", "block_height": 124, "ok": true,
//!                "gas_burnt": "2428...", "logs": 1, "children": 2}, ...]}
//! `receipts` is in the order the RPC returns them (execution order within the transaction's
//! receipt tree); `children` = how many receipts that receipt created. A block height Arena could
//! not read is null.
use near_workspaces::network::Sandbox;
use near_workspaces::result::{ExecutionFinalResult, ExecutionOutcome};
use near_workspaces::Worker;
use serde_json::{json, Value};
use std::collections::HashMap;

async fn height(w: &Worker<Sandbox>, cache: &mut HashMap<String, Option<u64>>, o: &ExecutionOutcome) -> Option<u64> {
    let k = o.block_hash.to_string();
    if let Some(h) = cache.get(&k) {
        return *h;
    }
    let h = w.view_block().block_hash(o.block_hash).await.ok().map(|b| b.height());
    cache.insert(k, h);
    h
}

pub async fn trace(w: &Worker<Sandbox>, r: &ExecutionFinalResult) -> Value {
    let mut cache = HashMap::new();
    let tx = r.outcome();
    let txh = height(w, &mut cache, tx).await;
    let mut out = Vec::new();
    for (i, o) in r.receipt_outcomes().iter().enumerate() {
        out.push(json!({
            "index": i, "executor": o.executor_id.to_string(), "block_height": height(w, &mut cache, o).await,
            "ok": o.is_success(), "gas_burnt": o.gas_burnt.as_gas().to_string(), "logs": o.logs.len(), "children": o.receipt_ids.len(),
        }));
    }
    json!({"tx_hash": tx.transaction_hash.to_string(), "tx_block_height": txh, "receipts": out})
}
