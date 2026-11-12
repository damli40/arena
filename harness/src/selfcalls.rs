//! Which methods the guard called on ITSELF during one transaction (direct gate runs only).
//!
//! A guard that pays with a promise usually calls itself back when the transfer ends (the
//! "callback"). The gate uses this list to confirm that the method the config names as the
//! callback is the one the guard really calls back on itself after a payment, with the id the
//! payment returned. Read from the node's own record of the transaction (EXPERIMENTAL_tx_status),
//! never from the guard's views or logs.
//!
//! Shape (the `self_calls` field of a gate step): a list of {"method": "<name>", "args": <JSON or
//! null>} for every function-call receipt whose sender and receiver are both the guard account,
//! or null if Arena could not read the transaction (the gate then treats the callback as not
//! confirmed).
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::Worker;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn b64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let end = i + body[i..].windows(2).position(|w| w == b"\r\n")?;
        let n = usize::from_str_radix(std::str::from_utf8(&body[i..end]).ok()?.split(';').next()?.trim(), 16).ok()?;
        if n == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(end + 2..end + 2 + n)?);
        i = end + 2 + n + 2;
    }
}

async fn rpc(addr: &str, body: &Value) -> Option<Value> {
    let host = addr.trim_start_matches("http://").trim_end_matches('/').to_string();
    let payload = body.to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let mut s = tokio::net::TcpStream::connect(&host).await.ok()?;
    s.write_all(req.as_bytes()).await.ok()?;
    let mut raw = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(30), s.read_to_end(&mut raw)).await.ok()?.ok()?;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let mut b = raw[split + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        b = dechunk(&b)?;
    }
    serde_json::from_slice(&b).ok()
}

pub async fn trace(w: &Worker<Sandbox>, r: &ExecutionFinalResult, guard: &str) -> Value {
    let tx = r.outcome();
    let q = json!({"jsonrpc": "2.0", "id": "arena", "method": "EXPERIMENTAL_tx_status",
        "params": {"tx_hash": tx.transaction_hash.to_string(), "sender_account_id": tx.executor_id.to_string(), "wait_until": "EXECUTED_OPTIMISTIC"}});
    let Some(resp) = rpc(&w.rpc_addr(), &q).await else { return Value::Null };
    let Some(receipts) = resp.pointer("/result/receipts").and_then(|x| x.as_array()) else { return Value::Null };
    let mut out = Vec::new();
    for rc in receipts {
        if rc.get("predecessor_id").and_then(|x| x.as_str()) != Some(guard) || rc.get("receiver_id").and_then(|x| x.as_str()) != Some(guard) {
            continue;
        }
        for a in rc.pointer("/receipt/Action/actions").and_then(|x| x.as_array()).into_iter().flatten() {
            if let Some(fc) = a.get("FunctionCall") {
                let args = fc.get("args").and_then(|x| x.as_str()).and_then(b64).and_then(|v| serde_json::from_slice::<Value>(&v).ok()).unwrap_or(Value::Null);
                out.push(json!({"method": fc.get("method_name").cloned().unwrap_or(Value::Null), "args": args}));
            }
        }
    }
    Value::Array(out)
}
