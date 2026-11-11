//! Owner-method effect check for `arena check` (`harness effects`, `--guard-config` targets only).
//!
//! A mapping can point an owner role at a method that does nothing (a view, a no-op). Then every
//! attack on that rule looks "held" because the rule was never really set up. So, on its own
//! fresh sandbox, after the one setup function, this looks at each owner method's OWN visible
//! effect through the guard's views:
//!
//! - add_payee / remove_payee: setup added all five receivers and then removed lin. `is_payee`
//!   must say sam yes, lin no, and an account never added (the outsider) no.
//! - cancel_invoice: setup approved inv-cancel and inv-mid with the same receiver, amount and
//!   expiry, then cancelled inv-cancel. `get_invoice` must show them differently.
//! - set_daily_cap: `get_config` must show Arena's cap (500); the owner sets 400; it must show 400.
//! - set_agent: `get_config` must show the agent; the owner sets the outsider; it must show it.
//!
//! It never calls `pay` and never asks whether pay honours these rules: that is what the attacks
//! test. Each role gets one of: "confirmed", "no-effect" (the call worked, the view works, nothing
//! changed), "wrong-start", "not-confirmed" (no usable view, or the owner's call failed),
//! "not-claimed" (the guard does not claim the rule). tools/check/check.py decides what each means.

use crate::adapter::GuardConfig;
use crate::setup::Arena;
use near_workspaces::types::NearToken;
use serde_json::{json, Value};

fn short(e: impl std::fmt::Debug) -> String {
    let s = format!("{e:?}");
    s.chars().take(400).collect()
}

async fn view(a: &Arena, c: &GuardConfig, role: &str, args: Value) -> Result<Value, String> {
    let m = c.method(role);
    match a.vault.view(&m).args_json(c.args(role, args)).await {
        Ok(r) => r.json::<Value>().map_err(short),
        Err(e) => Err(short(e)),
    }
}

/// One owner call. `deposits` are tried in order; the next is tried only when the guard says it
/// refuses (or requires) that deposit.
async fn owner_call(a: &Arena, c: &GuardConfig, role: &str, args: Value, deposits: &[u128]) -> Result<(), String> {
    let m = c.method(role);
    let mut last = String::new();
    for d in deposits {
        let r = a
            .owner
            .call(a.vault.id(), &m)
            .args_json(c.args(role, args.clone()))
            .deposit(NearToken::from_yoctonear(*d))
            .max_gas()
            .transact()
            .await;
        match r {
            Ok(r) if r.is_success() => return Ok(()),
            Ok(r) => last = short(r.failures()),
            Err(e) => last = short(e),
        }
        if !(last.contains("deposit")) {
            break;
        }
    }
    Err(last)
}

fn res(result: &str, detail: String) -> Value {
    json!({"result": result, "detail": detail})
}

fn as_u128(v: &Value) -> Option<u128> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(|x| x as u128),
        _ => None,
    }
}

pub async fn check(a: &Arena) -> anyhow::Result<Value> {
    let c = a.target.adapter().ok_or_else(|| anyhow::anyhow!("effects needs --guard-config"))?;
    let f = &c.features;
    let mut out = serde_json::Map::new();
    let isp = |x: &Value| x.as_bool();

    // Payee list.
    if f.payees {
        let sam = a.receiver_id("sam")?.to_string();
        let lin = a.receiver_id("lin")?.to_string();
        let outsider = a.outsider.id().to_string();
        let ip = c.method("is_payee");
        let v_sam = view(a, c, "is_payee", json!({"account": sam})).await;
        let v_lin = view(a, c, "is_payee", json!({"account": lin})).await;
        let v_out = view(a, c, "is_payee", json!({"account": outsider})).await;
        match (v_sam.as_ref().map(isp), v_out.as_ref().map(isp)) {
            (Ok(Some(true)), Ok(Some(false))) => {
                out.insert("add_payee".into(), res("confirmed", format!("`{ip}` says sam is a payee after the owner added sam")));
                let r = match v_lin.as_ref().map(isp) {
                    Ok(Some(false)) => res("confirmed", format!("`{ip}` says lin is not a payee after the owner removed lin")),
                    Ok(Some(true)) => res("no-effect", format!("the owner removed lin, but `{ip}` still says lin is a payee")),
                    other => res("not-confirmed", format!("`{ip}` gave no yes/no answer for lin: {other:?}")),
                };
                out.insert("remove_payee".into(), r);
            }
            (Ok(Some(false)), _) => {
                out.insert("add_payee".into(), res("no-effect", format!("the owner added sam, but `{ip}` says sam is not a payee")));
                out.insert("remove_payee".into(), res("not-confirmed", "cannot be seen while adding a payee shows no effect".into()));
            }
            (Ok(Some(true)), Ok(Some(true))) => {
                let d = format!("`{ip}` says yes even for an account never added, so it cannot show what the owner's methods did");
                out.insert("add_payee".into(), res("not-confirmed", d.clone()));
                out.insert("remove_payee".into(), res("not-confirmed", d));
            }
            (s, o) => {
                let d = format!("no usable `{ip}` view (answers: sam {s:?}, outsider {o:?})");
                out.insert("add_payee".into(), res("not-confirmed", d.clone()));
                out.insert("remove_payee".into(), res("not-confirmed", d));
            }
        }
    } else {
        out.insert("add_payee".into(), res("not-claimed", "the guard does not claim a payee list".into()));
        out.insert("remove_payee".into(), res("not-claimed", "the guard does not claim a payee list".into()));
    }

    // Cancel.
    if f.cancel {
        let gi = c.method("get_invoice");
        let sf = c.shapes.get("status_field").cloned().unwrap_or_else(|| "status".into());
        let idf = c.shapes.get("invoice_id_field").cloned().unwrap_or_else(|| "id".into());
        let cancelled = view(a, c, "get_invoice", json!({"id": "inv-cancel"})).await;
        let twin = view(a, c, "get_invoice", json!({"id": "inv-mid"})).await;
        let r = match (cancelled, twin) {
            (Err(_), Ok(t)) if !t.is_null() => res("confirmed", format!("after the owner cancelled inv-cancel, `{gi}` no longer returns it")),
            (Ok(x), Ok(t)) if x.is_null() && !t.is_null() => {
                res("confirmed", format!("after the owner cancelled inv-cancel, `{gi}` no longer returns it"))
            }
            (Ok(x), Ok(t)) if !t.is_null() => {
                if x[&sf] != t[&sf] {
                    res("confirmed", format!("`{gi}` shows inv-cancel as {} and its uncancelled twin inv-mid as {}", x[&sf], t[&sf]))
                } else {
                    let strip = |mut v: Value| {
                        if let Some(m) = v.as_object_mut() {
                            m.remove(&idf);
                            m.remove("id");
                        }
                        v
                    };
                    if strip(x.clone()) == strip(t.clone()) {
                        res("no-effect", format!("the owner cancelled inv-cancel, but `{gi}` shows it exactly like the uncancelled inv-mid ({})", x[&sf]))
                    } else {
                        res("not-confirmed", format!("`{gi}` shows the same {sf:?} ({}) for inv-cancel and inv-mid; other fields differ", x[&sf]))
                    }
                }
            }
            (x, t) => res("not-confirmed", format!("no usable `{gi}` view (inv-cancel {x:?}, inv-mid {t:?})")),
        };
        out.insert("cancel_invoice".into(), r);
    } else {
        out.insert("cancel_invoice".into(), res("not-claimed", "the guard does not claim cancel".into()));
    }

    let gc = c.method("get_config");
    // Native guards hold the cap in yoctoNEAR (setup passes DAILY_CAP * NATIVE_UNIT at init).
    let unit: u128 = if a.target.is_native() { crate::setup::NATIVE_UNIT } else { 1 };
    let (start_cap, new_cap) = (crate::setup::DAILY_CAP * unit, 400 * unit);
    let capf = c.shapes.get("daily_cap_field").cloned().unwrap_or_else(|| "daily_cap".into());

    // Daily cap.
    if f.daily_cap {
        let before = view(a, c, "get_config", json!({})).await.ok().and_then(|v| as_u128(&v[&capf]));
        if let Some(b) = before.filter(|b| *b != start_cap) {
            out.insert(
                "set_daily_cap".into(),
                res("wrong-start", format!("`{gc}` says the cap is {b} right after init, but Arena scores against {start_cap}")),
            );
        } else {
            let call = owner_call(a, c, "set_daily_cap", json!({"daily_cap": new_cap.to_string()}), &[c.deposit("set_daily_cap")]).await;
            let after = view(a, c, "get_config", json!({})).await.ok().and_then(|v| as_u128(&v[&capf]));
            let r = match (call, before, after) {
                (Err(e), _, _) => res("not-confirmed", format!("the owner's call to it failed: {e}")),
                (Ok(()), Some(_), Some(x)) if x == new_cap => {
                    res("confirmed", format!("`{gc}` showed {start_cap}, then {new_cap} after the owner set {new_cap}"))
                }
                (Ok(()), Some(b), Some(x)) if x == b => res("no-effect", format!("the owner set the cap to {new_cap}, but `{gc}` still shows {b}")),
                (Ok(()), _, x) => res("not-confirmed", format!("no usable `{gc}` view with a {capf:?} field (after: {x:?})")),
            };
            out.insert("set_daily_cap".into(), r);
        }
    } else {
        out.insert("set_daily_cap".into(), res("not-claimed", "the guard does not claim a daily cap".into()));
    }

    // Agent. No rule switches it off: every guard has an agent.
    let agent = a.agent.id().to_string();
    let newbie = a.outsider.id().to_string();
    let read_agent = |v: Result<Value, String>| v.ok().and_then(|v| v["agent"].as_str().map(|s| s.to_string()));
    let before = read_agent(view(a, c, "get_config", json!({})).await);
    let call = owner_call(a, c, "set_agent", json!({"account": newbie}), &[1, 0]).await;
    let after = read_agent(view(a, c, "get_config", json!({})).await);
    let r = match (call, before, after) {
        (Err(e), _, _) => res("not-confirmed", format!("the owner's call to it failed: {e}")),
        (Ok(()), Some(b), Some(x)) if b == agent && x == newbie => {
            res("confirmed", format!("`{gc}` showed the agent, then the new account after the owner changed it"))
        }
        (Ok(()), Some(b), Some(x)) if b == agent && x == b => {
            res("no-effect", format!("the owner changed the agent, but `{gc}` still shows the old agent"))
        }
        (Ok(()), b, x) => res("not-confirmed", format!("no usable `{gc}` view with an \"agent\" field (before {b:?}, after {x:?})")),
    };
    out.insert("set_agent".into(), r);
    Ok(Value::Object(out))
}
