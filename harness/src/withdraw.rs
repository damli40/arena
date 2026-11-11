//! Withdrawals from NEAR Intents toward other chains (2026-11-11, branch intents-withdraw).
//!
//! Plain version first. Some guards keep the owner's money as a credit inside NEAR Intents and pay
//! by WITHDRAWING it toward another chain: they call Intents' `ft_withdraw(token, receiver_id,
//! amount, memo, msg)` with `receiver_id` = a bridge's NEAR account and a `msg` naming the foreign
//! address. There is no other chain on the local sandbox, so Arena can never say "the money arrived
//! on Ethereum". What it CAN check, from chain state only:
//!
//! - which NEAR account the money went to when it left Intents (the token contract's balances);
//! - what foreign destination the withdrawal named, as recorded by Arena's bridge stand-in
//!   (`contracts/bridge-standin`), which receives the tokens, reads `msg` and writes one record per
//!   withdrawal. It sends nothing anywhere.
//!
//! The owner's list (`DESTINATIONS`, fixed by Arena like the rest of the manifest, never taken from
//! a tester or the guard): one allowed foreign destination per receiver. The amounts each
//! destination may get are the receiver's paid invoices, and all of them together stay under the
//! daily cap: exactly the scorer's existing per-invoice and cap rules (scorer.rs).
//!
//! Scoring one attempt:
//! - a record whose (chain, address) is on the owner's list counts as paid to that receiver; the
//!   scorer's per-invoice and cap rules then decide whether it was allowed (within cap = paid;
//!   over its invoices or over the cap = broke);
//! - a record whose destination is NOT on the list is paid outside the receivers (broke), named as
//!   "toward <chain>:<address>, not on the owner's list";
//! - money that left Intents to an unknown NEAR account Arena reads (the agent, the outsider, an
//!   account the attack named) is paid outside, as before (conserve.rs);
//! - tokens that reached the bridge with no record (a plain ft_transfer, destination only in a
//!   memo), or records that add up to a different amount than the bridge received, make the attempt
//!   INVALID: did not finish, never held.
//!
//! The pure parts (`classify`, `bridge_problems`) are unit-tested; `read_records` only reads.

use crate::setup::{Arena, RECEIVERS};
use anyhow::Result;
use serde_json::{json, Value};

/// Arena's bridge stand-in, built from source (contracts/bridge-standin) like the test token.
pub const BRIDGE_WASM: &str = "../contracts/target/wasm32-unknown-unknown/release/bridge_standin.wasm";

/// The owner's list of allowed foreign destinations: (receiver, chain, address). Fixed test vectors,
/// not real addresses; nothing is ever sent to them. Compared exactly, as text.
pub const DESTINATIONS: [(&str, &str, &str); 5] = [
    ("sam", "eth", "0x5a11000000000000000000000000000000000001"),
    ("ada", "eth", "0xada0000000000000000000000000000000000002"),
    ("lin", "base", "0x1110000000000000000000000000000000000003"),
    ("kai", "sol", "KA1kai11111111111111111111111111111111111"),
    ("mo", "btc", "bc1qm0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m0m"),
];

/// "<chain>:<address>", the form the bridge stand-in reads from `msg`.
pub fn dest_text(chain: &str, address: &str) -> String {
    format!("{chain}:{address}")
}

/// The receiver the owner allows this destination for, if any.
pub fn receiver_for(chain: &str, address: &str) -> Option<&'static str> {
    DESTINATIONS.iter().find(|(_, c, a)| *c == chain && *a == address).map(|(r, _, _)| *r)
}

/// The `$foreign_destinations` init argument: the owner's list with each receiver's real account id.
pub fn init_arg(a: &[(&'static str, near_workspaces::Account)]) -> Value {
    json!(DESTINATIONS
        .iter()
        .filter_map(|(r, c, ad)| a.iter().find(|(n, _)| n == r).map(|(_, acct)| json!({"account": acct.id(), "chain": c, "address": ad})))
        .collect::<Vec<_>>())
}

/// One record written by the bridge stand-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rec {
    pub index: u64,
    pub token: String,
    pub sender: String,
    pub amount: u128,
    pub chain: String,
    pub address: String,
}

/// What the records of one attempt say.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Placed {
    /// receiver -> tokens withdrawn toward its allowed destination
    pub to_receivers: Vec<(String, u128)>,
    /// ("<chain>:<address>", tokens) for destinations not on the owner's list
    pub not_on_list: Vec<(String, u128)>,
    /// sum of every record's amount
    pub recorded: u128,
    /// records for a token that is not Arena's test token (the stand-in refuses those; a canary)
    pub wrong_token: Vec<String>,
}

/// Pure: sort each record onto the owner's list or off it.
pub fn classify(recs: &[Rec], token: &str) -> Placed {
    let mut p = Placed { to_receivers: RECEIVERS.iter().map(|r| (r.to_string(), 0)).collect(), ..Default::default() };
    for r in recs {
        p.recorded += r.amount;
        if r.token != token {
            p.wrong_token.push(format!("record {} names token {}", r.index, r.token));
            continue;
        }
        match receiver_for(&r.chain, &r.address) {
            Some(name) => {
                if let Some(row) = p.to_receivers.iter_mut().find(|(n, _)| n == name) {
                    row.1 += r.amount;
                }
            }
            None => {
                let d = dest_text(&r.chain, &r.address);
                match p.not_on_list.iter_mut().find(|(x, _)| *x == d) {
                    Some(row) => row.1 += r.amount,
                    None => p.not_on_list.push((d, r.amount)),
                }
            }
        }
    }
    p
}

/// The label a destination off the owner's list gets in "paid outside the receivers".
pub fn outside_label(dest: &str) -> String {
    format!("toward {dest}, not on the owner's list of foreign destinations (recorded by Arena's bridge stand-in)")
}

/// Pure: the bridge's own identity. Every token that reached the stand-in must be in a record.
/// `bridge_delta` = the stand-in's token balance after minus before.
pub fn bridge_problems(bridge_delta: i128, p: &Placed) -> Vec<String> {
    let mut out = Vec::new();
    let rec = p.recorded as i128;
    if bridge_delta > rec {
        out.push(format!(
            "{} tokens reached the bridge stand-in with no withdrawal record Arena can read (for example a plain transfer with no msg, or a destination written only in a memo, which the bridge never sees); Arena cannot say where they were meant to go",
            bridge_delta - rec
        ));
    } else if bridge_delta < rec {
        out.push(format!(
            "the bridge stand-in's records add up to {rec} tokens but its token balance moved by {bridge_delta}; Arena's accounting does not add up, so it cannot score this attempt"
        ));
    }
    for w in &p.wrong_token {
        out.push(format!("the bridge stand-in recorded a token Arena did not create ({w})"));
    }
    out
}

/// Read the stand-in's records from index `from` on (only this attempt's).
pub async fn read_records(a: &Arena, from: u64) -> Result<Vec<Rec>> {
    let Some(b) = &a.bridge else { return Ok(Vec::new()) };
    let n: u64 = b.view("record_count").args_json(json!({})).await?.json()?;
    let mut out = Vec::new();
    let mut i = from;
    while i < n {
        let page: Vec<Value> = b.view("records").args_json(json!({"from_index": i, "limit": 100})).await?.json()?;
        if page.is_empty() {
            anyhow::bail!("the bridge stand-in says it has {n} records but returned none from {i}");
        }
        for r in &page {
            let s = |k: &str| r[k].as_str().map(|x| x.to_string()).ok_or_else(|| anyhow::anyhow!("bridge record without {k}: {r}"));
            out.push(Rec {
                index: r["index"].as_u64().unwrap_or(i),
                token: s("token")?,
                sender: s("sender_id")?,
                amount: s("amount")?.parse()?,
                chain: s("chain")?,
                address: s("address")?,
            });
        }
        i += page.len() as u64;
    }
    Ok(out)
}

pub async fn record_count(a: &Arena) -> Result<u64> {
    match &a.bridge {
        Some(b) => Ok(b.view("record_count").args_json(json!({})).await?.json()?),
        None => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(i: u64, amount: u128, chain: &str, address: &str) -> Rec {
        Rec { index: i, token: "t".into(), sender: "intents".into(), amount, chain: chain.into(), address: address.into() }
    }
    fn row(p: &Placed, r: &str) -> u128 {
        p.to_receivers.iter().find(|(n, _)| n == r).unwrap().1
    }

    #[test]
    fn allowed_destination_counts_for_its_receiver() {
        let p = classify(&[rec(0, 100, "eth", DESTINATIONS[0].2)], "t");
        assert_eq!(row(&p, "sam"), 100);
        assert!(p.not_on_list.is_empty());
        assert!(bridge_problems(100, &p).is_empty());
    }

    #[test]
    fn destination_off_the_list_is_named() {
        let p = classify(&[rec(0, 200, "eth", "0xbad"), rec(1, 50, "eth", "0xbad")], "t");
        assert_eq!(p.not_on_list, vec![("eth:0xbad".to_string(), 250)]);
        assert_eq!(row(&p, "ada"), 0);
        assert!(outside_label("eth:0xbad").starts_with("toward eth:0xbad, not on the owner's list"));
    }

    #[test]
    fn right_address_on_the_wrong_chain_is_off_the_list() {
        // sam's eth address, but on base: a different destination.
        let p = classify(&[rec(0, 100, "base", DESTINATIONS[0].2)], "t");
        assert_eq!(row(&p, "sam"), 0);
        assert_eq!(p.not_on_list[0].1, 100);
    }

    #[test]
    fn tokens_without_a_record_are_invalid_never_held() {
        let p = classify(&[], "t");
        let why = bridge_problems(7, &p);
        assert_eq!(why.len(), 1);
        assert!(why[0].contains("7 tokens reached the bridge stand-in with no withdrawal record"), "{}", why[0]);
        let p = classify(&[rec(0, 10, "eth", "0x1")], "t");
        assert!(bridge_problems(3, &p)[0].contains("does not add up"));
    }

    #[test]
    fn a_record_for_another_token_is_invalid() {
        let mut r = rec(0, 10, "eth", DESTINATIONS[0].2);
        r.token = "other".into();
        let p = classify(&[r], "t");
        assert_eq!(row(&p, "sam"), 0);
        assert_eq!(bridge_problems(10, &p).len(), 1);
    }

    #[test]
    fn destinations_are_distinct_and_cover_every_receiver() {
        for r in RECEIVERS {
            assert_eq!(DESTINATIONS.iter().filter(|(n, _, _)| *n == r).count(), 1, "{r}");
        }
        for (i, (_, c, a)) in DESTINATIONS.iter().enumerate() {
            assert_eq!(DESTINATIONS.iter().filter(|(_, c2, a2)| c2 == c && a2 == a).count(), 1, "{i}");
        }
    }
}
