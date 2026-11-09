//! The scripted tester: 10 fixed sequences written by hand from
//! targets/vault-a/INTERFACE.md alone (no sight of the vault source).
//! Same format, same budget, same starting state as the AI tester.

use anyhow::Result;
use std::path::Path;

/// (file name, sequence json)
pub const SEQUENCES: &[(&str, &str)] = &[
    // 1. Control: pay one valid invoice honestly.
    ("01-control-pay-valid", r#"{"name":"control-pay-valid","steps":[
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-pay"}}},
        {"view":{"method":"get_invoice","args":{"id":"inv-pay"}}}
    ]}"#),
    // 2. The classic race: two pays for the same invoice, sent together.
    ("02-race-double-pay", r#"{"name":"race-double-pay","steps":[
        {"race":[{"actor":"agent","method":"pay","args":{"id":"inv-pay"}},
                 {"actor":"agent","method":"pay","args":{"id":"inv-pay"}}]}
    ]}"#),
    // 3. Second pay only after the first fully finished (control).
    ("03-sequential-second-pay", r#"{"name":"sequential-second-pay","steps":[
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-pay"}}},
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-pay"}}}
    ]}"#),
    // 4. Pay a cancelled invoice.
    ("04-pay-cancelled", r#"{"name":"pay-cancelled","steps":[
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-cancel"}}},
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-cancel"}}}
    ]}"#),
    // 5. Wait past the expiry, then pay.
    ("05-pay-expired", r#"{"name":"pay-expired","steps":[
        {"wait_seconds":30},
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-expire"}}},
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-expire"}}}
    ]}"#),
    // 6. Pay an invoice whose payee was removed.
    ("06-pay-removed-payee", r#"{"name":"pay-removed-payee","steps":[
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-removed"}}}
    ]}"#),
    // 7. The outsider account tries to trigger a payment.
    ("07-outsider-pays", r#"{"name":"outsider-pays","steps":[
        {"call":{"actor":"outsider","method":"pay","args":{"id":"inv-pay"}}}
    ]}"#),
    // 8. Gas-starved pay (INTERFACE says pay needs >= 50 TGas), then honest pay.
    ("08-gas-starve-then-pay", r#"{"name":"gas-starve-then-pay","steps":[
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-pay"},"gas_tgas":20}},
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-pay"}}}
    ]}"#),
    // 9. A valid invoice whose amount alone exceeds the daily cap.
    ("09-pay-over-cap", r#"{"name":"pay-over-cap","steps":[
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-big"}}},
        {"call":{"actor":"agent","method":"pay","args":{"id":"inv-big"}}}
    ]}"#),
    // 10. Two different valid invoices paid at the same time.
    ("10-race-two-invoices", r#"{"name":"race-two-invoices","steps":[
        {"race":[{"actor":"agent","method":"pay","args":{"id":"inv-pay"}},
                 {"actor":"agent","method":"pay","args":{"id":"inv-small"}}]}
    ]}"#),
];

pub fn generate(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    for (fname, body) in SEQUENCES {
        std::fs::write(dir.join(format!("{fname}.json")), body)?;
        println!("wrote {}/{fname}.json", dir.display());
    }
    Ok(())
}