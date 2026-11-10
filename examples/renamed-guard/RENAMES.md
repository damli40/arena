# renamed-guard

A copy of `targets/vault-a/src/lib.rs` with only its public method names changed, to show that
`arena check` handles a guard whose names differ from `targets/vault-a/INTERFACE.md` through a
mapping (data), and that the score matches the original.

| Interface (vault-a) | This guard |
|---|---|
| `new` | `setup_vault` |
| `add_payee` | `allow_payee` |
| `remove_payee` | `revoke_payee` |
| `approve_invoice` | `approve_bill` |
| `cancel_invoice` | `cancel_bill` |
| `set_agent` | `change_agent` |
| `set_daily_cap` | `update_daily_limit` |
| `pay` | `execute_payment` |
| `get_invoice` | `bill_info` |
| `get_config` | `vault_config` |
| `paid_today` | `spent_today` |
| `is_payee` | `payee_allowed` |

Arguments, deposits, logic and events are unchanged (the unit tests are renamed to match).
`diff targets/vault-a/src/lib.rs examples/renamed-guard/src/lib.rs` shows every change.

Build: `cd examples/renamed-guard && cargo build --release --target wasm32-unknown-unknown`
(Rust 1.86, pinned by `rust-toolchain.toml`). Check:

```
./arena check examples/renamed-guard/target/wasm32-unknown-unknown/release/renamed_guard.wasm \
  --config examples/renamed-guard/guard.json --mapping examples/renamed-guard/mapping.json
```

Not a guard to deploy. A test fixture.
