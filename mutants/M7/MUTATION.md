# M7

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M7/src/lib.rs
@@ -271,7 +271,7 @@
                 InvoiceStatus::Approved => {}
                 InvoiceStatus::Pending => env::panic_str("payment already in flight"),
                 InvoiceStatus::Paid => env::panic_str("invoice already paid"),
-                InvoiceStatus::Cancelled => env::panic_str("invoice cancelled"),
+                InvoiceStatus::Cancelled => {} // MUTANT M7: cancelled check removed
             }
             require!(now < inv.expires_at_ns, "invoice expired");
             match self.payees.get(&inv.receiver) {
```
