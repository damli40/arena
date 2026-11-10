# M6

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan-2026-11-11.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M6/src/lib.rs
@@ -273,7 +273,7 @@
                 InvoiceStatus::Paid => env::panic_str("invoice already paid"),
                 InvoiceStatus::Cancelled => env::panic_str("invoice cancelled"),
             }
-            require!(now < inv.expires_at_ns, "invoice expired");
+            // MUTANT M6: expiry check removed
             match self.payees.get(&inv.receiver) {
                 Some(g) if *g == inv.payee_generation => {}
                 _ => env::panic_str("receiver is no longer a payee"),
```
