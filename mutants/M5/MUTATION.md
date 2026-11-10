# M5

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan-2026-11-11.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M5/src/lib.rs
@@ -294,7 +294,7 @@
         // in a later block cannot start another transfer for the same invoice.
         {
             let inv = self.invoices.get_mut(&id).expect("checked above");
-            inv.status = InvoiceStatus::Pending;
+            // MUTANT M5: not marked Pending before the transfer
             inv.pending_day = Some(today);
         }
 
@@ -339,7 +339,7 @@
             };
 
         let (amount, pending_day) = match self.invoices.get_mut(&id) {
-            Some(inv) if inv.status == InvoiceStatus::Pending => {
+            Some(inv) if inv.status == InvoiceStatus::Pending || inv.status == InvoiceStatus::Approved => { // MUTANT M5
                 let day = inv.pending_day.take();
                 if succeeded {
                     inv.status = InvoiceStatus::Paid;
```
