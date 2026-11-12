# race-m2

One planted flaw in a copy of targets/vault-a, for race ordering (evidence/race-ordering-2026-11-11.md).
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/race-m2/src/lib.rs
@@ -59,6 +59,8 @@
     pub payee_generation: u64,
     /// UTC day the in-flight amount was counted against (only while Pending).
     pub pending_day: Option<u64>,
+    /// MUTANT race-m2: block the in-flight mark was set in
+    pub pending_block: u64,
 }
 
 #[near(serializers = [json])]
@@ -194,6 +196,7 @@
                 status: InvoiceStatus::Approved,
                 payee_generation: generation,
                 pending_day: None,
+                pending_block: 0, // MUTANT race-m2
             },
         );
         emit(
@@ -269,7 +272,9 @@
             };
             match inv.status {
                 InvoiceStatus::Approved => {}
-                InvoiceStatus::Pending => env::panic_str("payment already in flight"),
+                // MUTANT race-m2: an in-flight mark older than 2 blocks counts as abandoned
+                InvoiceStatus::Pending if env::block_height() <= inv.pending_block + 2 => env::panic_str("payment already in flight"),
+                InvoiceStatus::Pending => {}
                 InvoiceStatus::Paid => env::panic_str("invoice already paid"),
                 InvoiceStatus::Cancelled => env::panic_str("invoice cancelled"),
             }
@@ -296,6 +301,7 @@
             let inv = self.invoices.get_mut(&id).expect("checked above");
             inv.status = InvoiceStatus::Pending;
             inv.pending_day = Some(today);
+            inv.pending_block = env::block_height(); // MUTANT race-m2
         }
 
         emit(
```
