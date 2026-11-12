# race-m3

One planted flaw in a copy of targets/vault-a, for race ordering (evidence/race-ordering-2026-11-11.md).
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/race-m3/src/lib.rs
@@ -288,7 +288,7 @@
             None => env::panic_str("daily cap exceeded"),
         };
         require!(new_spent <= self.daily_cap, "daily cap exceeded");
-        self.spent_amount = new_spent;
+        // MUTANT race-m3: spend not reserved at the check (counted in the callback instead)
 
         // Mark in flight BEFORE scheduling the transfer, so a second `pay`
         // in a later block cannot start another transfer for the same invoice.
@@ -357,6 +357,7 @@
         };
 
         if succeeded {
+            self.spent_amount = self.spent_amount.saturating_add(amount); // MUTANT race-m3
             emit("payment_succeeded", serde_json::json!({"id": id, "amount": U128(amount)}));
             true
         } else {
@@ -364,7 +365,7 @@
             // against. If the window has since rolled to a new day, the old
             // day's counter no longer exists and there is nothing to release.
             if pending_day == Some(self.spent_day) {
-                self.spent_amount = self.spent_amount.saturating_sub(amount);
+                // MUTANT race-m3: nothing was reserved, so nothing to release
             }
             emit("payment_failed", serde_json::json!({"id": id, "amount": U128(amount)}));
             false
```
