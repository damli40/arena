# M9

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan-2026-11-11.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M9/src/lib.rs
@@ -364,7 +364,7 @@
             // against. If the window has since rolled to a new day, the old
             // day's counter no longer exists and there is nothing to release.
             if pending_day == Some(self.spent_day) {
-                self.spent_amount = self.spent_amount.saturating_sub(amount);
+                self.spent_amount = self.spent_amount.saturating_sub(amount.saturating_mul(2)); // MUTANT M9
             }
             emit("payment_failed", serde_json::json!({"id": id, "amount": U128(amount)}));
             false
```
