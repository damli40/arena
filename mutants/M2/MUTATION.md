# M2

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan-2026-11-11.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M2/src/lib.rs
@@ -287,7 +287,7 @@
             Some(v) => v,
             None => env::panic_str("daily cap exceeded"),
         };
-        require!(new_spent <= self.daily_cap, "daily cap exceeded");
+        // MUTANT M2: daily-cap check removed
         self.spent_amount = new_spent;
 
         // Mark in flight BEFORE scheduling the transfer, so a second `pay`
```
