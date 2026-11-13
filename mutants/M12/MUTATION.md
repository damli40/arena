# M12

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan-2026-11-13.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M12/src/lib.rs
@@ -424,7 +424,7 @@
     // ------------------------------------------------------------------
 
     fn assert_owner(&self) {
-        require!(env::predecessor_account_id() == self.owner, "only the owner can do this");
+        // MUTANT M12: owner check removed
     }
 
     fn roll_day(&mut self, today: u64) {
```
