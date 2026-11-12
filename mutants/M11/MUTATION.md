# M11

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan-2026-11-12.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M11/src/lib.rs
@@ -257,7 +257,7 @@
             .saturating_add(GAS_CALLBACK)
             .saturating_add(GAS_PAY_OVERHEAD);
         let remaining = env::prepaid_gas().saturating_sub(env::used_gas());
-        require!(remaining >= needed, "not enough gas attached to pay safely");
+        let _ = (remaining, needed); // MUTANT M11: gas pre-check removed
 
         let now = env::block_timestamp();
         let today = now / NS_PER_DAY;
```
