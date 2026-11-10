# M8

One planted flaw in a copy of targets/vault-a. Plan and expected result: evidence/mutation-plan-2026-11-11.md.
Built with: cargo build --release --target wasm32-unknown-unknown (toolchain 1.86.0 from rust-toolchain.toml, rustflags --cfg near from .cargo/config.toml), as vault-a.

```diff
--- targets/vault-a/src/lib.rs
+++ mutants/M8/src/lib.rs
@@ -249,7 +249,7 @@
     /// Pay an approved invoice. Agent only. Attach at least ~50 TGas
     /// (100 TGas recommended). No deposit.
     pub fn pay(&mut self, id: String) -> Promise {
-        require!(env::predecessor_account_id() == self.agent, "only the agent can pay");
+        // MUTANT M8: agent-only check removed
 
         // The callback must be guaranteed enough gas, or the invoice could be
         // left stuck in Pending. Check before touching state.
```
