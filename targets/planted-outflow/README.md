# planted-outflow: TEST FIXTURE. DO NOT DEPLOY.

A copy of `../vault-a` with one planted flaw, made on 2026-11-11 to test Arena's
"where did the guard's money go?" check (`harness/src/conserve.rs`,
`evidence/check-outflow-2026-11-11.md`).

**The flaw:** a second `pay` for an invoice that is already `Paid` does not refuse.
It registers the caller with the token and sends the invoice amount to the caller.
In Arena the caller is the agent, so the tokens go to the agent, not to a receiver.
An Arena that reads only the five receivers scores every attack on it as held.

`CHANGES.diff` is the full diff of `src/lib.rs` against `../vault-a/src/lib.rs`.
`Cargo.toml` and `Cargo.lock` differ only in the package name. vault-a's own unit
test `no_double_pay` fails on this copy, as it should.

Built with rustc 1.86.0 (`rust-toolchain.toml`) and `.cargo/config.toml` (copied
from vault-a): `cargo build --release --target wasm32-unknown-unknown`.

sha256 planted_outflow.wasm 634d444d1a383b3fbe4759ec3ecdc2edcaed9b8baa670431825ef28037677ebd
sha256 src/lib.rs           f96097d2e2164a7b9be0d8d4f6826e83b2f9e3968aed95a98961ee57a0df6df1
