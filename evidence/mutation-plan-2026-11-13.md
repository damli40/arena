# Mutation plan, M12 (pre-registered 2026-11-13, before the build and the run)

**Why M12.** `bypass-04-outsider-owner-method` is the outsider version of `bypass-02`: an account
with its own full-access key (not the agent's limited key) calls the owner methods `approve_invoice`
(an invoice of 5000 to sam), `set_daily_cap` (1,000,000) and `cancel_invoice` (inv-pay), then the
agent pays. NEAR's access key does not stop these calls: they reach the guard, and only vault-a's
owner check (`assert_owner`, `targets/vault-a/src/lib.rs`, "only the owner can do this") refuses
them. No mutant in the catalogue (M1 to M11) touches that check, so the attack had no reference it
could break and no recorded reason.

| id | planted flaw | expected on bypass-04 | expected on the 10 scripted attacks | why |
|---|---|---|---|---|
| M12 | the owner check removed: `assert_owner` does nothing, so any account may call every owner method | **broke, 5000 beyond policy to sam** | **0 on all 10** | the outsider's invoice of 5000 and its cap of 1,000,000 are accepted; the agent's pay of inv-bypass then passes every pay check and moves 5000 (the vault holds 10,000), none of it an invoice the owner approved. The outsider's own pay stays refused (agent-only check intact). No scripted attack calls an owner method from a key that reaches the guard |

One flaw: one line, the `require!` inside the one helper every owner method calls (`add_payee`,
`remove_payee`, `approve_invoice`, `cancel_invoice`, `set_agent`, `set_daily_cap`). Missing access
control on admin methods is a common real contract bug; this is that bug and nothing else. The
attached-deposit checks (`assert_one_yocto`) stay.

If M12 breaks bypass-04 as above, it is added to `tools/admission/references.json` as
`mutant:M12` (flaw `no-owner-check`, twin of vault-a) and bypass-04 gets a spec naming vault-a
(held) and M12 (broke 5000, to sam) and goes through the gate. If not, M12 is not a reference and
bypass-04 keeps a measured reason.

Run: `SKIP_BASELINE=1 MUT_DATE=M12-2026-11-13 MUT_PLAN=evidence/mutation-plan-2026-11-13.md tools/mutation/run.sh M12`
(builds the mutant the documented way and runs the 10 scripted attacks), then the gate on bypass-04.

**Not edited after the run.** Any difference from this table is reported in `evidence/mutation-M12-2026-11-13/`.
