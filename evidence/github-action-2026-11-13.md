# The pull-request check on GitHub, first run (2026-11-13)

**What ran:** `examples/workflows/arena-check.yml`, copied into a separate public test repo, https://github.com/damli40/arena-check-demo, pull request #1. The guard is Arena's own vault-a (`targets/vault-a/vault_a.wasm`, committed prebuilt in that repo, so the build step only copies it). The workflow pins Arena at commit `9679b61b36789fcd2cc3a4a8ba580cd86fafab4a`.

**Where:** GitHub's `ubuntu-latest` runner (Linux x86_64). Run: https://github.com/damli40/arena-check-demo/actions/runs/43460356898

**Result:** both jobs passed. The check job took 17m43s.

```
arena: held 49/49 (0 not applicable; 3 stopped by the agent's access key before the guard ran; rules claimed: all 4 (payees, cancel, expiry, daily_cap); 2450 tokens paid against the owner's intent)
  honest payments: the guard paid all 63 honest invoices the attacks asked it to pay
```

This is the same badge `./arena check targets/vault-a/vault_a.wasm` prints on macOS (`evidence/invoice-fixes-2026-11-12/checks/vault-a/summary.md`).

**What the first attempt found:** run https://github.com/damli40/arena-check-demo/actions/runs/43460172235, pinned at `4ff1674`, failed before the check started. GitHub could not load Arena's `action.yml`: line 67 held an unquoted description containing `: `, which YAML reads as a new key. Commit `9679b61` quoted it. Local tests had not caught it, because they run the check script directly and never load `action.yml`.

**Files:** `github-action-2026-11-13/summary.md` (the job summary from the run's `arena-report` artifact) and `github-action-2026-11-13/key-lines.txt` (the result lines from the run log).

**Limits:** one run, one guard. The PR check ran on Linux; the rest of Arena (proofs, `verify.sh`, the hunter) has not been run on Linux by this run.
