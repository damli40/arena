# M12 result (plan: evidence/mutation-plan-2026-11-13.md, committed before the build)

M12 = vault-a with the owner check removed (`assert_owner` does nothing; `mutants/M12/MUTATION.md`),
wasm sha256 `253eacb2335151b2...` (`mutants/M12/FROZEN.txt`).

| what | plan | got |
|---|---|---|
| the 10 scripted attacks on M12 | 0 on all 10 | 0 on all 10 (`summary.tsv`, `M12.log`) |
| bypass-04 through the gate | broke, 5000 beyond policy to sam | validated: vault-a held 3 of 3, M12 broke 5000 to sam 3 of 3 (`evidence/admission/bypass-04-outsider-owner-method/20261113T104612Z`) |

No difference from the plan. What this shows: bypass-04 reaches the guard (unlike bypass-02, which
NEAR's access key stops), and it is the one library attack that catches a missing owner check. What
it does not show: that any researched guard has this flaw; M12 is a planted fixture.
