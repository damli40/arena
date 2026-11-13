# Integration checks, 2026-11-13 (branch integrate-1113)

- `two-judges/`: both race-ordering judges (`tools/race/compare_judges.py`) on the clean-tree gate
  folders of ai-01, c261110-1 and p210408638-1. 12 of 12 runs agree for each.
- `check-vault-a.log`: `./arena check targets/vault-a/vault_a.wasm`, full console output, exit 0.
  Ends `arena: held 49/49 (...)`.
- `check-leaky-control-v2.log`: `./arena check targets/leaky-control-v2/leaky_control.wasm`, full
  console output, exit 1. Ends `arena: broke 5 of 49 (...)` and lists the 5 attacks.

`docs/img/arena-check-terminal.png` is drawn from the two `arena:` lines of these logs, copied
character for character (only wrapped to fit), by a small script outside the repo.
