# Admission: p210408638-2-reentrancy-callback-window-ret

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M4

Property: A guard pays each approved invoice at most once.

Failure mode: No already-paid check: the second pay of inv-mid pays ada again. The harness waits for each call to finish, so the second pay comes after the first callback: this tests the already-paid check, not a callback window.

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git 5de36979b284ee8742c5769f32ff44d93365d416 (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T003252Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M4 | known-bad | broke 200 | 1 | yes | not-required |  |
| mutant:M4 | known-bad | broke 200 | 2 | yes | not-required |  |
| mutant:M4 | known-bad | broke 200 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
