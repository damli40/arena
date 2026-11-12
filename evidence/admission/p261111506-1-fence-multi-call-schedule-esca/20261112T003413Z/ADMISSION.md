# Admission: p261111506-1-fence-multi-call-schedule-esca

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M2, mutant:M4

Property: A guard pays each invoice at most once and never spends more than the daily cap (500) in one day.

Failure mode: Pays inv-pay, then inv-big, then inv-pay again. No daily-cap check pays inv-big (700 in a day); no already-paid check pays inv-pay twice (sam 100).

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git 5de36979b284ee8742c5769f32ff44d93365d416 (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T003413Z.
Runs counted 9 of 9 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M2 | known-bad | broke 200 | 1 | yes | not-required |  |
| mutant:M2 | known-bad | broke 200 | 2 | yes | not-required |  |
| mutant:M2 | known-bad | broke 200 | 3 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 1 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 2 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
