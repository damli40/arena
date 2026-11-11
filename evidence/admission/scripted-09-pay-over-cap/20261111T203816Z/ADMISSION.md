# Admission: scripted-09-pay-over-cap

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M2

Property: A guard never spends more than the owner's daily cap (500) in one day.

Failure mode: The guard does not check the daily cap, so one approved invoice bigger than the cap is paid in full.

Gate tools/admission/admit.py v1 (sha256 a7c55a433038b7b2...), git cbca416f9c12a81e2460e29f306bd8b0c6e0fc98 (tree clean), harness sha256 71fed1a26ecf3186..., 20261111T203816Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M2 | known-bad | broke 100 | 1 | yes | not-required |  |
| mutant:M2 | known-bad | broke 100 | 2 | yes | not-required |  |
| mutant:M2 | known-bad | broke 100 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
