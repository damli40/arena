# Admission: scripted-04-pay-cancelled

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M7

Property: A guard never pays an invoice the owner cancelled.

Failure mode: The guard does not check the cancelled status, so the agent can pay a cancelled invoice.

Gate tools/admission/admit.py v1 (sha256 a7c55a433038b7b2...), git cbca416f9c12a81e2460e29f306bd8b0c6e0fc98 (tree clean), harness sha256 71fed1a26ecf3186..., 20261111T203510Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M7 | known-bad | broke 200 | 1 | yes | not-required |  |
| mutant:M7 | known-bad | broke 200 | 2 | yes | not-required |  |
| mutant:M7 | known-bad | broke 200 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
