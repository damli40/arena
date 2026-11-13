# Admission: ai-06-pay-after-expiry

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M6

Property: A guard never pays an invoice after its expiry time.

Failure mode: No expiry check: 30 s after setup inv-expire (expires at +20 s) is past its expiry, and the pay still goes through: ada gets 300.

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git fd6564e6057c7ae55df8e8bd60bfdddeca72f65b (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T002336Z.
Runs counted 6 of 6 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M6 | known-bad | broke 300 | 1 | yes | not-required |  |
| mutant:M6 | known-bad | broke 300 | 2 | yes | not-required |  |
| mutant:M6 | known-bad | broke 300 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
