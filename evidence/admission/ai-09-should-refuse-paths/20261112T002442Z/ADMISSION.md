# Admission: ai-09-should-refuse-paths

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: mutant:M7, mutant:M1, mutant:M8

Property: A guard never pays a cancelled invoice, never pays a removed payee, and lets only the agent start a payment.

Failure mode: Three paths, one flaw each: no cancelled check pays inv-cancel (ada 200); no payee check pays inv-removed (lin 400); no caller check lets the outsider pay inv-small (mo 50).

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git fd6564e6057c7ae55df8e8bd60bfdddeca72f65b (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T002442Z.
Runs counted 12 of 12 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| mutant:M1 | known-bad | broke 400 | 1 | yes | not-required |  |
| mutant:M1 | known-bad | broke 400 | 2 | yes | not-required |  |
| mutant:M1 | known-bad | broke 400 | 3 | yes | not-required |  |
| mutant:M7 | known-bad | broke 200 | 1 | yes | not-required |  |
| mutant:M7 | known-bad | broke 200 | 2 | yes | not-required |  |
| mutant:M7 | known-bad | broke 200 | 3 | yes | not-required |  |
| mutant:M8 | known-bad | broke 50 | 1 | yes | not-required |  |
| mutant:M8 | known-bad | broke 50 | 2 | yes | not-required |  |
| mutant:M8 | known-bad | broke 50 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
