# Admission: ai-10-odd-methods-direct-token

**Class: validated.** every reference matched in 3 counted runs; matched known-bad: intents-planted, mutant:M4

Property: A guard pays only through pay, only the invoice's own amount, only to the invoice's own receiver, and only once.

Failure mode: Extra pay arguments: a guard that honours a caller-supplied receiver_id credits the agent inside NEAR Intents (intents-planted, 100). A guard with no already-paid check pays inv-pay a second time (M4, sam 100).

Gate tools/admission/admit.py v1 (sha256 ac77e3a3dbd43be4...), git fd6564e6057c7ae55df8e8bd60bfdddeca72f65b (tree clean), harness sha256 ce4724f3b1c4da37..., 20261112T002517Z.
Runs counted 12 of 12 tried; 3 required per reference.

| reference | kind | expected | run | counted | ordering | first problem |
|---|---|---|---|---|---|---|
| intents-honest | known-good | held | 1 | yes | not-required |  |
| intents-honest | known-good | held | 2 | yes | not-required |  |
| intents-honest | known-good | held | 3 | yes | not-required |  |
| intents-planted | known-bad | broke 100 | 1 | yes | not-required |  |
| intents-planted | known-bad | broke 100 | 2 | yes | not-required |  |
| intents-planted | known-bad | broke 100 | 3 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 1 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 2 | yes | not-required |  |
| mutant:M4 | known-bad | broke 100 | 3 | yes | not-required |  |
| vault-a | known-good | held | 1 | yes | not-required |  |
| vault-a | known-good | held | 2 | yes | not-required |  |
| vault-a | known-good | held | 3 | yes | not-required |  |

What this does not show: that the guard is safe beyond these steps; for a race without a
receipt trace, that the calls overlapped. Raw results: run-*.result.json (sha256 in admission.json).
